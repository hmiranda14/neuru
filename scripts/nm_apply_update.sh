#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# NEURU — privileged update applier. Run as root (e.g. inside the web container):
#   docker compose exec -u root <neuru-web> bash /var/www/html/netmon/scripts/nm_apply_update.sh
#
# It applies the build that NEURU already downloaded + cryptographically verified
# into updates/staging/. It re-verifies (SHA-256 + Ed25519 signature) before
# touching anything, snapshots the current app for rollback, then swaps files in —
# preserving local state (connection.php, .nm_secret.key, uploads/, logs/, .env).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
APP="$(cd "$(dirname "$0")/.." && pwd)"
UPD="$APP/updates"
STAGE="$UPD/staging"
BK="$UPD/backups"
PENDING="$UPD/PENDING"
PRESERVE=(connection.php .nm_secret.key .nm_secret.key.pub uploads logs updates .env net_mon_config_local.php)

say(){ printf '\033[1;36m[neuru-update]\033[0m %s\n' "$*"; }
die(){ printf '\033[1;31m[neuru-update] ERROR:\033[0m %s\n' "$*"; exit 1; }

mkdir -p "$STAGE" "$BK"

# ── locate the staged build ────────────────────────────────────────────────
FILE=""; VERSION=""; SHA=""
if [ -f "$PENDING" ]; then
  FILE="$(grep -E '^file='    "$PENDING" | cut -d= -f2-)"
  VERSION="$(grep -E '^version=' "$PENDING" | cut -d= -f2-)"
  SHA="$(grep -E '^sha256='  "$PENDING" | cut -d= -f2-)"
fi
[ -n "$FILE" ] && [ -f "$STAGE/$(basename "$FILE")" ] || FILE="$(ls -t "$STAGE"/neuru-*.tar.gz 2>/dev/null | head -1)"
[ -n "$FILE" ] || die "no staged build found in $STAGE (download+verify one from the Updates page first)"
TARBALL="$STAGE/$(basename "$FILE")"
[ -f "$TARBALL" ] || die "staged file missing: $TARBALL"
[ -n "$VERSION" ] || VERSION="$(basename "$TARBALL" | sed -E 's/^neuru-(.+)\.tar\.gz$/\1/')"
say "Staged build: $TARBALL  (version $VERSION)"

# ── re-verify integrity + authenticity (belt & suspenders) ─────────────────
LOCAL_SHA="$(sha256sum "$TARBALL" | awk '{print $1}')"
if [ -n "$SHA" ] && [ "$SHA" != "$LOCAL_SHA" ]; then die "SHA-256 mismatch — refusing"; fi
say "Verifying Ed25519 signature against the embedded portal public key ..."
php -r 'require $argv[1]."/nm_update.php";
  $ver=$argv[2]; $sha=$argv[3];
  $sig=@file_get_contents($argv[1]."/updates/staging/".basename($argv[4]).".sig");
  // U1 — a missing sidecar is now a HARD failure (was fail-open). The web download always writes
  // the .sig next to the tarball, so the legit flow is unaffected; a tarball dropped into staging/
  // WITHOUT a signature is refused instead of being applied unverified.
  if($sig===false){ fwrite(STDERR,"missing .sig sidecar — refusing to apply an unverified build\n"); exit(4); }
  exit(nm_update_verify_sig($ver,$sha,trim($sig)) ? 0 : 3);' \
  "$APP" "$VERSION" "$LOCAL_SHA" "$(basename "$TARBALL")" \
  || die "signature re-verification FAILED — this build is not trusted"

OLD_VER="$(cat "$APP/VERSION" 2>/dev/null || echo unknown)"
TS="$(date +%Y%m%d-%H%M%S)"

# ── backup ─────────────────────────────────────────────────────────────────
BACKUP="$BK/backup-${OLD_VER}-${TS}.tar.gz"
say "Backing up current app → $BACKUP"
EXC=(); for p in "${PRESERVE[@]}"; do EXC+=(--exclude="./$p"); done
# The backup is a rollback SNAPSHOT, not an archive of record — tolerate files a running cron
# writes/removes mid-read (transient race → GNU tar rc=1 "file changed" / rc=2 "cannot stat", which
# used to fatal the whole update, e.g. Joel's Pi 2026-07-23). --ignore-failed-read demotes a vanished
# file to a warning; we abort ONLY on a real failure (no space / unwritable dest → no backup produced).
trc=0; ( cd "$APP" && tar czf "$BACKUP" "${EXC[@]}" --ignore-failed-read \
        --warning=no-file-changed --warning=no-file-removed . ) || trc=$?
{ [ "$trc" -le 1 ] || [ -s "$BACKUP" ]; } || die "backup failed (tar rc=$trc) — aborting, nothing changed"

# ── extract ────────────────────────────────────────────────────────────────
TMP="$(mktemp -d "$STAGE/_extract_XXXX")"
trap 'rm -rf "$TMP"' EXIT
say "Extracting ..."
tar xzf "$TARBALL" -C "$TMP"
# find the app root inside the tarball (files at root or under a top folder)
SRC="$TMP"
if [ ! -f "$SRC/nm_license.php" ] && [ ! -f "$SRC/net_mon.php" ]; then
  for d in "$TMP"/*/; do [ -f "$d/nm_license.php" ] && { SRC="${d%/}"; break; }; done
fi
say "Source root: $SRC"

# ── merge (preserve local state) ───────────────────────────────────────────
say "Applying files (preserving local state & secrets) ..."
RSYNC_EXC=(); for p in "${PRESERVE[@]}"; do RSYNC_EXC+=(--exclude="/$p"); done
if command -v rsync >/dev/null 2>&1; then
  rsync -a "${RSYNC_EXC[@]}" "$SRC"/ "$APP"/
else
  # tar-pipe merge (rsync is NOT in the image): correctly overlays directories —
  # overwrites changed files, creates new ones, and NEVER nests an existing dir
  # (which a plain `cp -a dir dest/` would do). Preserved top-level paths excluded.
  TAR_EXC=(); for p in "${PRESERVE[@]}"; do TAR_EXC+=(--exclude="./$p"); done
  ( cd "$SRC" && tar cf - "${TAR_EXC[@]}" . ) | ( cd "$APP" && tar xf - )
fi

# ── perms + finish ─────────────────────────────────────────────────────────
chown -R www-data:www-data "$APP" 2>/dev/null || true
for d in uploads logs updates; do [ -d "$APP/$d" ] && chmod -R 0775 "$APP/$d" 2>/dev/null || true; done
rm -f "$PENDING"

# HTTPS self-activation: the SSL vhost/cert normally comes up via the entrypoint, which only
# re-runs on a container restart. Applying an update does NOT restart the container, so an
# install updating INTO the HTTPS release would stay http-only until the next restart. Run the
# (idempotent, root) setup here so :443 goes live immediately after an in-portal update. No-op
# if the script is absent (older payloads) or openssl is missing.
[ -f "$APP/scripts/nm_https_setup.sh" ] && { sh "$APP/scripts/nm_https_setup.sh" && say "HTTPS vhost ensured (:443)"; }

# CRITICAL: clear the PHP OPcache so the NEW code is served immediately. Without this,
# Apache keeps serving the cached bytecode of the old files and the update "looks like
# nothing changed" until the next restart. A graceful reload recycles workers (no downtime).
if command -v apachectl >/dev/null 2>&1;   then apachectl -k graceful 2>/dev/null && say "apache reloaded — OPcache cleared";
elif command -v apache2ctl >/dev/null 2>&1; then apache2ctl graceful   2>/dev/null && say "apache reloaded — OPcache cleared";
else service apache2 reload 2>/dev/null && say "apache reloaded — OPcache cleared"; fi

say "Done. $OLD_VER → $VERSION applied."
say "Rollback if needed:  tar xzf \"$BACKUP\" -C \"$APP\""
