#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# NEURU-in-a-Box entrypoint. Boots the WHOLE platform inside ONE container:
# embedded MariaDB → import the schema on first boot → then hand off to the standard
# NEURU entrypoint (which generates connection.php pointing at 127.0.0.1, seeds the
# secret key + crontab, starts the pollers/syslog/netflow, and finally Apache in the
# foreground). Idempotent: on a restart with an existing data volume it skips init.
# This single image runs on Ubuntu/Docker, a Raspberry Pi, and a MikroTik x86 CHR.
# ─────────────────────────────────────────────────────────────────────────────
set +e
APP=/var/www/html/netmon
DATADIR=/var/lib/mysql

# The app talks to the EMBEDDED database on loopback (the standard entrypoint reads these).
export NM_DB_HOST="${NM_DB_HOST:-127.0.0.1}"
export NM_DB_NAME="${NM_DB_NAME:-netmon}"
export NM_DB_USER="${NM_DB_USER:-sisuser}"
export NM_DB_PASS="${NM_DB_PASS:-sispass}"

mkdir -p "$DATADIR" /run/mysqld
chown -R mysql:mysql "$DATADIR" /run/mysqld 2>/dev/null

# 1) initialize the MariaDB data dir on first boot (empty volume)
if [ ! -d "$DATADIR/mysql" ]; then
    echo "[box] initializing MariaDB data dir…"
    mariadb-install-db --user=mysql --datadir="$DATADIR" --auth-root-authentication-method=normal >/tmp/mariadb-init.log 2>&1 \
      || mysql_install_db --user=mysql --datadir="$DATADIR" >/tmp/mariadb-init.log 2>&1
fi

# 2) start MariaDB in the background, auto-restart if it dies
( while true; do
    mysqld_safe --datadir="$DATADIR" --skip-networking=0 --bind-address=127.0.0.1 >>/var/log/neuru-mariadb.log 2>&1
    echo "[box] mariadb exited, restart in 3s" >>/var/log/neuru-mariadb.log; sleep 3
  done ) &

# wait for the socket (up to ~60s)
echo "[box] waiting for MariaDB…"
for i in $(seq 1 60); do mysqladmin --protocol=socket ping >/dev/null 2>&1 && break; sleep 1; done

# 3) create the app DB + user, and import the schema on first boot (empty DB)
mysql --protocol=socket -u root >/dev/null 2>&1 <<SQL
CREATE DATABASE IF NOT EXISTS \`${NM_DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
CREATE USER IF NOT EXISTS '${NM_DB_USER}'@'localhost' IDENTIFIED BY '${NM_DB_PASS}';
CREATE USER IF NOT EXISTS '${NM_DB_USER}'@'127.0.0.1' IDENTIFIED BY '${NM_DB_PASS}';
CREATE USER IF NOT EXISTS '${NM_DB_USER}'@'%' IDENTIFIED BY '${NM_DB_PASS}';
GRANT ALL PRIVILEGES ON \`${NM_DB_NAME}\`.* TO '${NM_DB_USER}'@'localhost';
GRANT ALL PRIVILEGES ON \`${NM_DB_NAME}\`.* TO '${NM_DB_USER}'@'127.0.0.1';
GRANT ALL PRIVILEGES ON \`${NM_DB_NAME}\`.* TO '${NM_DB_USER}'@'%';
FLUSH PRIVILEGES;
SQL

TABLES=$(mysql --protocol=socket -N -u root -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${NM_DB_NAME}'" 2>/dev/null)
if [ "${TABLES:-0}" -lt 50 ] && [ -f "$APP/install/neuru-install.sql" ]; then
    echo "[box] importing NEURU schema (first boot)…"
    # The schema is a MySQL-8 dump; the embedded DB is MariaDB, which does NOT support the
    # utf8mb4_0900_* collations (nor MySQL-8-only /*!80xxx*/ clauses). Sanitize on the fly so the
    # import succeeds on MariaDB. (Without this every CREATE TABLE fails → 0 tables → stuck at
    # "importing-schema".)
    sed -E -e 's/utf8mb4_0900_ai_ci/utf8mb4_general_ci/g' \
           -e 's/utf8mb4_0900_as_cs/utf8mb4_general_ci/g' \
           -e 's/COLLATE=utf8mb4_0900_[a-z_]+/COLLATE=utf8mb4_general_ci/g' \
           "$APP/install/neuru-install.sql" \
      | mysql --protocol=socket -u root --force "${NM_DB_NAME}" 2>>/var/log/neuru-mariadb.log
    NT=$(mysql --protocol=socket -N -u root -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${NM_DB_NAME}'" 2>/dev/null)
    echo "[box] schema import done — ${NT:-0} tables (see /var/log/neuru-mariadb.log for any warnings)."
fi

# 4) Federation (optional): if this NEURU was deployed FROM a parent NEURU, enrol as its
#    slave. A STANDALONE install (no parent env) never federates.
if [ -n "$NEURU_MASTER_URL" ] && [ -n "$NEURU_MASTER_TOKEN" ] && [ -f "$APP/scripts/neuru-box/federate.php" ]; then
    echo "[box] federating to parent NEURU $NEURU_MASTER_URL…"
    php "$APP/scripts/neuru-box/federate.php" "$NEURU_MASTER_URL" "$NEURU_MASTER_TOKEN" "${NEURU_NAME:-$(hostname)}" >>/var/log/neuru-federate.log 2>&1 || true
fi

# 5) optional first-boot admin password override
if [ -n "$NEURU_ADMIN_PASS" ] && [ "${TABLES:-0}" -lt 50 ]; then
    php -r '$p=getenv("NEURU_ADMIN_PASS"); $h=password_hash($p,PASSWORD_DEFAULT);
        $c=@new mysqli(getenv("NM_DB_HOST"),getenv("NM_DB_USER"),getenv("NM_DB_PASS"),getenv("NM_DB_NAME"));
        if($c && !$c->connect_error){ @$c->query("UPDATE users SET password=\"".$c->real_escape_string($h)."\" WHERE role=\"admin\" LIMIT 1"); }' 2>/dev/null || true
fi

echo "[box] MariaDB ready — handing off to the standard NEURU entrypoint."
# 6) hand off: connection.php gen (127.0.0.1), secret key, crontab, daemons, Apache foreground
exec bash "$APP/scripts/netmon-entrypoint.sh"
