#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
# NEURU — Cisco interactive SSH config fetcher (Orchestrator, F4).
#
# Standard `ssh host "show running-config"` (exec channel) FAILS on real Cisco gear
# for two reasons the plain Config-Manager fetch can't handle:
#   1. PRIVILEGED EXEC — a non-priv-15 SSH user lands in user exec ("Router>") and
#      must `enable` (answering a second Password:) before `show running-config` works.
#   2. SECONDARY LOGIN — AireOS controllers ask for User:/Password: again inside the
#      SSH shell and use `show run-config`.
# This purpose-built interactive runner (paramiko invoke_shell, modelled on
# nm_wifi_ssh.py) owns those quirks. Creds arrive via the ENVIRONMENT (never argv,
# so nothing leaks in `ps`); www-data runs it (it can decrypt the credential).
#
#   NM_SSH_HOST/PORT/USER/PASS/KEY/TIMEOUT  — connection
#   NM_CISCO_PLATFORM  — ios|iosxe|nxos|asa|aireos   (drives pager + login flow)
#   NM_CISCO_CMD       — the show command (default 'show running-config')
#   NM_CISCO_ENABLE    — enable secret; empty → reuse the login password
#
# STDOUT = JSON {"ok":true,"config":"..."} or {"ok":false,"error":"..."}. Exit 0.
# ─────────────────────────────────────────────────────────────────────────────
import os, sys, io, re, json, time

for _pl in (os.environ.get("NM_PYLIBS", ""), "/home/neuru/netmon-pylibs", "/home/hmiranda/netmon-pylibs"):
    if _pl and _pl not in sys.path:
        sys.path.insert(0, _pl)

try:
    import paramiko
except Exception as e:
    print(json.dumps({"ok": False, "error": "paramiko not available: %s" % e})); sys.exit(0)

PROMPT = re.compile(r"[>#]\s*$", re.MULTILINE)


def out(obj):
    sys.stdout.write(json.dumps(obj)); sys.exit(0)


def load_key(text):
    text = (text or "").strip()
    if not text:
        return None
    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return cls.from_private_key(io.StringIO(text))
        except Exception:
            continue
    return None


def drain(chan, seconds, prompt_re=None):
    buf = b""; idle = 0; deadline = time.time() + seconds; paged = False
    while time.time() < deadline:
        if chan.recv_ready():
            chunk = chan.recv(65535)
            if chunk:
                buf += chunk; idle = 0
                tail = buf[-96:].decode("utf-8", "replace")
                if "More" in tail and "--" in tail:            # IOS/ASA pager
                    chan.send(" "); paged = True
                elif "Press Enter to continue" in tail or "Press any key to continue" in tail:  # AireOS pager
                    chan.send("\n"); paged = True
                continue
        idle += 1
        if prompt_re is not None and idle >= 2:
            if prompt_re.search(buf[-120:].decode("utf-8", "replace")):
                break
        # be far more patient with paged output (many pager round-trips)
        if idle >= (20 if paged else 8):
            break
        time.sleep(0.3)
    return buf.decode("utf-8", "replace")


def clean_config(transcript, cmd):
    """Strip the echoed command and the trailing CLI prompt from the captured text."""
    lines = transcript.replace("\r", "").split("\n")
    # drop everything up to and including the echoed command line
    start = 0
    for i, ln in enumerate(lines):
        if cmd.strip() and cmd.strip() in ln:
            start = i + 1
            break
    body = lines[start:]
    # strip residual pager-prompt echoes anywhere in the body
    body = [ln for ln in body if "Press Enter to continue" not in ln
            and "Press any key to continue" not in ln
            and not (("More" in ln) and ("--" in ln))]
    # drop trailing prompt-only line(s) and blank tail
    while body and (body[-1].strip() == "" or PROMPT.search(body[-1])):
        body.pop()
    return "\n".join(body).strip()


def main():
    host = os.environ.get("NM_SSH_HOST", "").strip()
    port = int(os.environ.get("NM_SSH_PORT", "22") or 22)
    user = os.environ.get("NM_SSH_USER", "").strip()
    pwd  = os.environ.get("NM_SSH_PASS", "")
    key_text = os.environ.get("NM_SSH_KEY", "")
    timeout = int(os.environ.get("NM_SSH_TIMEOUT", "30") or 30)
    platform = os.environ.get("NM_CISCO_PLATFORM", "ios").strip().lower()
    show_req = os.environ.get("NM_CISCO_CMD", "").strip()
    enable_secret = os.environ.get("NM_CISCO_ENABLE", "") or pwd

    if not host: out({"ok": False, "error": "no host"})
    if not user: out({"ok": False, "error": "no username"})

    pkey = load_key(key_text) if key_text.strip() else None
    if key_text.strip() and pkey is None:
        out({"ok": False, "error": "could not parse private key"})

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=host, port=port, username=user,
                       password=(pwd if pwd != "" else None), pkey=pkey,
                       timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
                       look_for_keys=False, allow_agent=False)
    except paramiko.AuthenticationException:
        out({"ok": False, "error": "authentication failed (bad username/password)"})
    except Exception as e:
        out({"ok": False, "error": "connect failed: %s" % e})

    try:
        chan = client.invoke_shell(width=512, height=2000)
        chan.settimeout(timeout)
        time.sleep(0.7)
        banner = drain(chan, 3, PROMPT)

        # 1) AireOS secondary login (User:/Password: inside the shell). AUTO-DETECT: if the
        #    device shows a User: prompt we treat it as AireOS even if the caller said 'ios'
        #    (e.g. the Config Manager registers WLCs as cisco_ios).
        is_aireos = (platform == "aireos")
        if is_aireos or re.search(r"User\s*:", banner):
            is_aireos = True
            chan.send(user + "\n"); time.sleep(0.6)
            b2 = drain(chan, 4, re.compile(r"Password\s*:", re.IGNORECASE))
            if re.search(r"Password\s*:", b2, re.IGNORECASE):
                chan.send(pwd + "\n"); time.sleep(0.6)
                banner = drain(chan, 4, PROMPT)

        # Finalize pager + show command now that we know AireOS vs IOS.
        if is_aireos:
            pager = "config paging disable"
            # `show run-config commands` = the clean CLI config (no live stats), the right
            # thing for versioning; plain `show run-config` includes runtime state → false drift.
            show = show_req
            if show in ("", "show running-config", "show run-config"):
                show = "show run-config commands"
        else:
            pager = "terminal pager 0" if platform == "asa" else "terminal length 0"
            show = show_req or "show running-config"

        # 2) Privileged exec (IOS/ASA/NX-OS): if we're at "Router>" escalate with enable
        if not is_aireos and re.search(r">\s*$", banner):
            chan.send("enable\n"); time.sleep(0.5)
            eb = drain(chan, 4, re.compile(r"(Password\s*:|#\s*$)", re.IGNORECASE))
            if re.search(r"Password\s*:", eb, re.IGNORECASE):
                chan.send(enable_secret + "\n"); time.sleep(0.6)
                eb2 = drain(chan, 4, PROMPT)
                if re.search(r">\s*$", eb2):
                    client.close()
                    out({"ok": False, "error": "enable failed — wrong enable secret or not permitted"})

        # 3) Disable paging, then run the show command
        chan.send(pager + "\n"); time.sleep(0.35); drain(chan, 4, PROMPT)
        chan.send(show + "\n"); time.sleep(0.4)
        transcript = drain(chan, timeout, PROMPT)
    except Exception as e:
        client.close(); out({"ok": False, "error": "command failed: %s" % e})

    client.close()
    cfg = clean_config(transcript, show)
    if len(cfg) < 200:   # a real Cisco config is always longer; reject truncated/racey fetches
        out({"ok": False, "error": "config too short (%d chars) — truncated fetch or still at a login/enable prompt" % len(cfg), "raw": transcript[:400]})
    out({"ok": True, "config": cfg})


if __name__ == "__main__":
    main()
