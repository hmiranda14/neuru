#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
# NEURU — WiFi controller SSH runner (universal WiFi Control Center transport).
#
# WiFi controllers (Cisco AireOS / Mobility Express, IOS-XE 9800, autonomous IOS,
# and later Aruba/UniFi/etc.) speak an INTERACTIVE CLI over SSH, not a clean
# `ssh host "cmd"` exec channel: they page output (--More--), some ask for a
# SECOND login (User:/Password:) after SSH auth, and control commands prompt for
# y/N confirmation. The Config Manager's nm_ssh_fetch.py is deliberately kept
# simple (exec / blind multiline) so we do NOT touch it — this purpose-built
# runner owns the interactive quirks so the WiFi engine stays clean.
#
# PHP (www-data, which CAN decrypt the SSH credential) passes everything via the
# ENVIRONMENT (never argv → no leak in `ps`):
#   NM_SSH_HOST/PORT/USER/PASS/KEY/TIMEOUT  — connection (same names as the CM helper)
#   NM_WIFI_PREP   — JSON array of setup lines sent first (e.g. ["config paging disable"])
#   NM_WIFI_STEPS  — JSON array of command lines to run, in order
#   NM_WIFI_PROMPT — regex matching the device's idle CLI prompt (default '[>#]\\s*$')
#   NM_WIFI_LOGIN  — "1" → answer a secondary User:/Password: prompt with USER/PASS
#
# STDOUT = the full interactive transcript (echoed commands + their output). The
# engine splits it per command by the echoed command line. Exit 0 on success.
# ─────────────────────────────────────────────────────────────────────────────
import os
import sys
import io
import re
import json
import time

for _pl in (os.environ.get("NM_PYLIBS", ""), "/home/neuru/netmon-pylibs", "/home/hmiranda/netmon-pylibs"):
    if _pl and _pl not in sys.path:
        sys.path.insert(0, _pl)

try:
    import paramiko
except Exception as e:  # pragma: no cover
    sys.stderr.write("paramiko not available: %s\n" % e)
    sys.exit(3)


def fail(msg, code=1):
    sys.stderr.write(str(msg).strip() + "\n")
    sys.exit(code)


def load_key(text):
    text = text.strip()
    if not text:
        return None
    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return cls.from_private_key(io.StringIO(text))
        except Exception:
            continue
    return None


def jenv(name):
    raw = os.environ.get(name, "")
    if not raw.strip():
        return []
    try:
        v = json.loads(raw)
        return v if isinstance(v, list) else []
    except Exception:
        return []


def drain(chan, seconds, prompt_re=None):
    """Read from the channel until it goes idle (or a prompt is seen), up to `seconds`."""
    buf = b""
    idle = 0
    deadline = time.time() + seconds
    while time.time() < deadline:
        if chan.recv_ready():
            chunk = chan.recv(65535)
            if chunk:
                buf += chunk
                idle = 0
                # a paged device: answer --More-- with a space to keep flowing
                tail = buf[-64:].decode("utf-8", "replace")
                if "More" in tail and "--" in tail:
                    chan.send(" ")
                continue
        idle += 1
        if prompt_re is not None and idle >= 2:
            tail = buf[-120:].decode("utf-8", "replace")
            if prompt_re.search(tail):
                break
        if idle >= 7:  # ~2.1s quiet → assume done
            break
        time.sleep(0.3)
    return buf


def main():
    host = os.environ.get("NM_SSH_HOST", "").strip()
    port = int(os.environ.get("NM_SSH_PORT", "22") or 22)
    user = os.environ.get("NM_SSH_USER", "").strip()
    pwd = os.environ.get("NM_SSH_PASS", "")
    key_text = os.environ.get("NM_SSH_KEY", "")
    timeout = int(os.environ.get("NM_SSH_TIMEOUT", "30") or 30)

    prep = jenv("NM_WIFI_PREP")
    steps = jenv("NM_WIFI_STEPS")
    prompt_txt = os.environ.get("NM_WIFI_PROMPT", r"[>#]\s*$")
    do_login = os.environ.get("NM_WIFI_LOGIN", "0").strip() == "1"

    if not host:
        fail("no host")
    if not user:
        fail("no username")
    if not steps:
        fail("no steps")

    try:
        prompt_re = re.compile(prompt_txt, re.MULTILINE)
    except Exception:
        prompt_re = re.compile(r"[>#]\s*$", re.MULTILINE)

    pkey = load_key(key_text) if key_text.strip() else None
    if key_text.strip() and pkey is None:
        fail("could not parse private key")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host, port=port, username=user,
            password=(pwd if pwd != "" else None),
            pkey=pkey,
            timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
            look_for_keys=False, allow_agent=False,
        )
    except paramiko.AuthenticationException:
        fail("authentication failed (bad username/password)", 2)
    except Exception as e:
        fail("connect failed: %s" % e, 2)

    transcript = ""
    try:
        chan = client.invoke_shell(width=512, height=2000)
        chan.settimeout(timeout)
        time.sleep(0.7)
        banner = drain(chan, 3, prompt_re).decode("utf-8", "replace")

        # Some AireOS WLCs ask for a SECOND login (User:/Password:) inside the SSH shell.
        if do_login and re.search(r"User\s*:", banner):
            chan.send(user + "\n")
            time.sleep(0.6)
            b2 = drain(chan, 4, re.compile(r"Password\s*:", re.IGNORECASE)).decode("utf-8", "replace")
            if re.search(r"Password\s*:", b2, re.IGNORECASE):
                chan.send(pwd + "\n")
                time.sleep(0.6)
                drain(chan, 4, prompt_re)

        # Setup lines (pager off, etc.) — output discarded.
        for l in prep:
            chan.send(str(l) + "\n")
            time.sleep(0.35)
            drain(chan, 4, prompt_re)

        # Command steps — full transcript kept (echo + output), so PHP can split per cmd.
        for l in steps:
            chan.send(str(l) + "\n")
            time.sleep(0.4)
            out = drain(chan, timeout, prompt_re)
            transcript += out.decode("utf-8", "replace")
    except Exception as e:
        client.close()
        fail("command failed: %s" % e, 1)

    client.close()

    if transcript.strip() == "":
        fail("empty output from device", 1)

    sys.stdout.write(transcript)
    sys.exit(0)


if __name__ == "__main__":
    main()
