#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
# NEURU — SSH config-fetch primitive for the Router Configuration Manager.
#
# PHP (running as www-data, which CAN decrypt the SSH credential) calls this with
# the connection details in the ENVIRONMENT (never argv → no leak in `ps`):
#
#     NM_SSH_HOST, NM_SSH_PORT, NM_SSH_USER, NM_SSH_PASS, NM_SSH_KEY (optional
#     private-key text), NM_SSH_CMD (the brand export command), NM_SSH_TIMEOUT.
#
# It SSHes the device exactly like `ssh user@host "<cmd>"`, runs the command, and
# prints the raw config to STDOUT (exit 0). On any failure it prints the reason to
# STDERR and exits non-zero. NEURU (nm_confmgr.php) then normalizes / diffs /
# versions / alerts — same as before; we only replaced the broken n8n SSH step.
#
# paramiko lives in the bind-mounted /home/hmiranda/netmon-pylibs (survives image
# rebuilds even though the venv doesn't); NM_PYLIBS points at it.
# ─────────────────────────────────────────────────────────────────────────────
import os
import sys
import io
import time

# paramiko may live in a bind-mounted libs dir; try the env path + generic/legacy defaults.
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


def main():
    host = os.environ.get("NM_SSH_HOST", "").strip()
    port = int(os.environ.get("NM_SSH_PORT", "22") or 22)
    user = os.environ.get("NM_SSH_USER", "").strip()
    pwd = os.environ.get("NM_SSH_PASS", "")
    key_text = os.environ.get("NM_SSH_KEY", "")
    command = os.environ.get("NM_SSH_CMD", "")
    timeout = int(os.environ.get("NM_SSH_TIMEOUT", "25") or 25)

    if not host:
        fail("no host")
    if not user:
        fail("no username")
    if not command.strip():
        fail("no command")

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

    try:
        lines = [l for l in command.replace("\r\n", "\n").split("\n")]
        multiline = len([l for l in lines if l.strip()]) > 1

        if multiline:
            # Interactive shell for multi-command sequences (e.g. Cisco
            # "terminal length 0" + "show running-config"): send each line,
            # then drain output until the device goes idle.
            chan = client.invoke_shell(width=512, height=1000)
            chan.settimeout(timeout)
            time.sleep(0.6)
            if chan.recv_ready():
                chan.recv(65535)
            for l in lines:
                chan.send(l + "\n")
                time.sleep(0.4)
            buf = b""
            idle = 0
            deadline = time.time() + timeout
            while time.time() < deadline:
                if chan.recv_ready():
                    chunk = chan.recv(65535)
                    if chunk:
                        buf += chunk
                        idle = 0
                        continue
                idle += 1
                if idle >= 6:  # ~1.8s with nothing new → done
                    break
                time.sleep(0.3)
            out = buf.decode("utf-8", "replace")
        else:
            # Single command → exec channel, identical to `ssh host "<cmd>"`.
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            out = stdout.read().decode("utf-8", "replace")
            err = stderr.read().decode("utf-8", "replace")
            if out.strip() == "" and err.strip() != "":
                fail("device error: " + err.strip()[:300], 1)
    except Exception as e:
        client.close()
        fail("command failed: %s" % e, 1)

    client.close()

    if out.strip() == "":
        fail("empty output from device", 1)

    sys.stdout.write(out)
    sys.exit(0)


if __name__ == "__main__":
    main()
