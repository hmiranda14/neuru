#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
# neuru-agent — featherweight remote collector for NEURU.
#
# Reads the host's /proc, /sys and (optionally) the Docker socket and PUSHES a
# health snapshot to NEURU over outbound HTTPS every NEURU_INTERVAL seconds. No
# inbound port, no SSH key — works behind NAT/CGNAT/firewalls. NEURU stores the
# snapshot in the SAME shape its SSH Linux Monitor produces, so an agent host
# renders identically in linux.php with zero server changes.
#
# Pure Python 3 standard library — no pip deps (keeps the image ~45 MB on Alpine).
#
# Config (environment):
#   NEURU_URL       full endpoint, e.g. https://neuru.example.com/nm_agent_api.php   (required)
#   NEURU_TOKEN     enrollment token from Config → Poller → Remote Agents            (required)
#   NEURU_HOSTNAME  display name (default: the host's hostname)
#   NEURU_UID       stable id (default: host machine-id, else hostname)
#   NEURU_INTERVAL  seconds between pushes (default 30; server may override)
#   NEURU_VERIFY_TLS  "0" to skip TLS verification (self-signed NEURU) — default "1"
#   HOST_PROC/HOST_SYS/HOST_ROOT  mount points (default /host/proc … , fall back to /proc)
#   DOCKER_SOCK     path to docker.sock (default /var/run/docker.sock; skipped if absent)
# ─────────────────────────────────────────────────────────────────────────────
import os, sys, time, json, socket, ssl, urllib.request, urllib.error, glob

def _envp(name, default):
    p = os.environ.get(name, default)
    return p if os.path.isdir(p) or os.path.exists(p) else default

PROC = _envp("HOST_PROC", "/proc" if not os.path.isdir("/host/proc") else "/host/proc")
SYS  = _envp("HOST_SYS",  "/sys"  if not os.path.isdir("/host/sys")  else "/host/sys")
ROOT = os.environ.get("HOST_ROOT", "/host/root" if os.path.isdir("/host/root") else "/")
DOCKER_SOCK = os.environ.get("DOCKER_SOCK", "/var/run/docker.sock")

URL      = os.environ.get("NEURU_URL", "").strip()
TOKEN    = os.environ.get("NEURU_TOKEN", "").strip()
INTERVAL = max(10, int(os.environ.get("NEURU_INTERVAL", "30") or "30"))
VERIFY   = os.environ.get("NEURU_VERIFY_TLS", "1") != "0"
VERSION  = "0.1.0"


def _read(path):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def hostname():
    h = os.environ.get("NEURU_HOSTNAME", "").strip()
    if h:
        return h
    h = _read(os.path.join(PROC, "sys/kernel/hostname")).strip()
    return h or socket.gethostname()


def machine_uid():
    uid = os.environ.get("NEURU_UID", "").strip()
    if uid:
        return uid
    for p in (os.path.join(ROOT, "etc/machine-id"),
              os.path.join(ROOT, "var/lib/dbus/machine-id"),
              "/etc/machine-id"):
        v = _read(p).strip()
        if v:
            return "mid-" + v[:32]
    return "host-" + hostname()


# ── CPU (two-sample) ─────────────────────────────────────────────────────────
def _cpu_sample():
    for line in _read(os.path.join(PROC, "stat")).splitlines():
        if line.startswith("cpu "):
            f = [int(x) for x in line.split()[1:]]
            idle = f[3] + (f[4] if len(f) > 4 else 0)
            total = sum(f)
            return total, idle
    return 0, 0


# ── Per-process CPU/RSS (two-sample) ─────────────────────────────────────────
def _proc_snapshot():
    """Return {pid: (comm, utime+stime, rss_kb)}."""
    out = {}
    for d in glob.glob(os.path.join(PROC, "[0-9]*")):
        pid = os.path.basename(d)
        st = _read(os.path.join(d, "stat"))
        if not st:
            continue
        try:
            rp = st.rfind(")")
            comm = st[st.find("(") + 1: rp]
            rest = st[rp + 2:].split()
            utime = int(rest[11]); stime = int(rest[12])
            rss_pages = int(rest[21])
            out[pid] = (comm, utime + stime, rss_pages * (os.sysconf("SC_PAGE_SIZE") // 1024))
        except Exception:
            continue
    return out


# ── Memory ───────────────────────────────────────────────────────────────────
def mem():
    t = a = 0
    for line in _read(os.path.join(PROC, "meminfo")).splitlines():
        if line.startswith("MemTotal:"):
            t = int(line.split()[1])
        elif line.startswith("MemAvailable:"):
            a = int(line.split()[1])
    mt = round(t / 1024); mf = round(a / 1024)
    return mt, mf, (mt - mf), (round((t - a) / t * 100, 1) if t else 0)


# ── Network (two-sample rate over lo-excluded ifaces) ─────────────────────────
def _net_sample():
    rx = tx = 0
    for line in _read(os.path.join(PROC, "net/dev")).splitlines():
        if ":" not in line:
            continue
        name, _, rest = line.partition(":")
        if name.strip() == "lo":
            continue
        f = rest.split()
        if len(f) >= 9:
            rx += int(f[0]); tx += int(f[8])
    return rx, tx


# ── Disks (statvfs on real mounts) ────────────────────────────────────────────
def disks():
    out = []
    skip = {"tmpfs", "devtmpfs", "overlay", "squashfs", "efivarfs", "proc", "sysfs",
            "cgroup", "cgroup2", "devpts", "mqueue", "debugfs", "tracefs", "fusectl",
            "configfs", "bpf", "autofs", "pstore", "securityfs", "ramfs"}
    seen_mnt, seen_dev = set(), set()
    for line in _read(os.path.join(PROC, "mounts")).splitlines():
        p = line.split()
        if len(p) < 3:
            continue
        mnt, fstype = p[1], p[2]
        if fstype in skip or mnt in seen_mnt:
            continue
        seen_mnt.add(mnt)
        real = ROOT.rstrip("/") + mnt if ROOT != "/" else mnt
        try:
            if not os.path.isdir(real):           # skip file bind-mounts (e.g. /etc/resolv.conf)
                continue
            dev = os.stat(real).st_dev
            if dev in seen_dev:                    # one entry per physical filesystem
                continue
            s = os.statvfs(real)
        except Exception:
            continue
        seen_dev.add(dev)
        size = s.f_blocks * s.f_frsize
        free = s.f_bavail * s.f_frsize
        if size <= 0:
            continue
        used = size - (s.f_bfree * s.f_frsize)
        pct = int(round(used / size * 100)) if size else 0
        out.append({"id": mnt, "size": round(size / 1073741824, 1),
                    "free": round(free / 1073741824, 1), "pct": pct})
    return out


# ── Sensors (hwmon) ───────────────────────────────────────────────────────────
def sensors():
    temps, fans, sens = [], [], []
    for hw in glob.glob(os.path.join(SYS, "class/hwmon/hwmon*")):
        chip = _read(os.path.join(hw, "name")).strip() or "hwmon"
        for f in sorted(glob.glob(os.path.join(hw, "temp*_input"))):
            base = f[:-6]
            label = _read(base + "_label").strip() or os.path.basename(base)
            try:
                c = round(int(_read(f).strip()) / 1000.0, 1)
            except Exception:
                continue
            nm = "%s %s" % (chip, label)
            temps.append({"name": nm, "c": c})
            sens.append({"type": "Temperature", "name": nm, "val": c})
        for f in sorted(glob.glob(os.path.join(hw, "fan*_input"))):
            base = f[:-6]
            label = _read(base + "_label").strip() or os.path.basename(base)
            try:
                rpm = int(_read(f).strip())
            except Exception:
                continue
            nm = "%s %s" % (chip, label)
            fans.append({"name": nm, "rpm": rpm})
            sens.append({"type": "Fan", "name": nm, "val": rpm})
    return temps, fans, sens


# ── Docker (optional, via unix socket) ───────────────────────────────────────
def _docker_get(path):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect(DOCKER_SOCK)
        req = "GET %s HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n" % path
        s.sendall(req.encode())
        buf = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        s.close()
        body = buf.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in buf else b""
        # de-chunk (Transfer-Encoding: chunked)
        if b"transfer-encoding: chunked" in buf.split(b"\r\n\r\n", 1)[0].lower():
            out, i = b"", 0
            while i < len(body):
                j = body.find(b"\r\n", i)
                if j < 0:
                    break
                try:
                    n = int(body[i:j], 16)
                except Exception:
                    break
                if n == 0:
                    break
                out += body[j + 2: j + 2 + n]
                i = j + 2 + n + 2
            body = out
        return json.loads(body.decode("utf-8", "replace") or "null")
    except Exception:
        return None


def _docker_post(path):
    """POST to the docker socket (e.g. container restart). Returns HTTP status or None."""
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(15)
        s.connect(DOCKER_SOCK)
        req = "POST %s HTTP/1.1\r\nHost: docker\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" % path
        s.sendall(req.encode())
        head = b""
        while b"\r\n" not in head:
            chunk = s.recv(4096)
            if not chunk:
                break
            head += chunk
        s.close()
        first = head.split(b"\r\n", 1)[0].decode("latin1", "replace")
        parts = first.split(" ")
        return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
    except Exception:
        return None


# ── Command executor (Phase 3) — SAFE, allow-listed actions only ─────────────
def exec_command(cmd):
    """Return (ok: bool, result: str) for a queued NEURU command."""
    name = (cmd.get("cmd") or "").lower()
    args = cmd.get("args") or {}
    if name == "ping":
        return True, "pong"
    if name == "collect_now":
        return True, "will collect on next cycle"
    if name == "restart_container":
        cname = str(args.get("name", "")).strip()
        if not cname:
            return False, "missing container name"
        if not os.path.exists(DOCKER_SOCK):
            return False, "docker socket not mounted"
        code = _docker_post("/containers/%s/restart" % cname)
        return (code in (204, 200)), ("restarted" if code in (204, 200) else "docker returned %s" % code)
    return False, "unsupported command '%s' in agent v%s" % (name, VERSION)


def containers():
    if not os.path.exists(DOCKER_SOCK):
        return []
    lst = _docker_get("/containers/json")
    if not isinstance(lst, list):
        return []
    out = []
    for c in lst[:60]:
        name = (c.get("Names") or ["/?"])[0].lstrip("/")
        state = c.get("State", "")
        cid = c.get("Id", "")[:12]
        cpu = memmb = 0
        stats = _docker_get("/containers/%s/stats?stream=false" % cid) if cid else None
        if isinstance(stats, dict):
            try:
                cd = stats["cpu_stats"]["cpu_usage"]["total_usage"] - stats["precpu_stats"]["cpu_usage"]["total_usage"]
                sd = stats["cpu_stats"]["system_cpu_usage"] - stats["precpu_stats"].get("system_cpu_usage", 0)
                ncpu = stats["cpu_stats"].get("online_cpus") or len(stats["cpu_stats"]["cpu_usage"].get("percpu_usage") or [1])
                if sd > 0:
                    cpu = round(cd / sd * ncpu * 100, 1)
                memmb = round(stats["memory_stats"].get("usage", 0) / 1048576, 1)
            except Exception:
                pass
        out.append({"name": name, "state": state, "cpu": cpu, "mem": memmb, "image": c.get("Image", "")})
    return out


# ── Build the combined health snapshot (card shape ∪ diag shape) ─────────────
def gather():
    c0 = _cpu_sample(); p0 = _proc_snapshot()
    n0 = _net_sample(); t0 = time.time()
    time.sleep(0.6)
    c1 = _cpu_sample(); p1 = _proc_snapshot()
    n1 = _net_sample(); dt = max(0.1, time.time() - t0)

    dtot = c1[0] - c0[0]; didle = c1[1] - c0[1]
    cpu = int(round(100 * (dtot - didle) / dtot)) if dtot > 0 else 0

    rx = max(0, (n1[0] - n0[0]) / dt); tx = max(0, (n1[1] - n0[1]) / dt)

    # top CPU (delta) + top mem (rss) from the two process snapshots
    clk = os.sysconf("SC_CLK_TCK") or 100
    per = {}
    for pid, (comm, jiff, rss) in p1.items():
        d = jiff - (p0.get(pid, (None, jiff, 0))[1])
        per.setdefault(comm, [0.0, 0])[0] += max(0, d)
        per[comm][1] = max(per[comm][1], rss)
    top_cpu = sorted(([k, round(v[0] / clk / dt * 100, 1)] for k, v in per.items()),
                     key=lambda x: -x[1])[:8]
    top_cpu = [{"name": k, "pct": p, "mb": 0} for k, p in top_cpu if p > 0]

    mrss = {}
    for pid, (comm, jiff, rss) in p1.items():
        mrss[comm] = mrss.get(comm, 0) + rss
    top_mem = sorted(mrss.items(), key=lambda x: -x[1])[:8]
    top_mem = [{"name": k, "mb": int(round(v / 1024)), "inst": 0, "pct": 0} for k, v in top_mem]

    mt, mf, mu, mpct = mem()
    dsk = disks()
    temps, fans, sens = sensors()
    sensor_types = {}
    for s in sens:
        sensor_types[s["type"]] = sensor_types.get(s["type"], 0) + 1

    up = 0.0
    try:
        up = float(_read(os.path.join(PROC, "uptime")).split()[0])
    except Exception:
        pass
    boot = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(time.time() - up))
    cores = len([l for l in _read(os.path.join(PROC, "cpuinfo")).splitlines()
                 if l.startswith("processor")]) or (os.cpu_count() or 0)
    load = " ".join(_read(os.path.join(PROC, "loadavg")).split()[:3])
    osr = {}
    for line in _read(os.path.join(ROOT, "etc/os-release")).splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            osr[k] = v.strip().strip('"')
    osname = osr.get("PRETTY_NAME", "") or "Linux"
    krel = _read(os.path.join(PROC, "sys/kernel/osrelease")).strip()

    d = {
        # ── card (nm_lx parse_kv) shape ──
        "os": osname, "osver": krel, "host": hostname(), "boot": boot,
        "mem_total": mt, "mem_free": mf, "cores": cores, "load": load,
        "disks": dsk, "pdisks": [], "svc_stopped_auto": [],
        "firewall": [], "proc_mem": [{"name": m["name"], "mb": m["mb"]} for m in top_mem[:6]],
        "proc_cpu": [{"name": c["name"], "cpu": c["pct"], "mb": 0} for c in top_cpu[:6]],
        # ── diag / live shape (superset extras) ──
        "cpu": cpu, "mem_used": mu, "mem_pct": mpct,
        "net_rx": round(rx / 1024, 1), "net_tx": round(tx / 1024, 1),
        "top_mem": top_mem, "top_cpu": top_cpu, "net_conn": [],
        "temps": temps, "fans": fans, "sensors": sens,
        "sensor_src": "hwmon" if sens else "",
        "sensor_types": [{"type": k, "n": v} for k, v in sensor_types.items()],
        "agent_version": VERSION,
    }
    return d


def _ssl_ctx():
    if URL.lower().startswith("https") and not VERIFY:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return None


def post(ep, payload):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(URL + "?ep=" + ep, data=body, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "X-NEURU-Agent-Token": TOKEN})
    with urllib.request.urlopen(req, timeout=20, context=_ssl_ctx()) as r:
        return json.loads(r.read().decode("utf-8", "replace") or "{}")


def main():
    if not URL or not TOKEN:
        print("[neuru-agent] NEURU_URL and NEURU_TOKEN are required", file=sys.stderr)
        sys.exit(2)
    uid, host = machine_uid(), hostname()
    print("[neuru-agent] v%s uid=%s host=%s → %s (every %ds)" % (VERSION, uid, host, URL, INTERVAL), flush=True)

    # register (best-effort; ingest also auto-registers)
    try:
        r = post("register", {"uid": uid, "hostname": host, "agent_version": VERSION})
        print("[neuru-agent] registered:", r, flush=True)
    except Exception as e:
        print("[neuru-agent] register failed (will retry via ingest):", e, flush=True)

    interval = INTERVAL
    pending_acks = []          # command results to report on the next ingest
    collect_now = False
    while True:
        t0 = time.time()
        try:
            health = gather()
            payload = {"uid": uid, "hostname": host, "agent_version": VERSION,
                       "health": health, "containers": containers()}
            if pending_acks:
                payload["acks"] = pending_acks
            r = post("ingest", payload)
            pending_acks = []
            collect_now = False
            if isinstance(r, dict):
                interval = max(10, int(r.get("interval", interval)))
                for cmd in (r.get("commands") or []):
                    ok, res = exec_command(cmd)
                    print("[neuru-agent] cmd #%s %s → %s (%s)" % (cmd.get("id"), cmd.get("cmd"), ok, res), flush=True)
                    pending_acks.append({"id": cmd.get("id"), "ok": ok, "result": res})
                    if (cmd.get("cmd") or "") == "collect_now":
                        collect_now = True
        except urllib.error.HTTPError as e:
            print("[neuru-agent] ingest HTTP %s: %s" % (e.code, e.read()[:200]), flush=True)
        except Exception as e:
            print("[neuru-agent] ingest error:", e, flush=True)
        if collect_now:
            continue                       # a queued collect_now → re-gather immediately
        time.sleep(max(2, interval - (time.time() - t0)))


if __name__ == "__main__":
    main()
