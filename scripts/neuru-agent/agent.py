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
from concurrent.futures import ThreadPoolExecutor

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
VERSION  = "0.2.0"


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


# ── CPU (two-sample; aggregate + per-core + breakdown) ───────────────────────
def _cpu_sample():
    agg = (0, 0, 0, 0, 0)   # total, idle, iowait, steal, busy-fields for breakdown
    cores = {}
    ctxt = intr = forks = procs_running = procs_blocked = 0
    for line in _read(os.path.join(PROC, "stat")).splitlines():
        p = line.split()
        if not p:
            continue
        if p[0] == "cpu" or (p[0].startswith("cpu") and p[0][3:].isdigit()):
            f = [int(x) for x in p[1:]]
            total = sum(f)
            idle = f[3] + (f[4] if len(f) > 4 else 0)
            iowait = f[4] if len(f) > 4 else 0
            steal = f[7] if len(f) > 7 else 0
            if p[0] == "cpu":
                agg = (total, idle, iowait, steal, 0)
            else:
                cores[p[0]] = (total, idle)
        elif p[0] == "ctxt":
            ctxt = int(p[1])
        elif p[0] == "intr":
            intr = int(p[1])
        elif p[0] == "processes":
            forks = int(p[1])
        elif p[0] == "procs_running":
            procs_running = int(p[1])
        elif p[0] == "procs_blocked":
            procs_blocked = int(p[1])
    return {"agg": agg, "cores": cores, "ctxt": ctxt, "intr": intr,
            "forks": forks, "procs_running": procs_running, "procs_blocked": procs_blocked}


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


# ── Memory (full breakdown incl. swap/buffers/cached) ─────────────────────────
def mem():
    m = {}
    for line in _read(os.path.join(PROC, "meminfo")).splitlines():
        k, _, v = line.partition(":")
        m[k] = int(v.split()[0]) if v.split() else 0
    t = m.get("MemTotal", 0); a = m.get("MemAvailable", 0)
    mt = round(t / 1024); mf = round(a / 1024)
    st = m.get("SwapTotal", 0); sf = m.get("SwapFree", 0)
    detail = {
        "buffers": round(m.get("Buffers", 0) / 1024),
        "cached": round((m.get("Cached", 0) + m.get("SReclaimable", 0)) / 1024),
        "dirty": round(m.get("Dirty", 0) / 1024),
        "swap_total": round(st / 1024), "swap_free": round(sf / 1024),
        "swap_used": round((st - sf) / 1024), "swap_pct": (round((st - sf) / st * 100, 1) if st else 0),
    }
    return mt, mf, (mt - mf), (round((t - a) / t * 100, 1) if t else 0), detail


# ── Network (two-sample; aggregate + per-interface incl. errors/drops) ────────
def _net_sample():
    """Return (agg_rx, agg_tx, {iface: (rx,tx,rxerr,txerr,rxdrop,txdrop)})."""
    rx = tx = 0; ifaces = {}
    for line in _read(os.path.join(PROC, "net/dev")).splitlines():
        if ":" not in line:
            continue
        name, _, rest = line.partition(":")
        name = name.strip()
        f = rest.split()
        if len(f) < 16:
            continue
        r, re, rd, tb, te, td = int(f[0]), int(f[2]), int(f[3]), int(f[8]), int(f[10]), int(f[11])
        if name != "lo":
            rx += r; tx += tb
        ifaces[name] = (r, tb, re, te, rd, td)
    return rx, tx, ifaces


# ── Disk I/O (two-sample from /proc/diskstats) ───────────────────────────────
def _diskstats_sample():
    """Return {dev: (read_sectors, write_sectors, io_in_progress)} for real block devs."""
    out = {}
    for line in _read(os.path.join(PROC, "diskstats")).splitlines():
        f = line.split()
        if len(f) < 14:
            continue
        dev = f[2]
        # skip loop/ram/partitions-of-partitions noise; keep sd*, nvme*, vd*, xvd*, mmcblk*, dm-*
        if dev.startswith(("loop", "ram", "fd", "sr")):
            continue
        try:
            out[dev] = (int(f[5]), int(f[9]), int(f[11]))   # sectors read, sectors written, ios in progress
        except Exception:
            continue
    return out


# ── Disks (statvfs on real mounts) ────────────────────────────────────────────
def disks():
    out = []
    skip = {"tmpfs", "devtmpfs", "overlay", "squashfs", "efivarfs", "proc", "sysfs",
            "cgroup", "cgroup2", "devpts", "mqueue", "debugfs", "tracefs", "fusectl",
            "configfs", "bpf", "autofs", "pstore", "securityfs", "ramfs"}
    # Read the HOST's mount table, not the container's. `{PROC}/mounts` is a symlink to `self/mounts`
    # → the agent's OWN (container) mount ns, where the host root sits at /host/root. PID 1 (with
    # pid:host) is the host init, whose mounts are the real host paths ("/", "/home", …).
    mpath = os.path.join(PROC, "mounts")
    for cand in (os.path.join(PROC, "1", "mounts"), os.path.join(PROC, "mounts")):
        try:
            with open(cand) as _f:
                _f.readline(); mpath = cand; break
        except Exception:
            continue
    seen_mnt, seen_dev = set(), set()
    for line in _read(mpath).splitlines():
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
        ipct = int(round((s.f_files - s.f_favail) / s.f_files * 100)) if s.f_files else 0
        out.append({"id": mnt, "size": round(size / 1073741824, 1),
                    "free": round(free / 1073741824, 1), "pct": pct, "ipct": ipct})
    return out


# ── Pressure Stall Information (PSI) — modern saturation signal ────────────────
def psi():
    out = {}
    for res in ("cpu", "memory", "io"):
        txt = _read(os.path.join(PROC, "pressure", res))
        for line in txt.splitlines():
            if line.startswith("some"):
                for tok in line.split():
                    if tok.startswith("avg10="):
                        out[res] = float(tok.split("=")[1]); break
    return out


# ── TCP/UDP socket states + listening ports (from /proc/net/*) ────────────────
_TCP_ST = {"01": "established", "02": "syn_sent", "03": "syn_recv", "04": "fin_wait1",
           "05": "fin_wait2", "06": "time_wait", "07": "close", "08": "close_wait",
           "09": "last_ack", "0A": "listen", "0B": "closing"}
def sockets():
    states = {}; listen = set()
    for proto in ("tcp", "tcp6"):
        for line in _read(os.path.join(PROC, "net", proto)).splitlines()[1:]:
            f = line.split()
            if len(f) < 4:
                continue
            st = _TCP_ST.get(f[3], f[3])
            states[st] = states.get(st, 0) + 1
            if f[3] == "0A":   # LISTEN
                try:
                    listen.add(int(f[1].split(":")[1], 16))
                except Exception:
                    pass
    udp = 0
    for proto in ("udp", "udp6"):
        udp += max(0, len(_read(os.path.join(PROC, "net", proto)).splitlines()) - 1)
    return states, sorted(listen), udp


# ── Misc kernel/system counters ───────────────────────────────────────────────
def fd_info():
    f = _read(os.path.join(PROC, "sys/fs/file-nr")).split()
    return (int(f[0]), int(f[2])) if len(f) >= 3 else (0, 0)

def entropy():
    try:
        return int(_read(os.path.join(PROC, "sys/kernel/random/entropy_avail")).strip() or 0)
    except Exception:
        return 0

def cpu_info():
    model = ""; mhz = []
    for line in _read(os.path.join(PROC, "cpuinfo")).splitlines():
        if line.startswith("model name") and not model:
            model = line.split(":", 1)[1].strip()
        elif line.startswith("cpu MHz"):
            try: mhz.append(float(line.split(":", 1)[1]))
            except Exception: pass
    # prefer live scaling freq from sysfs when present
    sfreq = []
    for f in glob.glob(os.path.join(SYS, "devices/system/cpu/cpu[0-9]*/cpufreq/scaling_cur_freq")):
        try: sfreq.append(int(_read(f).strip()) / 1000.0)
        except Exception: pass
    freq_mhz = round(sum(sfreq) / len(sfreq)) if sfreq else (round(sum(mhz) / len(mhz)) if mhz else 0)
    return model, freq_mhz


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


def _container_stat(c):
    name = (c.get("Names") or ["/?"])[0].lstrip("/")
    state = c.get("State", "")
    status = c.get("Status", "")
    cid = c.get("Id", "")[:12]
    cpu = memmb = mempct = netrx = nettx = 0
    stats = _docker_get("/containers/%s/stats?stream=false" % cid) if cid else None
    if isinstance(stats, dict):
        try:
            cd = stats["cpu_stats"]["cpu_usage"]["total_usage"] - stats["precpu_stats"]["cpu_usage"]["total_usage"]
            sd = stats["cpu_stats"]["system_cpu_usage"] - stats["precpu_stats"].get("system_cpu_usage", 0)
            ncpu = stats["cpu_stats"].get("online_cpus") or len(stats["cpu_stats"]["cpu_usage"].get("percpu_usage") or [1])
            if sd > 0:
                cpu = round(cd / sd * ncpu * 100, 1)
            usage = stats["memory_stats"].get("usage", 0)
            limit = stats["memory_stats"].get("limit", 0)
            memmb = round(usage / 1048576, 1)
            mempct = round(usage / limit * 100, 1) if limit else 0
            nets = stats.get("networks") or {}
            netrx = round(sum(n.get("rx_bytes", 0) for n in nets.values()) / 1048576, 2)
            nettx = round(sum(n.get("tx_bytes", 0) for n in nets.values()) / 1048576, 2)
        except Exception:
            pass
    restarts = 0; health = ""
    insp = _docker_get("/containers/%s/json" % cid) if cid else None
    if isinstance(insp, dict):
        try:
            restarts = insp.get("RestartCount", 0)
            health = ((insp.get("State") or {}).get("Health") or {}).get("Status", "") or ""
        except Exception:
            pass
    return {"name": name, "state": state, "status": status, "cpu": cpu, "mem": memmb,
            "mem_pct": mempct, "net_rx": netrx, "net_tx": nettx,
            "restarts": restarts, "health": health, "image": c.get("Image", "")}


def containers():
    if not os.path.exists(DOCKER_SOCK):
        return []
    lst = _docker_get("/containers/json")
    if not isinstance(lst, list):
        return []
    lst = lst[:50]
    if not lst:
        return []
    # Each container needs 2 blocking socket calls (stats waits ~1-2s for the CPU delta) → do them
    # CONCURRENTLY, else N containers = N×2s and the whole push misses its interval.
    try:
        with ThreadPoolExecutor(max_workers=min(24, len(lst))) as ex:
            return [r for r in ex.map(_container_stat, lst) if r]
    except Exception:
        return [_container_stat(c) for c in lst]


# ── Build the combined health snapshot (card ∪ diag ∪ deep metrics) ──────────
def gather():
    c0 = _cpu_sample(); p0 = _proc_snapshot()
    n0rx, n0tx, n0if = _net_sample(); d0 = _diskstats_sample(); t0 = time.time()
    time.sleep(0.6)
    c1 = _cpu_sample(); p1 = _proc_snapshot()
    n1rx, n1tx, n1if = _net_sample(); d1 = _diskstats_sample(); dt = max(0.1, time.time() - t0)

    # ── aggregate CPU% + iowait/steal breakdown ──
    a0, a1 = c0["agg"], c1["agg"]
    dtot = a1[0] - a0[0]; didle = a1[1] - a0[1]
    cpu = int(round(100 * (dtot - didle) / dtot)) if dtot > 0 else 0
    iowait = round(100 * (a1[2] - a0[2]) / dtot, 1) if dtot > 0 else 0
    steal = round(100 * (a1[3] - a0[3]) / dtot, 1) if dtot > 0 else 0
    # ── per-core CPU% ──
    cpu_cores = []
    for k in sorted(c1["cores"], key=lambda x: int(x[3:])):
        t, i = c1["cores"][k]; pt, pi = c0["cores"].get(k, (t, i))
        dt2 = t - pt
        cpu_cores.append(int(round(100 * ((dt2) - (i - pi)) / dt2)) if dt2 > 0 else 0)
    ctxt_s = round((c1["ctxt"] - c0["ctxt"]) / dt)
    intr_s = round((c1["intr"] - c0["intr"]) / dt)
    forks_s = round((c1["forks"] - c0["forks"]) / dt, 1)

    # ── network: aggregate + per-interface rates & error/drop deltas ──
    rx = max(0, (n1rx - n0rx) / dt); tx = max(0, (n1tx - n0tx) / dt)
    net_ifaces = []
    for name, (r, tb, re_, te, rd, td) in n1if.items():
        if name == "lo":
            continue
        pr = n0if.get(name, (r, tb, re_, te, rd, td))
        net_ifaces.append({"name": name,
            "rx": round(max(0, (r - pr[0]) / dt) / 1024, 1), "tx": round(max(0, (tb - pr[1]) / dt) / 1024, 1),
            "rx_err": re_ - pr[2], "tx_err": te - pr[3], "rx_drop": rd - pr[4], "tx_drop": td - pr[5]})
    net_ifaces.sort(key=lambda x: -(x["rx"] + x["tx"]))

    # ── disk I/O rates (sectors are 512 bytes) ──
    disk_io = []
    for dev, (rs, ws, ip) in d1.items():
        prs, pws, _ = d0.get(dev, (rs, ws, 0))
        rkb = max(0, (rs - prs) * 512 / dt / 1024); wkb = max(0, (ws - pws) * 512 / dt / 1024)
        if rkb or wkb or ip:
            disk_io.append({"dev": dev, "read": round(rkb, 1), "write": round(wkb, 1), "io": ip})
    disk_io.sort(key=lambda x: -(x["read"] + x["write"]))

    # ── top CPU (delta) + top mem (rss) from the two process snapshots ──
    clk = os.sysconf("SC_CLK_TCK") or 100
    per = {}
    for pid, (comm, jiff, rss) in p1.items():
        d = jiff - (p0.get(pid, (None, jiff, 0))[1])
        per.setdefault(comm, [0.0, 0])[0] += max(0, d)
        per[comm][1] = max(per[comm][1], rss)
    top_cpu = sorted(([k, round(v[0] / clk / dt * 100, 1)] for k, v in per.items()), key=lambda x: -x[1])[:8]
    top_cpu = [{"name": k, "pct": p, "mb": 0} for k, p in top_cpu if p > 0]
    mrss = {}
    for pid, (comm, jiff, rss) in p1.items():
        mrss[comm] = mrss.get(comm, 0) + rss
    top_mem = sorted(mrss.items(), key=lambda x: -x[1])[:8]
    top_mem = [{"name": k, "mb": int(round(v / 1024)), "inst": 0, "pct": 0} for k, v in top_mem]
    nproc = len(p1)
    nthreads = 0
    for d in glob.glob(os.path.join(PROC, "[0-9]*", "stat")):
        st = _read(d)
        try: nthreads += int(st[st.rfind(")") + 2:].split()[17])
        except Exception: pass

    mt, mf, mu, mpct, mdet = mem()
    dsk = disks()
    temps, fans, sens = sensors()
    sensor_types = {}
    for s in sens:
        sensor_types[s["type"]] = sensor_types.get(s["type"], 0) + 1

    tcp_states, listen_ports, udp = sockets()
    fd_used, fd_max = fd_info()
    pressure = psi()
    cpu_model, cpu_mhz = cpu_info()

    up = 0.0
    try: up = float(_read(os.path.join(PROC, "uptime")).split()[0])
    except Exception: pass
    boot = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(time.time() - up))
    cores = len(cpu_cores) or (os.cpu_count() or 0)
    la = _read(os.path.join(PROC, "loadavg")).split()
    load = " ".join(la[:3])
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
        # ── diag / live shape ──
        "cpu": cpu, "mem_used": mu, "mem_pct": mpct,
        "net_rx": round(rx / 1024, 1), "net_tx": round(tx / 1024, 1),
        "top_mem": top_mem, "top_cpu": top_cpu, "net_conn": [],
        "temps": temps, "fans": fans, "sensors": sens,
        "sensor_src": "hwmon" if sens else "",
        "sensor_types": [{"type": k, "n": v} for k, v in sensor_types.items()],
        # ── deep metrics (exceeds node_exporter's default surface) ──
        "cpu_model": cpu_model, "cpu_mhz": cpu_mhz, "cpu_cores": cpu_cores,
        "cpu_iowait": iowait, "cpu_steal": steal,
        "ctxt_per_s": ctxt_s, "intr_per_s": intr_s, "forks_per_s": forks_s,
        "load1": float(la[0]) if la else 0, "load5": float(la[1]) if len(la) > 1 else 0,
        "load15": float(la[2]) if len(la) > 2 else 0,
        "procs_running": c1["procs_running"], "procs_blocked": c1["procs_blocked"],
        "mem_buffers": mdet["buffers"], "mem_cached": mdet["cached"], "mem_dirty": mdet["dirty"],
        "swap_total": mdet["swap_total"], "swap_used": mdet["swap_used"], "swap_pct": mdet["swap_pct"],
        "net_ifaces": net_ifaces, "disk_io": disk_io,
        "tcp_states": tcp_states, "udp_sockets": udp, "listen_ports": listen_ports,
        "conns_total": sum(tcp_states.values()),
        "fd_used": fd_used, "fd_max": fd_max, "entropy": entropy(),
        "psi_cpu": pressure.get("cpu", 0), "psi_mem": pressure.get("memory", 0), "psi_io": pressure.get("io", 0),
        "procs": nproc, "threads": nthreads, "uptime_sec": int(up),
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
