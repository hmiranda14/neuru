#!/usr/bin/env python3
"""
sentinel-agent.py — the NEURU Sentinel wire sensor.

Runs on a network segment (host networking). It enrols with NEURU, PULLS the SPECTRE
reputation matrix (bad IPs + domains), then passively watches the wire:

  • DNS queries  → if a host resolves a known-bad domain (C2/malware), report it.
  • IP flows     → if a local host talks to a known-bad IP, report it.

Detection only — NEURU does the blocking (VECTOR-SHIELD fans the block out to your
Pi-hole/AdGuard/firewalls via Collective Immunity, and NEURO-ISOLATION can quarantine
the host on its gateway). Zero inline latency, no TLS interception. Outbound-only to
NEURU. Configured 100% from NEURU (pull desired-state). Mirrors the neuru-utilities model.

Env: NEURU_URL, SENTINEL_TOKEN (required); SENTINEL_UID, IFACE (default: all),
     POLL_SECONDS (matrix refresh, default 300), VERIFY_TLS ("0" for self-signed).
"""
import os, sys, ssl, json, time, socket, threading, urllib.request, urllib.error

AGENT_VERSION = "0.1.0"
NEURU_URL  = os.environ.get("NEURU_URL", "").rstrip("/")
TOKEN      = os.environ.get("SENTINEL_TOKEN", "")
IFACE      = os.environ.get("IFACE", "") or None
POLL       = int(os.environ.get("POLL_SECONDS", "300") or 300)
VERIFY_TLS = os.environ.get("VERIFY_TLS", "1") != "0"

BAD_IPS = set()
BAD_DOMS = set()
HITS = []            # queued hits to report
LOCK = threading.Lock()
COUNTS = {"dns": 0, "flows": 0}


def log(m): print(f"[sentinel] {m}", flush=True)

def uid():
    u = os.environ.get("SENTINEL_UID", "").strip()
    if u: return u
    try:
        with open("/etc/machine-id") as f:
            m = f.read().strip()
        if m: return "snt-" + m[:24]
    except Exception:
        pass
    return "snt-" + socket.gethostname()

def host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close(); return ip
    except Exception:
        return ""

def _ctx():
    if NEURU_URL.startswith("https") and not VERIFY_TLS:
        c = ssl.create_default_context(); c.check_hostname=False; c.verify_mode=ssl.CERT_NONE; return c
    return None

def api(path, payload):
    url = f"{NEURU_URL}/sentinel.php?api={path}"
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type":"application/json","X-Neuru-Sentinel-Token":TOKEN})
    try:
        with urllib.request.urlopen(req, timeout=30, context=_ctx()) as r:
            return json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        log(f"{path} HTTP {e.code}"); return None
    except Exception as e:
        log(f"{path} error: {e}"); return None

def queue_hit(local_ip, indicator, kind, module, detail):
    with LOCK:
        HITS.append({"local_ip": local_ip, "indicator": indicator, "kind": kind, "module": module, "detail": detail})
        if len(HITS) > 2000: del HITS[:1000]

# ── passive capture (scapy) ──────────────────────────────────────────────────
def is_local(ip):
    return ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                          "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                          "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "100.64."))

def on_packet(pkt):
    try:
        from scapy.all import IP, UDP, DNS, DNSQR
        if IP not in pkt: return
        src = pkt[IP].src; dst = pkt[IP].dst
        # DNS query → domain match
        if pkt.haslayer(DNSQR) and pkt.haslayer(DNS) and pkt[DNS].qr == 0:
            COUNTS["dns"] += 1
            try: qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".").lower()
            except Exception: qname = ""
            if qname:
                # match qname or any parent domain
                labels = qname.split(".")
                for i in range(len(labels) - 1):
                    cand = ".".join(labels[i:])
                    if cand in BAD_DOMS:
                        queue_hit(src, qname, "domain", "vector", f"DNS query for {qname}")
                        log(f"THREAT dns {src} → {qname}")
                        break
        # IP flow → dst reputation match (only local→remote)
        else:
            COUNTS["flows"] += 1
            if is_local(src) and not is_local(dst) and dst in BAD_IPS:
                queue_hit(src, dst, "ip", "spectre", f"connection {src} → {dst}")
                log(f"THREAT flow {src} → {dst}")
    except Exception:
        pass

def sniffer():
    try:
        from scapy.all import sniff
    except Exception as e:
        log(f"scapy unavailable ({e}) — sensor runs in report-only heartbeat mode"); return
    while True:
        try:
            log(f"sniffing {'iface='+IFACE if IFACE else 'all interfaces'} (DNS + IP reputation)")
            sniff(filter="udp port 53 or ip", iface=IFACE, prn=on_packet, store=False)
        except Exception as e:
            log(f"sniff error: {e}; retry in 10s"); time.sleep(10)

# ── TZSP receiver: consume traffic MIRRORED to us from a router (MikroTik /tool sniffer
#    streaming, Cisco/others via TZSP). Lets one sensor see the WHOLE network's DNS without
#    a physical SPAN cable — NEURU points the router's mirror stream at this host by IP. ──
TZSP_PORT = int(os.environ.get("TZSP_PORT", "37008") or 37008)

def _parse_tzsp(data):
    # TZSP: ver, type, encap(2), then tagged fields until END(0x01); rest = encapsulated frame.
    if len(data) < 4 or data[1] not in (0, 1): return None
    i = 4
    while i < len(data):
        tag = data[i]
        if tag == 0x01: return data[i+1:]        # END → inner packet follows
        if tag == 0x00: i += 1; continue          # PADDING
        if i + 1 >= len(data): return None
        i += 2 + data[i+1]                         # typed tag: type+len+data
    return None

def tzsp_listener():
    try:
        from scapy.all import Ether
    except Exception:
        return
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", TZSP_PORT))
    except Exception as e:
        log(f"TZSP bind udp/{TZSP_PORT} failed ({e}) — mirror receive disabled"); return
    log(f"listening for MIRRORED traffic (TZSP) on udp/{TZSP_PORT}")
    while True:
        try:
            data, _ = s.recvfrom(65535)
            inner = _parse_tzsp(data)
            if inner:
                try: on_packet(Ether(inner))
                except Exception: pass
        except Exception:
            pass

# ── main loop: enrol → pull matrix → report ──────────────────────────────────
def main():
    if not NEURU_URL or not TOKEN:
        log("NEURU_URL and SENTINEL_TOKEN are required"); sys.exit(2)
    U = uid(); NAME = os.environ.get("SENTINEL_NAME") or socket.gethostname()
    log(f"starting v{AGENT_VERSION} uid={U} → {NEURU_URL}")
    while True:
        r = api("enroll", {"uid": U, "hostname": NAME, "ip": host_ip(), "arch": os.uname().machine, "agent_version": AGENT_VERSION})
        if r and r.get("ok"): log(f"enrolled node_id={r.get('node_id')}"); break
        log("enroll failed, retry 15s"); time.sleep(15)

    threading.Thread(target=sniffer, daemon=True).start()
    threading.Thread(target=tzsp_listener, daemon=True).start()   # receive router-mirrored DNS

    matrix_rev = -1
    while True:
        d = api("desired", {"uid": U})
        if d and d.get("ok"):
            rev = int(d.get("matrix_rev", 0))
            if rev != matrix_rev:
                global BAD_IPS, BAD_DOMS
                BAD_IPS = set(d.get("ips", []) or [])
                BAD_DOMS = set(x.lower() for x in (d.get("domains", []) or []))
                matrix_rev = rev
                log(f"matrix synced: {len(BAD_IPS)} IPs, {len(BAD_DOMS)} domains (rev {rev})")
        with LOCK:
            hits = HITS[:500]; del HITS[:len(hits)]
            dns_c = COUNTS["dns"]; fl_c = COUNTS["flows"]; COUNTS["dns"] = 0; COUNTS["flows"] = 0
        api("report", {"uid": U, "seen_dns": dns_c, "seen_flows": fl_c, "hits": hits})
        time.sleep(POLL)

if __name__ == "__main__":
    main()
