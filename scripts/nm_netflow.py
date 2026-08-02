#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
# NEURU — NetFlow / IPFIX collector (SolarWinds NTA-style ingest).
#
# Design for HIGH RATE without melting CPU/DB:
#   • one UDP listener thread → drops raw datagrams on a bounded queue
#   • one parser/aggregator thread: decodes v5 / v9 / IPFIX and folds every flow
#     into an IN-MEMORY dict keyed by (exporter, src, dst, sport, dport, proto).
#     We never store individual flows.
#   • one flusher thread (every FLUSH_SECS): writes only the TOP-N aggregates of
#     the elapsed minute (executemany + ON DUPLICATE KEY UPDATE), prunes old
#     data, updates status counters, then clears the dict.
#   • template cache for v9/IPFIX; defensive per-packet parsing (bad packet =
#     dropped + counted, never crashes the daemon); DB auto-reconnect.
#
# Settings come from nm_settings (netflow_port, netflow_retention_days,
# netflow_sampling, netflow_topn). Env NM_NETFLOW_PORT overrides the port.
# ─────────────────────────────────────────────────────────────────────────────
import os
import sys
import socket
import struct
import threading
import queue
import signal
import time
from collections import defaultdict
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nm_db_config import DB                      # noqa: E402
import mysql.connector                           # noqa: E402

UDP_BUF      = 65535
FLUSH_SECS   = 60
QUEUE_MAX    = 20000
STATS        = defaultdict(int)
_running     = True

# Well-known service ports → used to pick the "application" port of a flow.
WELL_KNOWN = {
    20, 21, 22, 23, 25, 43, 49, 53, 67, 68, 69, 80, 88, 110, 111, 119, 123, 135,
    137, 138, 139, 143, 161, 162, 179, 389, 443, 445, 465, 500, 514, 515, 520,
    587, 623, 636, 993, 995, 1080, 1194, 1433, 1521, 1701, 1723, 1812, 1813,
    1900, 2049, 2055, 2082, 2083, 2222, 3128, 3306, 3389, 3478, 4500, 4739,
    5060, 5061, 5222, 5353, 5355, 5432, 5900, 5938, 6343, 6379, 6443, 8000,
    8080, 8443, 8883, 9000, 9090, 9100, 9200, 27017, 51820,
}


def log(msg):
    print(f"[{datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S} UTC] {msg}", flush=True)


def db_connect():
    while _running:
        try:
            c = mysql.connector.connect(
                host=DB["host"], user=DB["user"], password=DB["password"],
                database=DB["database"], autocommit=False, connection_timeout=8)
            return c
        except Exception as e:
            log(f"DB connect failed ({e}); retry in 5s")
            time.sleep(5)
    return None


def load_settings():
    port, retention, sampling, topn = 2055, 7, 1, 300
    try:
        c = db_connect(); cur = c.cursor()
        cur.execute("SELECT setting_key, setting_val FROM nm_settings WHERE setting_key IN "
                    "('netflow_port','netflow_retention_days','netflow_sampling','netflow_topn')")
        s = {k: v for k, v in cur.fetchall()}
        cur.close(); c.close()
        port      = int(s.get("netflow_port", port) or port)
        retention = max(1, int(s.get("netflow_retention_days", retention) or retention))
        sampling  = max(1, int(s.get("netflow_sampling", sampling) or sampling))
        topn      = max(50, int(s.get("netflow_topn", topn) or topn))
    except Exception as e:
        log(f"settings: using defaults ({e})")
    if os.environ.get("NM_NETFLOW_PORT"):
        port = int(os.environ["NM_NETFLOW_PORT"])
    return port, retention, sampling, topn


def ensure_table(c):
    cur = c.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS nm_netflow_flows (
        bucket DATETIME NOT NULL, exporter VARCHAR(45) NOT NULL,
        src_ip VARCHAR(45) NOT NULL, dst_ip VARCHAR(45) NOT NULL,
        src_port INT UNSIGNED NOT NULL DEFAULT 0, dst_port INT UNSIGNED NOT NULL DEFAULT 0,
        protocol TINYINT UNSIGNED NOT NULL DEFAULT 0, app_port INT UNSIGNED NOT NULL DEFAULT 0,
        bytes BIGINT UNSIGNED NOT NULL DEFAULT 0, packets BIGINT UNSIGNED NOT NULL DEFAULT 0,
        flows INT UNSIGNED NOT NULL DEFAULT 0,
        PRIMARY KEY (bucket,exporter,src_ip,dst_ip,src_port,dst_port,protocol),
        KEY idx_bucket (bucket), KEY idx_app (bucket,app_port,protocol),
        KEY idx_src (bucket,src_ip), KEY idx_dst (bucket,dst_ip)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""")
    c.commit(); cur.close()


def app_port(sport, dport):
    if dport in WELL_KNOWN:
        return dport
    if sport in WELL_KNOWN:
        return sport
    if dport and dport < 1024 and (sport >= 1024 or dport <= sport):
        return dport
    if sport and sport < 1024:
        return sport
    return min(sport, dport) if (sport and dport) else (dport or sport)


# ── Aggregation store (guarded by a lock) ────────────────────────────────────
_agg = defaultdict(lambda: [0, 0, 0])   # key -> [bytes, packets, flows]
_agg_lock = threading.Lock()
_templates = {}                          # (exporter, source_id, template_id) -> [(type,len),...]


def add_flow(exporter, src, dst, sport, dport, proto, nbytes, npkts, sampling):
    key = (exporter, src, dst, sport, dport, proto, app_port(sport, dport))
    with _agg_lock:
        e = _agg[key]
        e[0] += nbytes * sampling
        e[1] += npkts * sampling
        e[2] += 1
    STATS["flows"] += 1


def ip4(raw):
    return socket.inet_ntoa(raw)


# ── Parsers ──────────────────────────────────────────────────────────────────
def parse_v5(data, exporter, sampling):
    if len(data) < 24:
        return
    count = struct.unpack_from("!H", data, 2)[0]
    off = 24
    for _ in range(count):
        if off + 48 > len(data):
            break
        rec = data[off:off + 48]
        srcaddr = ip4(rec[0:4]); dstaddr = ip4(rec[4:8])
        dpkts  = struct.unpack_from("!I", rec, 16)[0]
        doct   = struct.unpack_from("!I", rec, 20)[0]
        sport  = struct.unpack_from("!H", rec, 32)[0]
        dport  = struct.unpack_from("!H", rec, 34)[0]
        prot   = rec[38]
        add_flow(exporter, srcaddr, dstaddr, sport, dport, prot, doct, dpkts, sampling)
        off += 48


# v9 / IPFIX field ids we care about
F_IN_BYTES, F_IN_PKTS = 1, 2
F_PROTO = 4
F_SRC_PORT, F_DST_PORT = 7, 11
F_SRC_IP, F_DST_IP = 8, 12
F_OUT_BYTES, F_OUT_PKTS = 23, 24


def _read_int(b):
    return int.from_bytes(b, "big") if b else 0


def _parse_data_records(body, fields, exporter, sampling):
    rec_len = sum(flen for (_ftype, flen) in fields)
    if rec_len == 0:
        return
    off = 0
    n = len(body)
    while off + rec_len <= n:
        src = dst = "0.0.0.0"; sport = dport = proto = 0; nb = npkts = 0
        p = off
        for ftype, flen in fields:
            chunk = body[p:p + flen]; p += flen
            if ftype in (F_SRC_IP,) and flen == 4:
                src = ip4(chunk)
            elif ftype in (F_DST_IP,) and flen == 4:
                dst = ip4(chunk)
            elif ftype == F_SRC_PORT:
                sport = _read_int(chunk)
            elif ftype == F_DST_PORT:
                dport = _read_int(chunk)
            elif ftype == F_PROTO:
                proto = _read_int(chunk)
            elif ftype in (F_IN_BYTES, F_OUT_BYTES):
                nb += _read_int(chunk)
            elif ftype in (F_IN_PKTS, F_OUT_PKTS):
                npkts += _read_int(chunk)
        if src != "0.0.0.0" or dst != "0.0.0.0":
            add_flow(exporter, src, dst, sport, dport, proto, nb, npkts, sampling)
        off += rec_len


def parse_v9(data, exporter, sampling):
    if len(data) < 20:
        return
    source_id = struct.unpack_from("!I", data, 16)[0]
    off = 20; n = len(data)
    while off + 4 <= n:
        fs_id, length = struct.unpack_from("!HH", data, off)
        if length < 4:
            break
        body = data[off + 4: off + length]
        if fs_id == 0:                       # template flowset
            p = 0
            while p + 4 <= len(body):
                tid, fcount = struct.unpack_from("!HH", body, p); p += 4
                fields = []
                for _ in range(fcount):
                    if p + 4 > len(body):
                        break
                    ft, fl = struct.unpack_from("!HH", body, p); p += 4
                    fields.append((ft, fl))
                if fields:
                    _templates[(exporter, source_id, tid)] = fields
        elif fs_id == 1:                     # options template — ignore
            pass
        elif fs_id >= 256:                   # data flowset
            fields = _templates.get((exporter, source_id, fs_id))
            if fields:
                _parse_data_records(body, fields, exporter, sampling)
        off += length


def parse_ipfix(data, exporter, sampling):
    if len(data) < 16:
        return
    total_len = struct.unpack_from("!H", data, 2)[0]
    domain_id = struct.unpack_from("!I", data, 12)[0]
    n = min(total_len, len(data))
    off = 16
    while off + 4 <= n:
        set_id, length = struct.unpack_from("!HH", data, off)
        if length < 4:
            break
        body = data[off + 4: off + length]
        if set_id == 2:                      # template set
            p = 0
            while p + 4 <= len(body):
                tid, fcount = struct.unpack_from("!HH", body, p); p += 4
                fields = []
                for _ in range(fcount):
                    if p + 4 > len(body):
                        break
                    ft, fl = struct.unpack_from("!HH", body, p); p += 4
                    if ft & 0x8000:          # enterprise field → skip its 4-byte PEN
                        ft &= 0x7FFF
                        p += 4
                    fields.append((ft, fl))
                if fields:
                    _templates[(exporter, domain_id, tid)] = fields
        elif set_id == 3:                    # options template — ignore
            pass
        elif set_id >= 256:
            fields = _templates.get((exporter, domain_id, set_id))
            if fields:
                _parse_data_records(body, fields, exporter, sampling)
        off += length


def parse_packet(data, exporter, sampling):
    if len(data) < 2:
        return
    ver = struct.unpack_from("!H", data, 0)[0]
    if ver == 5:
        parse_v5(data, exporter, sampling)
    elif ver == 9:
        parse_v9(data, exporter, sampling)
    elif ver == 10:
        parse_ipfix(data, exporter, sampling)
    else:
        STATS["unknown_ver"] += 1


# ── Threads ──────────────────────────────────────────────────────────────────
PKTQ = queue.Queue(maxsize=QUEUE_MAX)


def listener(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    except OSError:
        pass
    s.bind(("0.0.0.0", port))
    s.settimeout(1.0)
    log(f"listening for NetFlow/IPFIX on udp/{port}")
    while _running:
        try:
            data, addr = s.recvfrom(UDP_BUF)
        except socket.timeout:
            continue
        except OSError:
            break
        STATS["packets"] += 1
        try:
            PKTQ.put_nowait((data, addr[0]))
        except queue.Full:
            STATS["dropped"] += 1
    s.close()


def aggregator(sampling):
    while _running:
        try:
            data, ip = PKTQ.get(timeout=1.0)
        except queue.Empty:
            continue
        try:
            parse_packet(data, ip, sampling)
        except Exception:
            STATS["parse_err"] += 1


def flusher(retention_days, topn):
    c = db_connect()
    if c:
        ensure_table(c)
    last = time.time()
    last_prune = 0
    while _running:
        time.sleep(1)
        if time.time() - last < FLUSH_SECS:
            continue
        last = time.time()
        with _agg_lock:
            snapshot = list(_agg.items())
            _agg.clear()
        if not snapshot:
            _update_stats(c, 0)
            continue
        # keep only the top-N by bytes for this minute (bounds DB growth)
        snapshot.sort(key=lambda kv: kv[1][0], reverse=True)
        snapshot = snapshot[:topn]
        bucket = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:00")
        rows = [(bucket, k[0], k[1], k[2], k[3], k[4], k[5], k[6], v[0], v[1], v[2])
                for k, v in snapshot]
        try:
            if c is None or not c.is_connected():
                c = db_connect(); ensure_table(c)
            cur = c.cursor()
            cur.executemany(
                "INSERT INTO nm_netflow_flows "
                "(bucket,exporter,src_ip,dst_ip,src_port,dst_port,protocol,app_port,bytes,packets,flows) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
                "ON DUPLICATE KEY UPDATE bytes=bytes+VALUES(bytes), packets=packets+VALUES(packets), flows=flows+VALUES(flows)",
                rows)
            c.commit(); cur.close()
            STATS["written"] += len(rows)
        except Exception as e:
            log(f"flush insert failed ({e}); will reconnect")
            try:
                c.close()
            except Exception:
                pass
            c = None
        # retention prune (once an hour)
        if time.time() - last_prune > 3600 and c is not None:
            try:
                cur = c.cursor()
                cur.execute("DELETE FROM nm_netflow_flows WHERE bucket < (NOW() - INTERVAL %s DAY)", (retention_days,))
                c.commit(); cur.close()
                last_prune = time.time()
            except Exception:
                pass
        _update_stats(c, len(rows))


def _update_stats(c, written):
    exporters = 0
    try:
        if c and c.is_connected():
            cur = c.cursor()
            cur.execute("SELECT COUNT(DISTINCT exporter) FROM nm_netflow_flows WHERE bucket >= (NOW() - INTERVAL 1 HOUR)")
            exporters = cur.fetchone()[0] or 0
            for k, v in [("netflow_stat_last", int(time.time())),
                         ("netflow_stat_packets", STATS["packets"]),
                         ("netflow_stat_flows", STATS["flows"]),
                         ("netflow_stat_exporters", exporters),
                         ("netflow_stat_dropped", STATS["dropped"])]:
                cur.execute("INSERT INTO nm_settings (setting_key,setting_val) VALUES (%s,%s) "
                            "ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)", (k, str(v)))
            c.commit(); cur.close()
    except Exception:
        pass
    log(f"flush: wrote {written} aggregates · pkts={STATS['packets']} flows={STATS['flows']} "
        f"dropped={STATS['dropped']} exporters={exporters} templates={len(_templates)}")


def _shutdown(signum, _frame):
    global _running
    _running = False
    log(f"signal {signum} → shutting down")


def main():
    port, retention, sampling, topn = load_settings()
    log(f"NEURU NetFlow collector starting · port={port} retention={retention}d sampling={sampling} topN={topn}")
    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    threads = [
        threading.Thread(target=listener, args=(port,), daemon=True),
        threading.Thread(target=aggregator, args=(sampling,), daemon=True),
        threading.Thread(target=flusher, args=(retention, topn), daemon=True),
    ]
    for t in threads:
        t.start()
    while _running:
        time.sleep(1)
    log("stopped")


if __name__ == "__main__":
    main()
