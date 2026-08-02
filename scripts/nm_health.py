#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
# NEURU — Predictive Link & Hardware Health COLLECTOR.
#
# Standalone, isolated from nm_poller.py on purpose (a bug here must NOT break
# core polling). One-shot by default (cron-friendly); pass --loop to daemonize.
#
# Collects per node + interface:
#   ETHERNET (universal, standard OIDs):
#     in_err_rate   ifInErrors    .1.3.6.1.2.1.2.2.1.14   (Counter → /sec rate)
#     out_err_rate  ifOutErrors   .1.3.6.1.2.1.2.2.1.20
#     discard_rate  ifInDiscards+ifOutDiscards (.13 + .19)
#     fcs_rate      dot3StatsFCSErrors  .1.3.6.1.2.1.10.7.2.1.3
#   OPTICAL (SFP DOM, vendor-specific — driven by nm_health_optical_oids, the
#     rows the user ENABLED for their gear): rx_dbm / tx_dbm / temp_c / bias_ma / volt_v
#
# Writes gauges/rates to nm_health_samples; nm_health.php (PHP engine) then trends
# them and predicts days-to-failure. Counters' previous values live in
# nm_health_counters for delta computation.
# ─────────────────────────────────────────────────────────────────────────────
import sys, re, time, subprocess
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from nm_db_config import DB
import mysql.connector

INTERVAL = 300  # seconds between passes in --loop mode
MAX32 = 0xFFFFFFFF

# Realistic per-second ceilings for ethernet error/discard rates. Anything above
# these is not a real degradation signal: some devices (e.g. certain Cisco APs)
# report a packet/octet counter in the ifInErrors OID, which yields hundreds of
# thousands of "errors/s" and triggers false "Degrading" alarms. Drop those — a real
# failing link sits in the 0.001–100/s range, so these limits never hide a true fault.
PLAUSIBLE_MAX = {
    'in_err_rate':  5000.0,
    'out_err_rate': 5000.0,
    'fcs_rate':     5000.0,
    'discard_rate': 5000.0,
}

ETH_OIDS = {
    'in_err':      '.1.3.6.1.2.1.2.2.1.14',
    'out_err':     '.1.3.6.1.2.1.2.2.1.20',
    'in_disc':     '.1.3.6.1.2.1.2.2.1.13',
    'out_disc':    '.1.3.6.1.2.1.2.2.1.19',
    'fcs':         '.1.3.6.1.2.1.10.7.2.1.3',
}

def log(m): print(f"[{datetime.now():%H:%M:%S}] {m}", flush=True)
def get_db(): return mysql.connector.connect(**DB, autocommit=False)

def parse_num(s):
    if s is None: return None
    m = re.search(r'-?[\d.]+', str(s))
    return float(m.group()) if m else None

def snmp_walk(ip, community, ver, oid, timeout=3):
    v = '1' if ver == 'v1' else '2c'
    base = oid.lstrip('.')
    try:
        r = subprocess.run(['/usr/bin/snmpwalk', f'-v{v}', '-c', community, '-Oqn',
                            '-t', str(timeout), '-r', '1', ip, oid],
                           capture_output=True, text=True, timeout=timeout * 3)
        out = []
        for line in r.stdout.strip().split('\n'):
            if not line.strip(): continue
            parts = line.split(None, 1)
            if len(parts) != 2: continue
            full = parts[0].strip(); val = parts[1].strip().strip('"')
            stripped = full.lstrip('.')
            suffix = stripped[len(base):].lstrip('.') if stripped.startswith(base) else full.split('.')[-1]
            out.append((suffix, val))
        return out
    except Exception as e:
        log(f"    snmpwalk {oid} on {ip}: {e}")
        return []

# os_icon → optical vendor_key (mirrors nm_cm_guess_vendor)
def guess_vendor(os_icon):
    s = (os_icon or '').lower()
    if s in ('routeros', 'mikrotik'): return 'mikrotik'
    if s == 'cisco': return 'cisco'
    return 'generic'

def ensure(cur):
    cur.execute("""CREATE TABLE IF NOT EXISTS nm_health_samples (
        id BIGINT AUTO_INCREMENT PRIMARY KEY, node_id INT NOT NULL,
        kind VARCHAR(12) NOT NULL DEFAULT 'eth', entity VARCHAR(120) NOT NULL,
        metric VARCHAR(24) NOT NULL, value DOUBLE DEFAULT NULL, recorded_at DATETIME NOT NULL,
        KEY idx_series (node_id, entity, metric, recorded_at), KEY idx_time (recorded_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""")
    cur.execute("""CREATE TABLE IF NOT EXISTS nm_health_counters (
        node_id INT NOT NULL, if_index INT NOT NULL, metric VARCHAR(24) NOT NULL,
        counter BIGINT NOT NULL, polled_at DATETIME NOT NULL,
        PRIMARY KEY (node_id, if_index, metric)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""")
    cur.execute("""CREATE TABLE IF NOT EXISTS nm_health_optical_oids (
        id INT AUTO_INCREMENT PRIMARY KEY, vendor_key VARCHAR(40) NOT NULL DEFAULT 'generic',
        node_id INT DEFAULT NULL, label VARCHAR(80) NOT NULL DEFAULT '', metric VARCHAR(24) NOT NULL,
        oid VARCHAR(160) NOT NULL, scale DOUBLE NOT NULL DEFAULT 1, enabled TINYINT(1) NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, KEY idx_vendor (vendor_key), KEY idx_node (node_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""")

def rate(cur, node_id, if_index, metric, counter, now_dt, now_s):
    """Compute per-second rate vs the stored previous counter; upsert the counter."""
    cur.execute("SELECT counter, polled_at FROM nm_health_counters WHERE node_id=%s AND if_index=%s AND metric=%s",
                (node_id, if_index, metric))
    row = cur.fetchone()
    out = None
    if row is not None:
        prev_c, prev_t = int(row[0]), row[1]
        elapsed = (now_dt - prev_t).total_seconds()
        if elapsed > 0:
            d = counter - prev_c
            if d < 0: d = (counter - prev_c) % (MAX32 + 1)   # counter wrap
            r = d / elapsed
            # Drop physically-impossible rates (broken/non-standard counters, e.g. an AP
            # reporting a packet counter in the error OID) so they never alarm.
            ceil = PLAUSIBLE_MAX.get(metric, 1e6)
            if r <= ceil:
                out = round(r, 4)
    cur.execute("""INSERT INTO nm_health_counters (node_id, if_index, metric, counter, polled_at)
                   VALUES (%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE counter=%s, polled_at=%s""",
                (node_id, if_index, metric, counter, now_s, counter, now_s))
    return out

def collect_node(cur, node, now_dt, now_s):
    node_id, ip, community, ver, os_icon = node
    if not ip or not community: return 0
    # if_index → interface name
    cur.execute("SELECT if_index, if_name FROM nm_interfaces WHERE node_id=%s AND if_index IS NOT NULL AND show_graph=1", (node_id,))
    names = {int(r[0]): (r[1] or f"if{r[0]}") for r in cur.fetchall()}
    if not names:
        return 0
    written = 0
    # ── Ethernet error/discard/FCS counters → rates ──
    raw = {k: {} for k in ETH_OIDS}
    for k, oid in ETH_OIDS.items():
        for suffix, val in snmp_walk(ip, community, ver, oid):
            v = parse_num(val)
            idx = suffix.split('.')[-1] if suffix else None
            if v is not None and idx is not None and idx.isdigit():
                raw[k][int(idx)] = int(v)
    samples = []
    for idx, ifname in names.items():
        defs = [
            ('in_err_rate',  raw['in_err'].get(idx)),
            ('out_err_rate', raw['out_err'].get(idx)),
            ('fcs_rate',     raw['fcs'].get(idx)),
        ]
        # discards = in + out
        di, do = raw['in_disc'].get(idx), raw['out_disc'].get(idx)
        if di is not None or do is not None:
            defs.append(('discard_rate', (di or 0) + (do or 0)))
        for metric, counter in defs:
            if counter is None: continue
            r = rate(cur, node_id, idx, metric, counter, now_dt, now_s)
            if r is not None:
                samples.append((node_id, 'eth', ifname, metric, r, now_s))
    # ── Optical DOM (only enabled OID rows for this node / its vendor) ──
    vendor = guess_vendor(os_icon)
    cur.execute("""SELECT label, metric, oid, scale FROM nm_health_optical_oids
                   WHERE enabled=1 AND (node_id=%s OR (node_id IS NULL AND vendor_key IN (%s,'generic','entity_sensor')))""",
                (node_id, vendor))
    for label, metric, oid, scale in cur.fetchall():
        for suffix, val in snmp_walk(ip, community, ver, oid):
            v = parse_num(val)
            if v is None: continue
            ent = f"{label} #{suffix}" if suffix else label
            samples.append((node_id, 'optical', ent[:120], metric, v * float(scale), now_s))
    if samples:
        cur.executemany("INSERT INTO nm_health_samples (node_id,kind,entity,metric,value,recorded_at) VALUES (%s,%s,%s,%s,%s,%s)", samples)
        written = len(samples)
    return written

def run_once():
    db = get_db(); cur = db.cursor()
    ensure(cur); db.commit()
    cur.execute("""SELECT id, COALESCE(ip_address,''), COALESCE(snmp_community,''),
                          COALESCE(snmp_version,'v2c'), COALESCE(os_icon,'')
                   FROM nm_nodes
                   WHERE COALESCE(monitor_type,'snmp')='snmp' AND snmp_community IS NOT NULL AND snmp_community<>''""")
    nodes = cur.fetchall()
    now_dt = datetime.now(); now_s = now_dt.strftime('%Y-%m-%d %H:%M:%S')
    total = 0
    for node in nodes:
        try:
            n = collect_node(cur, node, now_dt, now_s)
            db.commit(); total += n
        except Exception as e:
            db.rollback(); log(f"  node {node[0]} error: {e}")
    # prune stale counters (no longer polled)
    try:
        cur.execute("DELETE FROM nm_health_counters WHERE polled_at < DATE_SUB(NOW(), INTERVAL 2 DAY)")
        db.commit()
    except Exception:
        db.rollback()
    log(f"health collect: {total} sample(s) across {len(nodes)} node(s)")
    cur.close(); db.close()

def main():
    loop = '--loop' in sys.argv
    while True:
        try:
            run_once()
        except Exception as e:
            log(f"run error: {e}")
        if not loop:
            break
        time.sleep(INTERVAL)

if __name__ == '__main__':
    main()
