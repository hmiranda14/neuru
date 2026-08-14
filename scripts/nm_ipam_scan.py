#!/usr/bin/env python3
"""
nm_ipam_scan.py — IPAM live-occupancy sweep.

Ping-sweeps a registered IPAM subnet (or all of them), SNMP-probes the responders
for a hostname, and upserts the result into nm_ipam_live. Those rows are what let
ipam.php show the REAL occupancy — the devices that are alive on the wire but are
NOT managed nodes (handed out by DHCP, static boxes nobody added yet). Without this
the "free" count lies (it only knew the IPs NEURU already monitors).

Usage:
    nm_ipam_scan.py <subnet_id>     # scan ONE subnet now (on-demand, from ipam.php)
    nm_ipam_scan.py                 # scan ALL subnets (background cron — gated)

Reuses the proven ping/SNMP helpers from nm_discovery.py. Ping is L3 (works from the
NATed container); ARP/MAC is only available when the DHCP-lease pull (SSH) supplies it.
"""

import sys
import ipaddress
from datetime import datetime

import nm_discovery as D          # ping_sweep_parallel, ping_one, snmp_probe, get_db, get_setting
from nm_db_config import DB       # noqa: F401 (kept for parity / future use)

LOG_PREFIX = '[nm_ipam_scan]'
MAX_HOSTS  = 4096                 # never enumerate a subnet bigger than this in one sweep


def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {LOG_PREFIX} {msg}", flush=True)


def set_status(cur, sid, val):
    """Record scan progress in nm_settings so the UI can show 'scanning…/done'."""
    try:
        D.save_setting(cur, f'ipam_scan_status_{sid}', val, 'IPAM scan status')
    except Exception:
        pass


def ensure_live_table(cur):
    """The canonical schema lives in nm_ipam.php (nm_ipam_ensure); mirror the one table
    this cron writes so a background sweep works before anyone opens ipam.php."""
    cur.execute("""
        CREATE TABLE IF NOT EXISTS nm_ipam_live (
            id INT AUTO_INCREMENT PRIMARY KEY,
            subnet_id INT NOT NULL,
            ip_address VARCHAR(45) NOT NULL,
            ip_bin VARBINARY(16) NOT NULL,
            mac VARCHAR(17) DEFAULT NULL,
            hostname VARCHAR(255) DEFAULT NULL,
            method VARCHAR(12) NOT NULL DEFAULT 'ping',
            rtt_ms FLOAT DEFAULT NULL,
            is_managed TINYINT(1) NOT NULL DEFAULT 0,
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen  DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uk_subnet_ip (subnet_id, ip_address),
            KEY idx_last (last_seen),
            KEY idx_ipbin (ip_bin)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)


def scan_subnet(db, cur, sid, cidr, communities, known_ips, iface_ips):
    try:
        net   = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        log(f"  subnet {sid} '{cidr}': invalid ({e})")
        return 0
    if net.version != 4:
        log(f"  subnet {sid} '{cidr}': IPv6 not swept")
        return 0
    hosts = [str(h) for h in net.hosts()]
    if len(hosts) > MAX_HOSTS:
        log(f"  subnet {sid} '{cidr}': {len(hosts)} hosts > cap {MAX_HOSTS} — skipped (too large to sweep)")
        set_status(cur, sid, f'skipped:too_large:{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
        return 0

    set_status(cur, sid, f'running:{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    db.commit()

    log(f"  subnet {sid} '{cidr}': sweeping {len(hosts)} hosts…")
    alive = D.ping_sweep_parallel(hosts, workers=50)
    log(f"  subnet {sid}: {len(alive)} alive")

    # SNMP hostname enrichment — parallel + short timeout so it never dominates the
    # sweep (non-SNMP hosts would otherwise each burn comms × timeout serially).
    def probe_hostname(ip):
        for comm in communities[:5]:
            try:
                sys_name, _ = D.snmp_probe(ip, comm, 'v2c', timeout=1)
            except Exception:
                sys_name = None
            if sys_name:
                return ip, sys_name[:255]
        return ip, None
    hostnames = {}
    if alive:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=20) as pool:
            for fut in as_completed([pool.submit(probe_hostname, ip) for ip in alive]):
                ip, hn = fut.result()
                if hn:
                    hostnames[ip] = hn

    n = 0
    for ip in alive:
        hostname = hostnames.get(ip)
        is_managed = 1 if (ip in known_ips or ip in iface_ips) else 0
        method = 'snmp' if hostname else 'ping'
        try:
            cur.execute("""
                INSERT INTO nm_ipam_live (subnet_id, ip_address, ip_bin, hostname, method, is_managed, first_seen, last_seen)
                VALUES (%s, %s, INET6_ATON(%s), %s, %s, %s, NOW(), NOW())
                ON DUPLICATE KEY UPDATE hostname=COALESCE(VALUES(hostname), hostname),
                    method=VALUES(method), is_managed=VALUES(is_managed), last_seen=NOW()
            """, (sid, ip, ip, hostname, method, is_managed))
            n += 1
        except Exception as e:
            log(f"    upsert {ip} failed: {e}")

    db.commit()
    set_status(cur, sid, f'done:{len(alive)}:{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    db.commit()
    return n


def main():
    one = None
    if len(sys.argv) > 1:
        try:
            one = int(sys.argv[1])
        except ValueError:
            log(f"bad subnet id '{sys.argv[1]}'"); sys.exit(2)

    db  = D.get_db()
    cur = db.cursor()
    ensure_live_table(cur); db.commit()

    # Background (all-subnets) run respects the Scheduled Jobs throttle gate; the
    # on-demand single-subnet run always executes (the user asked for it).
    if one is None:
        try:
            from nm_job_gate import should_run
            if not should_run(cur, db, 'ipam-scan'):
                log("gate: skip (disabled/throttled)"); cur.close(); db.close(); return
        except Exception:
            pass   # fail-open

    # communities: discovery setting + every community already used by a node
    communities_raw = D.get_setting(cur, 'discovery_communities', 'public')
    comms = [c.strip() for c in communities_raw.split(',') if c.strip()]
    cur.execute("SELECT DISTINCT snmp_community FROM nm_nodes WHERE snmp_community IS NOT NULL AND snmp_community<>''")
    comms += [r[0] for r in cur.fetchall()]
    comms = list(dict.fromkeys(comms)) or ['public']

    # managed-IP sets (so is_managed is truthful)
    cur.execute("SELECT ip_address FROM nm_nodes WHERE ip_address IS NOT NULL AND ip_address<>''")
    known_ips = {r[0] for r in cur.fetchall()}
    iface_ips = set()
    try:
        cur.execute("SELECT if_ip_address FROM nm_interfaces WHERE if_ip_address IS NOT NULL AND if_ip_address<>''")
        iface_ips = {r[0] for r in cur.fetchall()}
    except Exception:
        pass

    if one is not None:
        cur.execute("SELECT id, cidr FROM nm_ipam_subnets WHERE id=%s", (one,))
    else:
        cur.execute("SELECT id, cidr FROM nm_ipam_subnets WHERE family=4 ORDER BY id")
    subnets = cur.fetchall()
    if not subnets:
        log("no subnets to scan"); cur.close(); db.close(); return

    total = 0
    for sid, cidr in subnets:
        total += scan_subnet(db, cur, sid, cidr, comms, known_ips, iface_ips)

    log(f"done — {total} live rows upserted across {len(subnets)} subnet(s)")
    cur.close(); db.close()


if __name__ == '__main__':
    main()
