#!/usr/bin/env python3
"""
nm_discovery.py — LAN Auto-Discovery
Ping-sweeps configured subnets, SNMP-probes live hosts,
and stores candidates in nm_discovery_candidates for user review.
Never auto-imports — the user approves each device.
"""

import sys
import subprocess
import ipaddress
import mysql.connector
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_DIR   = Path(__file__).resolve().parent.parent
LOG_PREFIX = '[nm_discovery]'

# ─── DB credentials (filled in by install.sh via nm_db_config.py) ─────────────
from nm_db_config import DB

# ─── Logging ──────────────────────────────────────────────────────────────────
def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {LOG_PREFIX} {msg}", flush=True)

def get_db():
    return mysql.connector.connect(**DB, autocommit=False)

# ─── Settings helpers ─────────────────────────────────────────────────────────
def get_setting(cur, key, default=''):
    cur.execute("SELECT setting_val FROM nm_settings WHERE setting_key=%s", (key,))
    row = cur.fetchone()
    return row[0] if row else default

def save_setting(cur, key, val, label=None):
    cur.execute("""
        INSERT INTO nm_settings (setting_key, setting_val, label) VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE setting_val=%s
    """, (key, val, label, val))

# ─── DB table ─────────────────────────────────────────────────────────────────
def ensure_table(cur):
    cur.execute("""
        CREATE TABLE IF NOT EXISTS nm_discovery_candidates (
            id             INT AUTO_INCREMENT PRIMARY KEY,
            ip_address     VARCHAR(45) NOT NULL,
            sys_name       VARCHAR(200) DEFAULT NULL,
            sys_descr      VARCHAR(500) DEFAULT NULL,
            snmp_community VARCHAR(100) DEFAULT NULL,
            snmp_version   VARCHAR(10)  DEFAULT NULL,
            os_guess       VARCHAR(50)  DEFAULT 'generic',
            subnet         VARCHAR(45)  DEFAULT NULL,
            discovered_at  DATETIME     NOT NULL,
            status         ENUM('pending','imported','rejected') DEFAULT 'pending',
            node_id        INT DEFAULT NULL,
            UNIQUE KEY uk_ip (ip_address),
            INDEX idx_status (status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)

# ─── Ping ─────────────────────────────────────────────────────────────────────
def ping_sweep_fping(subnet_str):
    """Fast sweep via fping. Returns list of responding IPs, or None if fping unavailable."""
    try:
        r = subprocess.run(
            ['fping', '-a', '-q', '-t', '500', '-g', subnet_str],
            capture_output=True, text=True, timeout=120
        )
        return [l.strip() for l in r.stdout.splitlines() if l.strip()]
    except FileNotFoundError:
        return None
    except Exception as e:
        log(f"  fping error: {e}")
        return None

def ping_one(ip_str):
    """Single ping with 1s timeout. Returns True if alive."""
    try:
        r = subprocess.run(
            ['ping', '-c', '1', '-W', '1', ip_str],
            capture_output=True, timeout=3
        )
        return r.returncode == 0
    except Exception:
        return False

def ping_sweep_parallel(hosts, workers=30):
    """Parallel ping sweep. Returns list of responding IPs."""
    alive = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(ping_one, ip): ip for ip in hosts}
        for fut in as_completed(futs):
            if fut.result():
                alive.append(futs[fut])
    return alive

# ─── SNMP probe ───────────────────────────────────────────────────────────────
def snmp_probe(ip_str, community, version='v2c', timeout=2):
    """
    Try snmpget for sysName (.1.3.6.1.2.1.1.5.0) and sysDescr (.1.3.6.1.2.1.1.1.0).
    Returns (sys_name, sys_descr) or (None, None) on failure/timeout.
    """
    ver = '1' if version == 'v1' else '2c'
    try:
        r = subprocess.run(
            ['/usr/bin/snmpget', f'-v{ver}', '-c', community, '-Oqv',
             '-t', str(timeout), '-r', '0', ip_str, '.1.3.6.1.2.1.1.5.0'],
            capture_output=True, text=True, timeout=timeout + 2
        )
        if r.returncode != 0:
            return None, None
        sys_name = r.stdout.strip().strip('"')
        if not sys_name or 'No Such' in sys_name or 'Timeout' in sys_name or 'Error' in sys_name:
            return None, None

        r2 = subprocess.run(
            ['/usr/bin/snmpget', f'-v{ver}', '-c', community, '-Oqv',
             '-t', str(timeout), '-r', '0', ip_str, '.1.3.6.1.2.1.1.1.0'],
            capture_output=True, text=True, timeout=timeout + 2
        )
        sys_descr = ''
        if r2.returncode == 0:
            sys_descr = r2.stdout.strip().strip('"')[:500]
        return sys_name, sys_descr
    except Exception:
        return None, None

def guess_os(sys_name='', sys_descr=''):
    """Guess os_icon from sysName + sysDescr."""
    combined = ((sys_name or '') + ' ' + (sys_descr or '')).lower()
    if 'mikrotik' in combined or 'routeros' in combined:
        return 'routeros'
    if any(k in combined for k in ['linux','ubuntu','debian','centos','fedora','rhel','alpine']):
        return 'linux'
    if any(k in combined for k in ['windows','microsoft']):
        return 'windows'
    if 'cisco' in combined:
        return 'cisco'
    return 'generic'

def probe_host(ip_str, communities, subnet_str, now_str):
    """Full probe: try each community in order. Returns candidate dict."""
    for comm in communities:
        for ver in ['v2c', 'v1']:
            sys_name, sys_descr = snmp_probe(ip_str, comm, ver)
            if sys_name:
                return {
                    'ip_address':     ip_str,
                    'sys_name':       sys_name,
                    'sys_descr':      sys_descr or '',
                    'snmp_community': comm,
                    'snmp_version':   ver,
                    'os_guess':       guess_os(sys_name, sys_descr or ''),
                    'subnet':         subnet_str,
                    'discovered_at':  now_str,
                }
    # Alive but no SNMP — still record it
    return {
        'ip_address':     ip_str,
        'sys_name':       None,
        'sys_descr':      None,
        'snmp_community': None,
        'snmp_version':   None,
        'os_guess':       'generic',
        'subnet':         subnet_str,
        'discovered_at':  now_str,
    }

# ─── Main discovery logic ─────────────────────────────────────────────────────
def discover():
    t_start = datetime.now()
    log("Starting LAN discovery scan")

    db  = get_db()
    cur = db.cursor()

    ensure_table(cur)
    db.commit()

    # Load settings
    subnets_raw     = get_setting(cur, 'discovery_subnets',     '')
    communities_raw = get_setting(cur, 'discovery_communities', 'public')

    # Include communities already used by existing nodes
    cur.execute("SELECT DISTINCT snmp_community FROM nm_nodes WHERE snmp_community IS NOT NULL AND snmp_community != ''")
    node_comms = [row[0] for row in cur.fetchall()]
    base_comms = [c.strip() for c in communities_raw.split(',') if c.strip()]
    all_comms  = list(dict.fromkeys(base_comms + node_comms))  # dedup, order preserved

    if not subnets_raw.strip():
        log("No subnets configured — set discovery_subnets in Settings")
        cur.close(); db.close()
        return

    # IPs to skip
    cur.execute("SELECT ip_address FROM nm_nodes WHERE ip_address IS NOT NULL AND ip_address != ''")
    known_ips = {row[0] for row in cur.fetchall()}
    cur.execute("SELECT ip_address FROM nm_discovery_candidates WHERE status='imported'")
    imported_ips = {row[0] for row in cur.fetchall()}
    skip_ips = known_ips | imported_ips

    now_str     = t_start.strftime('%Y-%m-%d %H:%M:%S')
    total_alive = 0
    total_snmp  = 0
    total_saved = 0

    for subnet_str in [s.strip() for s in subnets_raw.split(',') if s.strip()]:
        try:
            net   = ipaddress.ip_network(subnet_str, strict=False)
            hosts = [str(h) for h in net.hosts()]
        except ValueError as e:
            log(f"  Invalid subnet '{subnet_str}': {e}")
            continue

        log(f"  Scanning {subnet_str} ({len(hosts)} hosts, {len(all_comms)} community string(s))…")

        # Ping sweep — try fping first, fall back to parallel ping
        alive = ping_sweep_fping(subnet_str)
        if alive is None:
            log("    fping not found — using parallel ping (slower)")
            scan_hosts = [h for h in hosts if h not in skip_ips]
            alive = ping_sweep_parallel(scan_hosts)
        else:
            alive = [ip for ip in alive if ip not in skip_ips]

        log(f"    {len(alive)} live host(s) (excluding already-monitored nodes)")
        total_alive += len(alive)

        # SNMP probe live hosts in parallel
        with ThreadPoolExecutor(max_workers=10) as pool:
            futs = {pool.submit(probe_host, ip, all_comms, subnet_str, now_str): ip for ip in alive}
            for fut in as_completed(futs):
                try:
                    c = fut.result()
                    if c['sys_name']:
                        log(f"    SNMP OK  : {c['ip_address']} — {c['sys_name']}")
                        total_snmp += 1
                    else:
                        log(f"    No SNMP  : {c['ip_address']}")

                    cur.execute("""
                        INSERT INTO nm_discovery_candidates
                            (ip_address, sys_name, sys_descr, snmp_community, snmp_version,
                             os_guess, subnet, discovered_at, status)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'pending')
                        ON DUPLICATE KEY UPDATE
                            sys_name       = VALUES(sys_name),
                            sys_descr      = VALUES(sys_descr),
                            snmp_community = VALUES(snmp_community),
                            snmp_version   = VALUES(snmp_version),
                            os_guess       = VALUES(os_guess),
                            discovered_at  = VALUES(discovered_at),
                            status         = IF(status = 'rejected', 'rejected', 'pending')
                    """, (
                        c['ip_address'], c['sys_name'], c['sys_descr'],
                        c['snmp_community'], c['snmp_version'],
                        c['os_guess'], c['subnet'], c['discovered_at']
                    ))
                    total_saved += 1
                except Exception as e:
                    log(f"    Probe error {futs[fut]}: {e}")

        db.commit()
        log(f"  {subnet_str}: done")

    save_setting(cur, 'discovery_last_run', now_str, 'Last discovery run')
    db.commit()

    elapsed = (datetime.now() - t_start).total_seconds()
    log(f"Discovery complete — {total_alive} live, {total_snmp} with SNMP, {total_saved} candidates, {elapsed:.1f}s")
    cur.close()
    db.close()

if __name__ == '__main__':
    try:
        discover()
    except Exception as e:
        log(f"FATAL: {e}")
        raise
