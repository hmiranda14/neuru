#!/usr/bin/env python3
"""
nm_poller.py — Network Monitor statistics collector (LibreNMS-independent)
Polls devices via direct SNMP. LibreNMS is used only as an optional fallback
for nodes that have no SNMP credentials configured.
"""

import sys
import json
import time
import re
import subprocess
import mysql.connector
from datetime import datetime
from pathlib import Path

BASE_DIR   = Path(__file__).resolve().parent.parent
CFG_FILE   = BASE_DIR / 'librenms_config.json'   # optional — only used if present and enabled
LOG_PREFIX = '[nm_poller]'

# ─── DB credentials (filled in by install.sh via nm_db_config.py) ─────────────
from nm_db_config import DB

# ─── Logging ──────────────────────────────────────────────────────────────────
def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {LOG_PREFIX} {msg}", flush=True)

def get_db():
    return mysql.connector.connect(**DB, autocommit=False)

# ─── Optional LibreNMS helper (fallback only) ─────────────────────────────────
def load_lnms_cfg():
    """Load LibreNMS config if it exists and is enabled. Returns (url, token) or (None, None)."""
    if not CFG_FILE.exists():
        return None, None
    try:
        with open(CFG_FILE) as f:
            cfg = json.load(f)
        if not cfg.get('enabled'):
            return None, None
        return cfg['url'].rstrip('/'), cfg['token']
    except Exception:
        return None, None

def lnms_get(base_url, token, endpoint, params=None, timeout=8):
    try:
        import requests
        url = f"{base_url}{endpoint}"
        r = requests.get(url, headers={'X-Auth-Token': token}, params=params, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        log(f"  API error {endpoint}: {e}")
        return None

# ─── SNMP helpers ─────────────────────────────────────────────────────────────
def parse_num(s):
    """Extract first numeric value from an SNMP output string."""
    if s is None:
        return None
    m = re.search(r'-?[\d.]+', str(s))
    return float(m.group()) if m else None

_HEXTOK = set('0123456789abcdefABCDEF')
def decode_snmp_octet(value):
    """net-snmp renders an OCTET STRING as a space-separated hex dump (e.g.
    '4D 69 63 ...') whenever it holds a non-printable byte — common for Windows
    ifDescr, which carries a trailing NUL. Detect that shape and decode back to
    text (dropping the NUL + control chars). Plain strings pass through unchanged."""
    if not value:
        return value
    toks = value.strip().split()
    if len(toks) >= 2 and all(len(t) == 2 and t[0] in _HEXTOK and t[1] in _HEXTOK for t in toks):
        try:
            raw  = bytes(int(t, 16) for t in toks)
            text = raw.split(b'\x00', 1)[0].decode('utf-8', 'replace')   # cut at first NUL
            text = ''.join(ch for ch in text if ch.isprintable()).strip()
            # only accept a clean ASCII result — guards against a coincidental
            # two-token name (e.g. 'AB CD') being mangled into replacement chars
            if text and all(ord(ch) < 127 for ch in text):
                return text
        except Exception:
            pass
    return value

# Vendor-published virtual/pseudo adapters that aren't worth auto-monitoring or
# alerting on (generic across hosts — Windows miniports/tunnels, container veths,
# loopbacks). Matched as case-insensitive substrings of the interface name. New
# such interfaces are still DISCOVERED (visible) but default to show_graph=0, so a
# laptop's 30 phantom NICs don't each raise an "interface down" alert.
IFACE_SKIP_PATTERNS = (
    'wan miniport', 'miniport', 'loopback', 'teredo', '6to4', 'isatap',
    'ip-https', 'kernel debug', 'wi-fi direct', 'wifi direct', 'bluetooth device',
    'ras async', 'pseudo-interface', 'virtual adapter', 'tunnel adapter',
    'qos packet', 'wfp ', 'npcap', 'wintun', 'tap-windows',
    'veth', 'vethernet', 'docker', 'br-', 'virbr',
)
def is_virtual_iface(name):
    n = (name or '').lower()
    return any(p in n for p in IFACE_SKIP_PATTERNS)

def snmp_walk(ip, community, snmp_ver, oid, timeout=3):
    """
    Walk OID subtree using snmpwalk with numeric+quiet output (-Oqn).
    Returns list of {oid, suffix, value} dicts where suffix is the
    portion of the OID after the requested base OID.
    """
    ver  = '1' if snmp_ver == 'v1' else '2c'
    base = oid.lstrip('.')
    try:
        r = subprocess.run(
            ['/usr/bin/snmpwalk', f'-v{ver}', '-c', community, '-Oqn',
             '-t', str(timeout), '-r', '1', ip, oid],
            capture_output=True, text=True, timeout=timeout * 3
        )
        result = []
        for line in r.stdout.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            full_oid = parts[0].strip()
            value    = parts[1].strip().strip('"')
            stripped = full_oid.lstrip('.')
            suffix   = stripped[len(base):].lstrip('.') if stripped.startswith(base) else full_oid.split('.')[-1]
            result.append({'oid': full_oid, 'suffix': suffix, 'value': value})
        return result
    except Exception as e:
        log(f"    snmpwalk error {oid} on {ip}: {e}")
        return []

def snmp_get_val(ip, community, snmp_ver, oid, timeout=3):
    """Get single OID numeric value. Returns float or None on failure."""
    ver = '1' if snmp_ver == 'v1' else '2c'
    try:
        r = subprocess.run(
            ['/usr/bin/snmpget', f'-v{ver}', '-c', community, '-Oqv',
             '-t', str(timeout), '-r', '1', ip, oid],
            capture_output=True, text=True, timeout=timeout * 3
        )
        if r.returncode != 0:
            return None
        val = r.stdout.strip()
        if not val or 'No Such' in val or 'noSuch' in val:
            return None
        return parse_num(val)
    except Exception as e:
        log(f"    snmpget error {oid} on {ip}: {e}")
        return None

def snmp_get_str(ip, community, snmp_ver, oid, timeout=3):
    """Get single OID as string. Returns str or None."""
    ver = '1' if snmp_ver == 'v1' else '2c'
    try:
        r = subprocess.run(
            ['/usr/bin/snmpget', f'-v{ver}', '-c', community, '-Oqv',
             '-t', str(timeout), '-r', '1', ip, oid],
            capture_output=True, text=True, timeout=timeout * 3
        )
        if r.returncode != 0:
            return None
        val = r.stdout.strip().strip('"')
        return val if val and 'No Such' not in val else None
    except Exception:
        return None

# ─── Health metric pollers (direct SNMP) ──────────────────────────────────────
def poll_hr_cpu(ip, community, snmp_ver):
    """Walk hrProcessorLoad. Returns list of (suffix, pct) tuples."""
    rows   = snmp_walk(ip, community, snmp_ver, '.1.3.6.1.2.1.25.3.3.1.2')
    result = []
    for row in rows:
        v = parse_num(row['value'])
        if v is not None and 0 <= v <= 100:
            result.append((row['suffix'], v))
    return result

def poll_hr_storage(ip, community, snmp_ver):
    """Walk hrStorageTable. Returns list of dicts with memory/disk info."""
    TYPES = {
        '.1.3.6.1.2.1.25.2.1.2': 'memory',
        '.1.3.6.1.2.1.25.2.1.4': 'disk',
        '.1.3.6.1.2.1.25.2.1.9': 'disk',
    }
    rows    = snmp_walk(ip, community, snmp_ver, '.1.3.6.1.2.1.25.2.3.1')
    entries = {}

    for row in rows:
        parts = row['suffix'].split('.', 1)
        if len(parts) < 2:
            continue
        col = parts[0]
        idx = parts[1]
        if idx not in entries:
            entries[idx] = {}
        val = row['value']
        if col == '2':   entries[idx]['type_oid'] = val
        elif col == '3': entries[idx]['descr']    = val
        elif col == '4': entries[idx]['alloc']    = parse_num(val) or 1.0
        elif col == '5': entries[idx]['size']     = parse_num(val) or 0.0
        elif col == '6': entries[idx]['used']     = parse_num(val) or 0.0

    # ── Linux memory correction ──────────────────────────────────────────────
    # On Linux/net-snmp, hrStorageRam "used" = MemTotal − MemFree, which COUNTS
    # reclaimable buffers/cache and makes RAM look ~95% used. Correct it to the real
    # used (what `free` and htop show):
    #   • preferred: MemAvailable (the "Available memory" entry) → used = total − available
    #   • fallback : subtract the "Memory buffers" + "Cached memory" entries
    # These extra entries are hrStorageOther (only present on Linux), so other vendors
    # fall through unchanged.
    avail_bytes = None
    cache_buf_bytes = 0.0
    for e in entries.values():
        descr = (e.get('descr') or '').lower()
        sz = float(e.get('size', 0)); us = float(e.get('used', 0)); al = float(e.get('alloc', 1))
        if 'available memory' in descr and sz > 0:
            avail_bytes = sz * al
        elif 'cached' in descr or 'buffer' in descr:   # "Cached memory", "Memory buffers"
            cache_buf_bytes += us * al

    result = []
    for idx, e in entries.items():
        type_oid     = e.get('type_oid', '')
        storage_type = None
        for t_oid, t_name in TYPES.items():
            if t_oid in type_oid:
                storage_type = t_name
                break
        if not storage_type:
            continue
        size  = float(e.get('size', 0))
        used  = float(e.get('used', 0))
        alloc = float(e.get('alloc', 1))
        if size <= 0:
            continue
        total_bytes = size * alloc
        used_bytes  = used * alloc
        if storage_type == 'memory':
            if avail_bytes is not None:
                used_bytes = max(0.0, total_bytes - avail_bytes)
            elif cache_buf_bytes > 0:
                used_bytes = max(0.0, used_bytes - cache_buf_bytes)
        perc = round(used_bytes / total_bytes * 100, 2) if total_bytes > 0 else 0.0
        result.append({
            'idx'         : idx,
            'descr'       : e.get('descr', idx),
            'storage_type': storage_type,
            'perc'        : perc,
            'bytes_used'  : int(used_bytes),
            'bytes_total' : int(total_bytes),
        })
    return result

def poll_uptime_snmp(ip, community, snmp_ver):
    """sysUpTime → seconds. snmpget -Oqv formats timeticks as 'D:HH:MM:SS.ss'
    (or 'HH:MM:SS.ss'), so parse that rather than treating it as a plain number."""
    raw = snmp_get_str(ip, community, snmp_ver, '.1.3.6.1.2.1.1.3.0')
    if not raw:
        return None
    raw = raw.strip().strip('"')
    if raw.isdigit():                      # raw timeticks (1/100 s)
        return round(int(raw) / 100.0, 1)
    try:
        parts = raw.split(':')
        sec  = float(parts[-1])
        mins = int(parts[-2]) if len(parts) >= 2 else 0
        hrs  = int(parts[-3]) if len(parts) >= 3 else 0
        days = int(parts[-4]) if len(parts) >= 4 else 0
        return round(days * 86400 + hrs * 3600 + mins * 60 + sec, 1)
    except Exception:
        return None


def detect_os_icon(sys_descr, sys_oid):
    """Map sysDescr / sysObjectID to a NetMon os_icon (mikrotik|cisco|linux|generic)."""
    d = (sys_descr or '').lower()
    o = sys_oid or ''
    if '14988' in o or 'routeros' in d or 'mikrotik' in d:
        return 'mikrotik'
    if '.1.3.6.1.4.1.9' in o or 'cisco' in d or ' ios ' in f' {d} ':
        return 'cisco'
    if '8072' in o or '2021' in o or 'linux' in d or 'ubuntu' in d or 'debian' in d:
        return 'linux'
    return 'generic'


def poll_system_info(cur, node_id, ip, community, snmp_ver):
    """Read the SNMP system group and refresh nm_nodes (hostname/location/model/os).
    Never overwrites the user-chosen display_name."""
    sys_name  = snmp_get_str(ip, community, snmp_ver, '.1.3.6.1.2.1.1.5.0')
    sys_descr = snmp_get_str(ip, community, snmp_ver, '.1.3.6.1.2.1.1.1.0')
    sys_loc   = snmp_get_str(ip, community, snmp_ver, '.1.3.6.1.2.1.1.6.0')
    sys_oid   = snmp_get_str(ip, community, snmp_ver, '.1.3.6.1.2.1.1.2.0')

    sets, vals = [], []
    if sys_name:
        sets.append('hostname=%s');  vals.append(sys_name[:200])
    if sys_loc:
        sets.append('location=%s');  vals.append(sys_loc[:200])
    if sys_descr:
        sets.append('hw_model=%s');  vals.append(sys_descr[:200])
    icon = detect_os_icon(sys_descr, sys_oid)
    if icon and icon != 'generic':
        sets.append('os_icon=%s');   vals.append(icon)
    if not sets:
        return False
    vals.append(node_id)
    cur.execute(f"UPDATE nm_nodes SET {', '.join(sets)} WHERE id=%s", tuple(vals))
    log(f"    SysInfo: {sys_name or '?'} / {icon} / {sys_loc or '—'}")
    return True

def _reachable(ip, count=2, timeout=1):
    """Quick ICMP reachability for the SNMP-node gate → (is_up, avg_ms|None, loss%).
    Lets a DOWN device be skipped in ~2s instead of stalling the poller for minutes on
    SNMP timeouts, and lets the alert engine flag it fast via a ping-down sample."""
    try:
        r = subprocess.run(['/usr/bin/ping', '-c', str(count), '-W', str(timeout), '-n', ip],
                           capture_output=True, text=True, timeout=count * timeout + 5)
        m = re.search(r'(\d+(?:\.\d+)?)%\s*packet loss', r.stdout); loss = float(m.group(1)) if m else 100.0
        mr = re.search(r'=\s*[\d.]+/([\d.]+)/', r.stdout); avg = float(mr.group(1)) if mr else None
        return (loss < 100.0), avg, loss
    except Exception:
        return False, None, 100.0

def poll_snmp_health(cur, node_id, ip, community, snmp_ver, now):
    """
    Poll CPU, memory, disk, custom OIDs, and uptime via direct SNMP.
    Stores results in nm_device_stats. Returns count of metrics stored.
    """
    stored = 0
    ver    = snmp_ver or 'v2c'

    # ── CPU ───────────────────────────────────────────────────────────────────
    cpu_vals = poll_hr_cpu(ip, community, ver)
    if cpu_vals:
        avg_cpu = round(sum(v for _, v in cpu_vals) / len(cpu_vals), 2)
        cur.execute("""
            INSERT INTO nm_device_stats (node_id, recorded_at, metric_type, metric_key, value)
            VALUES (%s, %s, 'cpu', 'avg', %s)
        """, (node_id, now, avg_cpu))
        for j, (suffix, pct) in enumerate(cpu_vals):
            cpu_key = f'cpu{suffix}' if int(suffix) < 1000 else f'core_{j+1}'
            cur.execute("""
                INSERT INTO nm_device_stats (node_id, recorded_at, metric_type, metric_key, value)
                VALUES (%s, %s, 'cpu', %s, %s)
            """, (node_id, now, cpu_key, pct))
        stored += len(cpu_vals) + 1
        log(f"    SNMP CPU: {avg_cpu:.1f}% avg ({len(cpu_vals)} core(s))")

    # ── Memory + Disk ─────────────────────────────────────────────────────────
    for se in poll_hr_storage(ip, community, ver):
        mtype = 'memory' if se['storage_type'] == 'memory' else 'storage'
        cur.execute("""
            INSERT INTO nm_device_stats (node_id, recorded_at, metric_type, metric_key, value, raw_value)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (node_id, now, mtype, se['descr'][:200], se['perc'], se['bytes_used']))
        stored += 1
        log(f"    SNMP {mtype.upper()} '{se['descr']}': {se['perc']}%")

    # ── Uptime ────────────────────────────────────────────────────────────────
    uptime = poll_uptime_snmp(ip, community, ver)
    if uptime is not None:
        cur.execute("""
            INSERT INTO nm_device_stats (node_id, recorded_at, metric_type, metric_key, value)
            VALUES (%s, %s, 'uptime', 'seconds', %s)
        """, (node_id, now, uptime))
        stored += 1

    # ── Custom OIDs from template + per-node config ───────────────────────────
    try:
        cur.execute("""
            SELECT oc.metric_name, oc.metric_type, oc.oid, oc.oid_total, oc.walk, oc.scale
            FROM nm_oid_configs oc
            WHERE oc.enabled = 1
              AND (
                oc.node_id = %s
                OR oc.template_id IN (
                    SELECT oid_template_id FROM nm_nodes WHERE id = %s AND oid_template_id IS NOT NULL
                )
              )
            ORDER BY oc.sort_order
        """, (node_id, node_id))

        for (mname, mtype, oid, oid_total, do_walk, scale) in cur.fetchall():
            scale = float(scale or 1.0)
            try:
                if do_walk:
                    for wrow in snmp_walk(ip, community, ver, oid):
                        v = parse_num(wrow['value'])
                        if v is None:
                            continue
                        cur.execute("""
                            INSERT INTO nm_device_stats (node_id, recorded_at, metric_type, metric_key, value)
                            VALUES (%s, %s, %s, %s, %s)
                        """, (node_id, now, mtype, f"{mname}.{wrow['suffix']}"[:200], round(v * scale, 4)))
                        stored += 1
                else:
                    raw = snmp_get_val(ip, community, ver, oid)
                    if raw is None:
                        continue
                    raw_bytes = None
                    if oid_total:
                        total = snmp_get_val(ip, community, ver, oid_total)
                        if total and total > 0:
                            if mtype == 'memory':
                                # Memory convention: the polled OID is FREE/available
                                # memory and oid_total is TOTAL → report USED%. `scale`
                                # is bytes-per-unit (e.g. 1024 when the device reports KB)
                                # so we can also store used bytes for the UI.
                                used  = max(0.0, total - raw)
                                value = round(used / total * 100, 2)
                                raw_bytes = int(used * (scale or 1))
                            else:
                                value = round(raw / total * 100, 2)
                        else:
                            value = None
                    else:
                        value = round(raw * scale, 4)
                    if value is not None:
                        if raw_bytes is not None:
                            cur.execute("""
                                INSERT INTO nm_device_stats (node_id, recorded_at, metric_type, metric_key, value, raw_value)
                                VALUES (%s, %s, %s, %s, %s, %s)
                            """, (node_id, now, mtype, mname[:200], value, raw_bytes))
                        else:
                            cur.execute("""
                                INSERT INTO nm_device_stats (node_id, recorded_at, metric_type, metric_key, value)
                                VALUES (%s, %s, %s, %s, %s)
                            """, (node_id, now, mtype, mname[:200], value))
                        stored += 1
                        log(f"    OID '{mname}': {value}")
            except Exception as e:
                log(f"    OID error {oid}: {e}")
    except Exception as e:
        log(f"    OID config query error: {e}")

    return stored

# ─── Interface traffic polling (direct SNMP) ──────────────────────────────────
def discover_interfaces(cur, node_id, ip, community, snmp_ver):
    """
    Auto-discover interfaces via SNMP ifTable.
    - Inserts new interfaces into nm_interfaces.
    - Updates if_index for existing rows where if_name matches but if_index is NULL.
    Returns (added, updated) counts.
    """
    ver = snmp_ver or 'v2c'

    # Walk ifDescr (.1.3.6.1.2.1.2.2.1.2). Decode hex-dumped OCTET STRINGs (Windows)
    # so names are human-readable AND distinct (raw hex truncates to identical stubs).
    if_names = {}
    for row in snmp_walk(ip, community, ver, '.1.3.6.1.2.1.2.2.1.2'):
        if_names[row['suffix']] = decode_snmp_octet(row['value'])

    if not if_names:
        log(f"    discover_interfaces: no ifDescr data from {ip}")
        return 0, 0

    # Get existing interfaces for this node
    cur.execute("SELECT id, if_name, if_index FROM nm_interfaces WHERE node_id = %s", (node_id,))
    existing = cur.fetchall()
    existing_by_idx  = {str(row[2]): row[0] for row in existing if row[2] is not None}
    existing_by_name = {row[1]: row[0] for row in existing}

    added = updated = 0
    for idx_str, name in if_names.items():
        name_trunc = name[:100]
        if idx_str in existing_by_idx:
            continue  # already tracked by index

        if name_trunc in existing_by_name:
            # Known interface with null if_index — fill it in
            iface_id = existing_by_name[name_trunc]
            cur.execute("UPDATE nm_interfaces SET if_index=%s WHERE id=%s", (int(idx_str), iface_id))
            updated += 1
        else:
            # New interface — insert DISABLED (show_graph=0). NEURU monitors ONLY the
            # interfaces the operator selects in Config; the poller no longer auto-enables
            # every "real-looking" NIC. A Windows box exposes many identically named /
            # virtual adapters (multiple "Realtek PCIe GbE", Hyper-V/WSL host-only NICs on
            # 192.168.64.x, etc.), some permanently down — auto-monitoring them produced
            # false "interface down" alarms. reconcile_primary_iface() auto-selects just
            # the single interface carrying the management IP as a sensible default.
            show = 0
            cur.execute("""
                INSERT INTO nm_interfaces
                    (node_id, lnms_port_id, if_name, display_name, if_index, show_graph, sort_order)
                VALUES (%s, NULL, %s, %s, %s, %s, %s)
            """, (node_id, name_trunc, name_trunc, int(idx_str), show, int(idx_str)))
            added += 1

    return added, updated

def poll_interface_ips(cur, node_id, ip, community, snmp_ver):
    """Walk ipAddrTable (ipAdEntIfIndex: IP→ifIndex) and store each interface's IP
    on nm_interfaces. Returns (updated, ipmap) where ipmap = {ip: current ifIndex} —
    used to self-heal the monitored interface across Windows ifIndex drift."""
    updated = 0
    ipmap = {}
    for row in snmp_walk(ip, community, snmp_ver or 'v2c', '.1.3.6.1.2.1.4.20.1.2'):
        ipaddr = row['suffix']           # OID suffix = the IPv4 address
        idx    = parse_num(row['value']) # value      = ifIndex
        if idx is None or ipaddr.count('.') != 3:
            continue
        if ipaddr.startswith('127.') or ipaddr == '0.0.0.0':
            continue
        ipmap[ipaddr] = int(idx)
        cur.execute(
            "UPDATE nm_interfaces SET if_ip_address=%s WHERE node_id=%s AND if_index=%s",
            (ipaddr, node_id, int(idx))
        )
        updated += cur.rowcount
    if updated:
        log(f"    Interface IPs: {updated} set")
    return updated, ipmap

def reconcile_primary_iface(cur, node_id, mgmt_ip, ipmap):
    """Windows renumbers ifIndex on reboot/driver change, so a monitored interface gets
    stuck on a now-dead ifIndex while its IP moved to a new one (false 'interface down').
    Re-point the monitored interface that carries the node's MANAGEMENT IP to whatever
    ifIndex currently owns that IP. Self-heals across reboots."""
    if not mgmt_ip:
        return
    cur_idx = ipmap.get(mgmt_ip)
    if not cur_idx:
        return
    # Sensible one-time default: if the operator hasn't selected ANY interface to monitor
    # yet, auto-select the single interface that carries the management IP — but ONLY if it
    # isn't a virtual/pseudo adapter. This keeps a fresh node's real NIC monitored out of
    # the box without re-enabling the phantom NICs discovery now leaves OFF. Never overrides
    # an operator who already picked interfaces (only fires when zero are monitored).
    cur.execute("SELECT COUNT(*) FROM nm_interfaces WHERE node_id=%s AND show_graph=1", (node_id,))
    if (cur.fetchone() or [0])[0] == 0:
        cur.execute("""SELECT id, if_name FROM nm_interfaces
                       WHERE node_id=%s AND if_index=%s ORDER BY id LIMIT 1""", (node_id, int(cur_idx)))
        mrow = cur.fetchone()
        if mrow and not is_virtual_iface(mrow[1] or ''):
            cur.execute("UPDATE nm_interfaces SET show_graph=1 WHERE id=%s", (mrow[0],))
            log(f"    Auto-selected mgmt-IP interface '{mrow[1]}' (ifIndex {cur_idx}) as default monitor")
    # the operator's monitored interface for the mgmt IP (keeps its friendly name/alias)
    cur.execute("""SELECT id, if_index FROM nm_interfaces
                   WHERE node_id=%s AND show_graph=1 AND if_ip_address=%s
                   ORDER BY id LIMIT 1""", (node_id, mgmt_ip))
    row = cur.fetchone()
    if row and int(row[1]) != int(cur_idx):
        cur.execute("UPDATE nm_interfaces SET if_index=%s WHERE id=%s", (int(cur_idx), row[0]))
        log(f"    Primary iface re-pointed to live ifIndex {cur_idx} (was {row[1]}) — Windows ifIndex drift")

def poll_interfaces_direct(cur, node_id, ip, community, snmp_ver, now):
    """
    Poll interface traffic counters directly via SNMP.
    Prefers 64-bit HC counters (ifXTable); falls back to 32-bit ifTable.
    Calculates byte/sec rates from deltas stored in nm_if_counters.
    Writes to nm_port_stats using nm_interfaces.id as port_id.
    Returns count of port_stat rows written.
    """
    ver = snmp_ver or 'v2c'

    # ── Read counters: try 64-bit HC first ────────────────────────────────────
    hc_in  = {}   # if_index_str -> counter (int)
    hc_out = {}
    use_32bit = False

    for row in snmp_walk(ip, community, ver, '.1.3.6.1.2.1.31.1.1.1.6'):   # ifHCInOctets
        v = parse_num(row['value'])
        if v is not None:
            hc_in[row['suffix']] = int(v)
    for row in snmp_walk(ip, community, ver, '.1.3.6.1.2.1.31.1.1.1.10'):  # ifHCOutOctets
        v = parse_num(row['value'])
        if v is not None:
            hc_out[row['suffix']] = int(v)

    # Some agents (e.g. Cisco AireOS / Mobility Express) advertise the ifXTable but
    # return placeholder HC counters (~2^56 / near 2^64). Treat those as invalid and
    # fall back to the 32-bit ifTable counters, which are real on those devices.
    HC_BOGUS = 1 << 56
    hc_bogus = (any(x >= HC_BOGUS for x in hc_in.values()) or
                any(x >= HC_BOGUS for x in hc_out.values()))

    if (not hc_in) or hc_bogus:
        use_32bit = True
        hc_in, hc_out = {}, {}
        for row in snmp_walk(ip, community, ver, '.1.3.6.1.2.1.2.2.1.10'): # ifInOctets (32-bit)
            v = parse_num(row['value'])
            if v is not None:
                hc_in[row['suffix']] = int(v)
        for row in snmp_walk(ip, community, ver, '.1.3.6.1.2.1.2.2.1.16'): # ifOutOctets (32-bit)
            v = parse_num(row['value'])
            if v is not None:
                hc_out[row['suffix']] = int(v)

    if not hc_in:
        log(f"    No interface counter data from {ip}")
        return 0

    # ── Operational status and speed ──────────────────────────────────────────
    if_status = {}
    if_speed  = {}
    for row in snmp_walk(ip, community, ver, '.1.3.6.1.2.1.2.2.1.8'):  # ifOperStatus
        v = parse_num(row['value'])
        if v is not None:
            if_status[row['suffix']] = 'up' if int(v) == 1 else 'down'
    for row in snmp_walk(ip, community, ver, '.1.3.6.1.2.1.2.2.1.5'):  # ifSpeed
        v = parse_num(row['value'])
        if v is not None:
            if_speed[row['suffix']] = int(v)

    # ── Map if_index → nm_interfaces.id for this node ─────────────────────────
    cur.execute("""
        SELECT id, if_index FROM nm_interfaces
        WHERE node_id = %s AND if_index IS NOT NULL AND show_graph = 1
    """, (node_id,))
    iface_map = {str(row[1]): row[0] for row in cur.fetchall()}  # idx_str -> nm_iface_id

    if not iface_map:
        log(f"    No monitored interfaces for node {node_id} — run discovery first")
        return 0

    # ── Load previous counter snapshot ────────────────────────────────────────
    cur.execute("""
        SELECT if_index, in_octets, out_octets, polled_at
        FROM nm_if_counters WHERE node_id = %s
    """, (node_id,))
    prev = {str(row[0]): (int(row[1]), int(row[2]), row[3]) for row in cur.fetchall()}

    now_dt  = datetime.strptime(now, '%Y-%m-%d %H:%M:%S')
    MAX32   = 0xFFFFFFFF
    stored  = 0

    for idx_str, iface_id in iface_map.items():
        cur_in  = hc_in.get(idx_str)
        cur_out = hc_out.get(idx_str)
        if cur_in is None or cur_out is None:
            continue

        oper  = if_status.get(idx_str, 'unknown')
        speed = if_speed.get(idx_str, 0)

        in_rate = out_rate = 0
        in_util = out_util = None

        if idx_str in prev:
            prev_in, prev_out, prev_time = prev[idx_str]
            elapsed = (now_dt - prev_time).total_seconds()

            if elapsed > 0:
                if use_32bit:
                    d_in  = (cur_in  - prev_in)  % (MAX32 + 1)
                    d_out = (cur_out - prev_out) % (MAX32 + 1)
                else:
                    d_in  = max(0, cur_in  - prev_in)
                    d_out = max(0, cur_out - prev_out)

                # Sanity: skip obviously bogus spikes (>100 Gbps on any interface)
                max_reasonable = 100_000_000_000 * elapsed / 8
                if d_in  > max_reasonable: d_in  = 0
                if d_out > max_reasonable: d_out = 0

                in_rate  = int(d_in  / elapsed)
                out_rate = int(d_out / elapsed)

                if speed > 0:
                    in_util  = round(in_rate  * 8 / speed * 100, 2)
                    out_util = round(out_rate * 8 / speed * 100, 2)

        cur.execute("""
            INSERT INTO nm_port_stats
                (node_id, port_id, recorded_at, in_rate, out_rate, in_util, out_util, oper_status, if_speed)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (node_id, iface_id, now, in_rate, out_rate, in_util, out_util, oper, speed))
        stored += 1

        # Upsert counter snapshot
        cur.execute("""
            INSERT INTO nm_if_counters (node_id, if_index, in_octets, out_octets, polled_at)
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE in_octets=%s, out_octets=%s, polled_at=%s
        """, (node_id, int(idx_str), cur_in, cur_out, now,
              cur_in, cur_out, now))

    log(f"    Direct SNMP ifaces: {stored} port sample(s) ({'32-bit' if use_32bit else '64-bit'} counters)")
    return stored

# ─── Ensure tables exist ──────────────────────────────────────────────────────
def ensure_tables(cur):
    cur.execute("""
        CREATE TABLE IF NOT EXISTS nm_port_stats (
            id          BIGINT AUTO_INCREMENT PRIMARY KEY,
            node_id     INT NOT NULL,
            port_id     INT NOT NULL,
            recorded_at DATETIME NOT NULL,
            in_rate     BIGINT DEFAULT 0,
            out_rate    BIGINT DEFAULT 0,
            in_util     DECIMAL(6,2) DEFAULT NULL,
            out_util    DECIMAL(6,2) DEFAULT NULL,
            oper_status VARCHAR(20) DEFAULT NULL,
            if_speed    BIGINT DEFAULT 0,
            INDEX idx_port_time (port_id, recorded_at),
            INDEX idx_node_time (node_id, recorded_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS nm_device_stats (
            id          BIGINT AUTO_INCREMENT PRIMARY KEY,
            node_id     INT NOT NULL,
            recorded_at DATETIME NOT NULL,
            metric_type VARCHAR(50) NOT NULL,
            metric_key  VARCHAR(200) DEFAULT '',
            value       DECIMAL(12,4) DEFAULT NULL,
            raw_value   BIGINT DEFAULT NULL,
            INDEX idx_node_metric_time (node_id, metric_type, recorded_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    try:
        cur.execute("ALTER TABLE nm_device_stats ADD COLUMN raw_value BIGINT DEFAULT NULL")
    except Exception:
        pass
    # (node_id, recorded_at) makes MAX(recorded_at) WHERE node_id=X an O(1) index lookup — without
    # it, net_mon.php's per-node "last poll" query scanned ~190k rows/node → ~30s page loads.
    try:
        cur.execute("CREATE INDEX idx_node_recorded ON nm_device_stats (node_id, recorded_at)")
    except Exception:
        pass
    # (node_id, metric_type, metric_key, recorded_at) turns net_mon_stats.php's "latest value per
    # metric_key" join (GROUP BY metric_key + MAX(recorded_at)) into a loose index scan (was ~4s → 0.1s).
    try:
        cur.execute("CREATE INDEX idx_node_type_key_time ON nm_device_stats (node_id, metric_type, metric_key, recorded_at)")
    except Exception:
        pass
    cur.execute("""
        CREATE TABLE IF NOT EXISTS nm_if_counters (
            id          BIGINT AUTO_INCREMENT PRIMARY KEY,
            node_id     INT NOT NULL,
            if_index    INT NOT NULL,
            in_octets   BIGINT UNSIGNED DEFAULT 0,
            out_octets  BIGINT UNSIGNED DEFAULT 0,
            polled_at   DATETIME NOT NULL,
            UNIQUE KEY uk_node_if (node_id, if_index),
            INDEX idx_node (node_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS nm_poller_config (
            id           INT AUTO_INCREMENT PRIMARY KEY,
            cfg_key      VARCHAR(100) NOT NULL UNIQUE,
            cfg_value    VARCHAR(500) NOT NULL DEFAULT '',
            updated_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS nm_settings (
            id          INT AUTO_INCREMENT PRIMARY KEY,
            setting_key VARCHAR(100) NOT NULL UNIQUE,
            setting_val VARCHAR(500) NOT NULL DEFAULT '',
            label       VARCHAR(200) DEFAULT NULL,
            updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS nm_poller_log (
            id           BIGINT AUTO_INCREMENT PRIMARY KEY,
            ran_at       DATETIME NOT NULL,
            duration_ms  INT DEFAULT 0,
            nodes_polled INT DEFAULT 0,
            ports_polled INT DEFAULT 0,
            errors       INT DEFAULT 0,
            status       VARCHAR(20) DEFAULT 'ok'
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS nm_oid_templates (
            id          INT AUTO_INCREMENT PRIMARY KEY,
            name        VARCHAR(100) NOT NULL,
            os_type     VARCHAR(50) DEFAULT 'generic',
            description VARCHAR(500) DEFAULT NULL,
            is_builtin  TINYINT(1) DEFAULT 0,
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uk_name (name)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS nm_oid_configs (
            id          INT AUTO_INCREMENT PRIMARY KEY,
            template_id INT DEFAULT NULL,
            node_id     INT DEFAULT NULL,
            metric_name VARCHAR(100) NOT NULL,
            metric_type VARCHAR(50) DEFAULT 'custom',
            oid         VARCHAR(200) NOT NULL,
            oid_total   VARCHAR(200) DEFAULT NULL,
            unit        VARCHAR(20) DEFAULT '%',
            walk        TINYINT(1) DEFAULT 0,
            scale       DECIMAL(12,6) DEFAULT 1.000000,
            description VARCHAR(300) DEFAULT NULL,
            enabled     TINYINT(1) DEFAULT 1,
            sort_order  INT DEFAULT 0,
            INDEX idx_template (template_id),
            INDEX idx_node (node_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    try:
        cur.execute("ALTER TABLE nm_nodes ADD COLUMN oid_template_id INT DEFAULT NULL")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE nm_nodes ADD COLUMN gateway_node_id INT DEFAULT NULL")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE nm_nodes ADD COLUMN poll_interval_health INT DEFAULT NULL")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE nm_nodes ADD COLUMN poll_interval_ifaces INT DEFAULT NULL")
    except Exception:
        pass

    seed_builtin_templates(cur)

def seed_builtin_templates(cur):
    cur.execute("""
        INSERT IGNORE INTO nm_oid_templates (name, os_type, description, is_builtin) VALUES
        ('Generic / HOST-RESOURCES-MIB', 'generic',
         'Universal standard MIBs. CPU via hrProcessorLoad, memory+disk via hrStorageTable. Works for MikroTik, Linux, Cisco and most SNMP devices.', 1),
        ('MikroTik RouterOS', 'mikrotik',
         'MikroTik enterprise OIDs for temperature, fan speed, and voltage sensors (Mikrotik-MIB::mtxrHlTable).', 1),
        ('Linux / NET-SNMP', 'linux',
         'UCD-SNMP MIB OIDs for Linux servers running net-snmp (snmpd).', 1),
        ('Cisco IOS / IOS-XE', 'cisco',
         'Cisco enterprise OIDs for CPU utilization (cpmCPUTotal5minRev) and memory pools.', 1)
    """)

    cur.execute("SELECT id, os_type FROM nm_oid_templates WHERE is_builtin=1")
    tpls = {row[1]: row[0] for row in cur.fetchall()}

    if 'mikrotik' in tpls:
        tid = tpls['mikrotik']
        cur.execute("SELECT COUNT(*) FROM nm_oid_configs WHERE template_id=%s", (tid,))
        if cur.fetchone()[0] == 0:
            for m in [
                ('CPU Temp',   'temperature', '.1.3.6.1.4.1.14988.1.1.3.11.0', None, '°C',  0, 0.1, 'mtxrHlCpuTemperature (tenths of °C)', 10),
                ('Board Temp', 'temperature', '.1.3.6.1.4.1.14988.1.1.3.10.0', None, '°C',  0, 0.1, 'mtxrHlBoardTemperature (tenths of °C)', 20),
                ('Fan Speed',  'custom',      '.1.3.6.1.4.1.14988.1.1.3.14.0', None, 'RPM', 0, 1.0, 'mtxrHlActiveFan (RPM)', 30),
                ('Voltage',    'custom',      '.1.3.6.1.4.1.14988.1.1.3.8.0',  None, 'V',   0, 0.1, 'mtxrHlVoltage (tenths of V)', 40),
            ]:
                cur.execute("""
                    INSERT IGNORE INTO nm_oid_configs
                    (template_id,metric_name,metric_type,oid,oid_total,unit,walk,scale,description,sort_order)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (tid, m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8]))

    if 'linux' in tpls:
        tid = tpls['linux']
        cur.execute("SELECT COUNT(*) FROM nm_oid_configs WHERE template_id=%s", (tid,))
        if cur.fetchone()[0] == 0:
            for m in [
                ('CPU User',    'cpu',    '.1.3.6.1.4.1.2021.11.9.0',  None, '%',  0, 1.0, 'UCD-SNMP ssCpuUser', 10),
                ('CPU System',  'cpu',    '.1.3.6.1.4.1.2021.11.10.0', None, '%',  0, 1.0, 'UCD-SNMP ssCpuSystem', 20),
                ('CPU Idle',    'cpu',    '.1.3.6.1.4.1.2021.11.11.0', None, '%',  0, 1.0, 'UCD-SNMP ssCpuIdle', 30),
                ('RAM Total kB','custom',  '.1.3.6.1.4.1.2021.4.5.0',   None, 'kB', 0, 1.0, 'UCD-SNMP memTotalReal', 40),
                ('RAM Free kB', 'custom',  '.1.3.6.1.4.1.2021.4.6.0',   None, 'kB', 0, 1.0, 'UCD-SNMP memAvailReal', 50),
                ('Disk Used %', 'disk',   '.1.3.6.1.4.1.2021.9.1.9',   None, '%',  1, 1.0, 'UCD-SNMP dskPercent walk (all mounts)', 60),
            ]:
                cur.execute("""
                    INSERT IGNORE INTO nm_oid_configs
                    (template_id,metric_name,metric_type,oid,oid_total,unit,walk,scale,description,sort_order)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (tid, m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8]))

    if 'cisco' in tpls:
        tid = tpls['cisco']
        cur.execute("SELECT COUNT(*) FROM nm_oid_configs WHERE template_id=%s", (tid,))
        if cur.fetchone()[0] == 0:
            for m in [
                ('CPU 5min',      'cpu',    '.1.3.6.1.4.1.9.9.109.1.1.1.1.8', None,                            '%', 1, 1.0, 'cpmCPUTotal5minRev walk', 10),
                ('Memory Used %', 'memory', '.1.3.6.1.4.1.9.9.48.1.1.1.5',    '.1.3.6.1.4.1.9.9.48.1.1.1.6', '%', 0, 1.0, 'ciscoMemoryPool used/(used+free)', 20),
            ]:
                cur.execute("""
                    INSERT IGNORE INTO nm_oid_configs
                    (template_id,metric_name,metric_type,oid,oid_total,unit,walk,scale,description,sort_order)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (tid, m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8]))

def get_nm_setting(cur, key, default=''):
    cur.execute("SELECT setting_val FROM nm_settings WHERE setting_key=%s", (key,))
    row = cur.fetchone()
    return row[0] if row else default

def run_scheduled_discovery(cur):
    """
    Run nm_discovery.py if the schedule says it's time.
    Uses discovery_last_run to decide whether to fire.
    """
    schedule = get_nm_setting(cur, 'discovery_schedule', 'manual')
    if schedule == 'manual':
        return  # user-triggered only

    last_run_str = get_nm_setting(cur, 'discovery_last_run', '')
    now_dt       = datetime.now()
    intervals    = {'daily': 86400, 'weekly': 604800}
    min_gap      = intervals.get(schedule)
    if not min_gap:
        return

    if last_run_str:
        try:
            last_run = datetime.strptime(last_run_str, '%Y-%m-%d %H:%M:%S')
            elapsed  = (now_dt - last_run).total_seconds()
            if elapsed < min_gap:
                return  # not time yet
        except Exception:
            pass  # bad timestamp — proceed with run

    log(f"Scheduled discovery ({schedule}) — running nm_discovery.py")
    py  = sys.executable
    scr = str(BASE_DIR / 'scripts' / 'nm_discovery.py')
    try:
        r = subprocess.run([py, scr], capture_output=True, text=True, timeout=300)
        for line in (r.stdout + r.stderr).splitlines():
            log(f"  [discovery] {line}")
    except Exception as e:
        log(f"  [discovery] run error: {e}")

def prune_old_data(cur, retention_days, db=None):
    # CHUNKED deletes (LIMIT + COMMIT per chunk) so a big retention drop can never hold a
    # single multi-minute row-lock that starves the poller's own INSERTs — that lock storm
    # showed up as "all devices down" on the dashboard. Each chunk is short and committed
    # immediately (autocommit is off); total work is capped per run, the rest finishes next
    # cycle.
    for tbl in ("nm_port_stats", "nm_device_stats"):
        deleted = 0
        while deleted < 200000:                       # per-run safety cap
            cur.execute("DELETE FROM %s WHERE recorded_at < NOW() - INTERVAL %%s DAY LIMIT 5000" % tbl,
                        (retention_days,))
            n = cur.rowcount
            if db is not None:
                db.commit()                           # release locks after every chunk
            deleted += n
            if n < 5000:
                break

# ─── Native alert engine (state-change detection → nm_ai_insights) ────────────
# Turns real state events (interface down, device down/unreachable) into alerts the
# moment they happen — independent of the n8n AI flows. Alerts are kind='alert',
# source='netmon' insights, so they show in the AI Insights panel + dashboard and
# can be picked up by the blast-radius / self-heal flows. Auto-resolves on recovery.
DOWN_STATES = ('down', 'lowerlayerdown', 'notpresent', 'testing')
# An "alerting" state has an open insight that must be resolved on recovery. 'degraded'
# (pings fine but SNMP/telemetry stale) is alerting but NOT down — so the dashboard does
# not paint it red, and it never fights the ping verdict (that fight caused the flap).
ALERT_STATES = DOWN_STATES + ('degraded',)

def ensure_alert_tables(cur):
    cur.execute("""
        CREATE TABLE IF NOT EXISTS nm_alert_state (
            id INT AUTO_INCREMENT PRIMARY KEY,
            entity_type VARCHAR(10) NOT NULL, entity_id INT NOT NULL, node_id INT NOT NULL,
            last_status VARCHAR(20) NOT NULL DEFAULT 'up', open_insight_id BIGINT UNSIGNED NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uk_ent (entity_type, entity_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)

def _alert_raise(cur, node_id, severity, title, body, data):
    cur.execute("""INSERT INTO nm_ai_insights (node_id, kind, severity, title, body, data, source, status)
                   VALUES (%s, 'alert', %s, %s, %s, %s, 'netmon', 'open')""",
                (node_id, severity, title, body, json.dumps(data) if data else None))
    return cur.lastrowid

def _alert_resolve(cur, insight_id):
    if insight_id:
        cur.execute("UPDATE nm_ai_insights SET status='resolved' WHERE id=%s AND status IN ('open','acknowledged')", (insight_id,))

def _state_set(cur, etype, eid, node_id, status, open_id):
    cur.execute("""INSERT INTO nm_alert_state (entity_type, entity_id, node_id, last_status, open_insight_id)
                   VALUES (%s, %s, %s, %s, %s)
                   ON DUPLICATE KEY UPDATE node_id=VALUES(node_id), last_status=VALUES(last_status), open_insight_id=VALUES(open_insight_id)""",
                (etype, eid, node_id, status, open_id))

def detect_alerts(cur):
    ensure_alert_tables(cur)
    cur.execute("SELECT entity_type, entity_id, last_status, open_insight_id FROM nm_alert_state")
    state = {(r[0], r[1]): {'last': r[2], 'open': r[3]} for r in cur.fetchall()}
    cur.execute("SELECT id, display_name FROM nm_nodes")
    names = {r[0]: r[1] for r in cur.fetchall()}
    raised = cleared = 0

    def transition(etype, eid, node_id, is_down, sev, t_down, b_down, data):
        nonlocal raised, cleared
        st = state.get((etype, eid))
        prev_down = bool(st) and (st['last'] in DOWN_STATES)
        if is_down and not prev_down:
            # down-transition OR first-sight-already-down → raise an alert
            iid = _alert_raise(cur, node_id, sev, t_down, b_down, data)
            _state_set(cur, etype, eid, node_id, 'down', iid)
            state[(etype, eid)] = {'last': 'down', 'open': iid}; raised += 1   # keep in-memory in sync so a
        elif (not is_down) and prev_down:                                       # second branch (ping vs SNMP-
            _alert_resolve(cur, st['open']); _state_set(cur, etype, eid, node_id, 'up', None)
            state[(etype, eid)] = {'last': 'up', 'open': None}; cleared += 1     # staleness) can't double-fire
        elif st is None:
            _state_set(cur, etype, eid, node_id, 'up', None)   # first sight & healthy → baseline only
            state[(etype, eid)] = {'last': 'up', 'open': None}

    # Interfaces — latest oper_status per monitored port
    cur.execute("""
        SELECT ps.node_id, ps.port_id, ps.oper_status, i.if_name, i.display_name
        FROM nm_port_stats ps
        JOIN (SELECT node_id, port_id, MAX(recorded_at) mx FROM nm_port_stats GROUP BY node_id, port_id) l
          ON l.node_id=ps.node_id AND l.port_id=ps.port_id AND l.mx=ps.recorded_at
        JOIN nm_interfaces i ON i.id=ps.port_id AND i.show_graph=1
    """)
    for node_id, port_id, oper, ifn, ifdisp in cur.fetchall():
        ifname = ifdisp or ifn or f"port {port_id}"; nname = names.get(node_id, f"Node {node_id}")
        transition('iface', port_id, node_id, (oper or '').lower() in DOWN_STATES, 'warning',
                   f"Interface down: {ifname} on {nname}",
                   f"Interface {ifname} on {nname} went {(oper or 'down').upper()}.",
                   {'event': 'iface_down', 'port_id': port_id, 'interface': ifname, 'oper': (oper or '').lower()})

    # ── ONE combined verdict per node ────────────────────────────────────────
    # CRITICAL: a node has TWO independent reachability signals — ICMP ping and SNMP
    # telemetry freshness. Running them as two separate transitions on the SAME state
    # key made them FIGHT (ping says up → resolve, SNMP-stale says down → raise) and
    # flap a fresh critical every poll. They are now COMBINED into a single tri-state
    # verdict, so a node is exactly one of: up | degraded | down.
    #
    #   • ICMP fails `ping_fail` consecutive  → DOWN   (critical, "Device down")
    #   • pings fine BUT SNMP stale >11 min   → DEGRADED (warning, "SNMP telemetry stale")
    #         → reachable on the network, only the management/telemetry plane is out
    #           (printer asleep, SNMP service stopped, ACL). NOT painted red.
    #   • SNMP stale AND we have no ping at all→ DOWN   (critical, can't confirm life)
    #   • otherwise                            → UP
    # Flap dampening on ICMP (a single WAN/LAN blip is transient, not an outage);
    # recovery is instant.
    ping_fail = max(1, int(get_nm_setting(cur, 'ping_fail_threshold', '3')))
    # How many minutes of SNMP silence before telemetry is "stale". Configurable so an
    # operator can tighten it (e.g. 6 min = ~2 missed polls) for faster service-down alerts.
    stale_min = max(3, int(get_nm_setting(cur, 'snmp_stale_minutes', '11')))

    def node_verdict(node_id, status, sev, title, body, data):
        """status ∈ {up, degraded, down}. Re-firing the SAME status is a no-op (no flap)."""
        nonlocal raised, cleared
        key = ('node', node_id)
        st  = state.get(key)
        prev = st['last'] if st else 'up'
        if status == prev:
            return                                  # unchanged → nothing to do (kills the flap)
        if st and st.get('open'):
            _alert_resolve(cur, st['open'])         # leaving an alerting state → resolve old insight
            if prev in ALERT_STATES: cleared += 1
        if status in ALERT_STATES:
            iid = _alert_raise(cur, node_id, sev, title, body, data)
            _state_set(cur, 'node', node_id, node_id, status, iid)
            state[key] = {'last': status, 'open': iid}; raised += 1
        else:
            _state_set(cur, 'node', node_id, node_id, 'up', None)
            state[key] = {'last': 'up', 'open': None}

    # recent ping samples (newest first), per node
    cur.execute("""
        SELECT node_id, is_up FROM (
            SELECT node_id, is_up,
                   ROW_NUMBER() OVER (PARTITION BY node_id ORDER BY id DESC) rn
            FROM nm_ping_stats
        ) t WHERE rn <= %s ORDER BY node_id, rn
    """, (ping_fail,))
    ping_recent = {}
    for node_id, is_up in cur.fetchall():
        ping_recent.setdefault(node_id, []).append(int(is_up))

    # SNMP staleness = minutes since the NEWEST telemetry of ANY kind for the node —
    # interface counters (nm_port_stats) OR health metrics (nm_device_stats: CPU/RAM/
    # uptime/OIDs). Reading BOTH is the fix for the "service/agent down but host still
    # pings" gap: a node polled only for health (no monitored interfaces) used to have
    # age=None forever and could NEVER go stale. Now, when its SNMP agent stops
    # answering while ICMP stays up, device_stats freezes → age climbs → DEGRADED fires.
    snmp_age = {}
    cur.execute("""SELECT id FROM nm_nodes WHERE COALESCE(monitor_type,'snmp')='snmp'
                   AND snmp_community IS NOT NULL AND snmp_community<>''""")
    for (node_id,) in cur.fetchall():
        cur.execute("SELECT MAX(recorded_at) FROM nm_port_stats WHERE node_id=%s", (node_id,))
        p = cur.fetchone()[0]
        cur.execute("SELECT MAX(recorded_at) FROM nm_device_stats WHERE node_id=%s", (node_id,))
        d = cur.fetchone()[0]
        newest = max([x for x in (p, d) if x is not None], default=None)
        if newest is None:
            snmp_age[node_id] = None                       # never had ANY SNMP data
        else:
            cur.execute("SELECT TIMESTAMPDIFF(MINUTE, %s, NOW())", (newest,))
            snmp_age[node_id] = cur.fetchone()[0]

    for node_id in (set(ping_recent) | set(snmp_age)):
        nname    = names.get(node_id, f"Node {node_id}")
        samples  = ping_recent.get(node_id, [])
        has_ping = len(samples) > 0
        icmp_down = has_ping and len(samples) >= ping_fail and all(v == 0 for v in samples)
        age       = snmp_age.get(node_id)
        is_snmp   = node_id in snmp_age
        snmp_stale = is_snmp and (age is not None) and age > stale_min
        # FRESH SNMP telemetry (data within ~11 min) is DEFINITIVE proof the device is
        # alive AND reachable on its management plane. A node answering SNMP every poll is
        # NOT down no matter how its ICMP behaves — many devices (printers, APs, firewalls)
        # legitimately drop or deprioritize ICMP while serving SNMP perfectly. So fresh SNMP
        # OVERRIDES an ICMP-down verdict; ICMP can only declare a node down when there is no
        # fresh SNMP to independently confirm life. (Killed the HP-PRT-8020 down↔up flap.)
        snmp_fresh = is_snmp and (age is not None) and age <= stale_min

        if icmp_down and snmp_fresh:
            # Drops pings but SNMP is current → device is alive and managed → NOT down.
            # Don't paint it red over ICMP flapping; ping loss stays visible in latency stats.
            node_verdict(node_id, 'up', None, None, None, None)
        elif icmp_down:
            extra = " SNMP is also unreachable." if snmp_stale else ""
            node_verdict(node_id, 'down', 'critical',
                f"Device down: {nname}",
                f"{nname} failed {ping_fail} consecutive ICMP checks (no reply).{extra}",
                {'event': 'device_down', 'method': 'ping', 'consecutive_fails': ping_fail})
        elif snmp_stale and not has_ping:
            # SNMP node we cannot ping at all → stale SNMP is the only life signal → down
            node_verdict(node_id, 'down', 'critical',
                f"Device unreachable: {nname}",
                f"No SNMP data from {nname} for ~{age} min and no ICMP data — device down or unreachable.",
                {'event': 'device_unreachable', 'method': 'snmp', 'stale_minutes': age})
        elif snmp_stale:
            # pings fine but telemetry stale → DEGRADED, NOT down
            node_verdict(node_id, 'degraded', 'warning',
                f"SNMP telemetry stale: {nname}",
                f"{nname} still answers ICMP ping (reachable) but its SNMP agent has returned "
                f"no data for ~{age} min — telemetry is stale (printer asleep, SNMP service "
                f"stopped, or an ACL is blocking us). The device itself is NOT down.",
                {'event': 'snmp_stale', 'method': 'snmp', 'stale_minutes': age, 'icmp': 'up'})
        elif is_snmp and age is None:
            continue   # never had SNMP data — don't alert on a node we've never reached
        else:
            node_verdict(node_id, 'up', None, None, None, None)

    log(f"Alert engine: {raised} raised, {cleared} cleared")

# ─── Main poll logic ──────────────────────────────────────────────────────────
def poll(only_node=None):
    t_start = time.time()
    log("Starting poll cycle" + (f" (single node {only_node})" if only_node else ""))

    # LibreNMS is now optional — used only as fallback for SNMP-unconfigured nodes
    lnms_url, token = load_lnms_cfg()
    if lnms_url:
        log("LibreNMS config found — available as fallback")
    else:
        log("LibreNMS config not found or disabled — running fully independent")

    db  = get_db()
    cur = db.cursor()

    ensure_tables(cur)
    db.commit()

    # On-demand single-node polls skip the heavy housekeeping (prune/discovery) to stay fast.
    if not only_node:
        retention_days = int(get_nm_setting(cur, 'retention_days', '30'))
        prune_old_data(cur, retention_days, db)
        run_scheduled_discovery(cur)

    # Load nodes with SNMP credentials
    _node_sql = """
        SELECT n.id                              node_id,
               n.lnms_device_id                 dev_id,
               COALESCE(n.ip_address, '')        ip_address,
               COALESCE(n.snmp_community, '')    snmp_community,
               COALESCE(n.snmp_version, 'v2c')  snmp_version,
               n.display_name
        FROM nm_nodes n
        WHERE COALESCE(n.monitor_type, 'snmp') <> 'ping'
    """
    if only_node:
        cur.execute(_node_sql + " AND n.id=%s ORDER BY n.id", (int(only_node),))
    else:
        cur.execute(_node_sql + " ORDER BY n.id")
    nodes = cur.fetchall()

    cur.execute("SELECT DATE_FORMAT(NOW(),'%Y-%m-%d %H:%i:%S') t")
    now        = cur.fetchone()[0]
    nodes_done = 0
    ports_done = 0
    errors     = 0

    for (node_id, dev_id, node_ip, snmp_comm, snmp_ver, display_name) in nodes:
        log(f"  Node {node_id} — {display_name} ({node_ip})")

        if snmp_comm and node_ip:
            # ── Full direct SNMP path ─────────────────────────────────────────
            ver = snmp_ver or 'v2c'

            # ── Reachability GATE: ping first. Record a ping sample (so the alert engine
            #    flags SNMP nodes DOWN fast via the ping path, not only the 11-min SNMP
            #    staleness). If unreachable, SKIP the SNMP polling — a dead node otherwise
            #    stalls the whole poller minutes on per-OID timeouts (→ overlapping cron
            #    runs → deadlocks → detect_alerts never ran → downs were never raised).
            up, lat, loss = _reachable(node_ip)
            # ICMP may be FILTERED even on a perfectly-alive host (Windows Firewall blocks
            # echo by default). Before declaring down, do a FAST single-OID SNMP liveness
            # probe (sysUpTime, short timeout). If SNMP answers, the node IS up — it just
            # doesn't speak ICMP — so we must NOT flag it down and must still poll it.
            snmp_alive = False
            if not up:
                if snmp_get_val(node_ip, snmp_comm, ver, '1.3.6.1.2.1.1.3.0', timeout=2) is not None:
                    snmp_alive = True
                    log(f"    ICMP filtered ({loss:.0f}% loss) but SNMP responds — host is UP")
            alive = up or snmp_alive
            try:
                # is_up reflects the NODE being up by ANY method (so the alert engine's ping
                # branch doesn't false-down an ICMP-filtered-but-SNMP-alive host); loss still
                # records the real ICMP loss for latency views.
                cur.execute("INSERT INTO nm_ping_stats (node_id,is_up,latency_ms,packet_loss,recorded_at) VALUES (%s,%s,%s,%s,%s)",
                            (node_id, 1 if alive else 0, lat, loss, now))
                db.commit()
            except Exception as e:
                log(f"    ping-sample error: {e}")
            if not alive:
                log(f"    UNREACHABLE (ICMP {loss:.0f}% loss + SNMP timeout) — skipping SNMP; marked for down-detection")
                continue

            # Auto-discover interfaces if we have none with if_index set
            cur.execute("""
                SELECT COUNT(*) FROM nm_interfaces
                WHERE node_id=%s AND if_index IS NOT NULL
            """, (node_id,))
            known_ifaces = cur.fetchone()[0]

            if known_ifaces == 0:
                added, updated = discover_interfaces(cur, node_id, node_ip, snmp_comm, ver)
                if added or updated:
                    log(f"    Discovery: +{added} new, {updated} updated interfaces")
                    db.commit()

            # System info (sysName/descr/location/objectID → nm_nodes)
            try:
                poll_system_info(cur, node_id, node_ip, snmp_comm, ver)
            except Exception as e:
                log(f"    SysInfo error: {e}")

            # Interface IPs (ipAddrTable → nm_interfaces.if_ip_address) + self-heal the
            # monitored interface against Windows ifIndex drift (follow the management IP).
            try:
                _, _ipmap = poll_interface_ips(cur, node_id, node_ip, snmp_comm, ver)
                reconcile_primary_iface(cur, node_id, node_ip, _ipmap)
            except Exception as e:
                log(f"    Interface-IP error: {e}")

            # Health metrics (CPU, memory, disk, uptime, custom OIDs)
            n_snmp = poll_snmp_health(cur, node_id, node_ip, snmp_comm, ver, now)
            log(f"    Health: {n_snmp} metric(s)")

            # Interface traffic (direct SNMP counters)
            n_ports = poll_interfaces_direct(cur, node_id, node_ip, snmp_comm, ver, now)
            ports_done += n_ports

        elif lnms_url and dev_id:
            # ── LibreNMS fallback (node has no SNMP config) ───────────────────
            log(f"    No SNMP config — using LibreNMS fallback (device {dev_id})")

            # Port stats from LibreNMS
            cur.execute("""
                SELECT id, lnms_port_id FROM nm_interfaces
                WHERE node_id=%s AND lnms_port_id IS NOT NULL
            """, (node_id,))
            port_map = {row[1]: row[0] for row in cur.fetchall()}  # lnms_port_id -> nm_iface_id

            if port_map:
                data = lnms_get(lnms_url, token,
                                f"/api/v0/devices/{dev_id}/ports",
                                params={'columns': 'port_id,ifSpeed,ifOperStatus,ifAdminStatus,'
                                                   'ifInOctets_rate,ifOutOctets_rate'})
                if data and 'ports' in data:
                    for p in data['ports']:
                        lpid = int(p.get('port_id', 0))
                        if lpid not in port_map:
                            continue
                        iface_id = port_map[lpid]
                        speed    = int(p.get('ifSpeed', 0) or 0)
                        in_rate  = int(p.get('ifInOctets_rate', 0) or 0)
                        out_rate = int(p.get('ifOutOctets_rate', 0) or 0)
                        oper     = (p.get('ifOperStatus') or 'unknown').lower()
                        in_util  = round(in_rate  * 8 / speed * 100, 2) if speed > 0 else None
                        out_util = round(out_rate * 8 / speed * 100, 2) if speed > 0 else None
                        cur.execute("""
                            INSERT INTO nm_port_stats
                                (node_id, port_id, recorded_at, in_rate, out_rate,
                                 in_util, out_util, oper_status, if_speed)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """, (node_id, iface_id, now, in_rate, out_rate,
                              in_util, out_util, oper, speed))
                        ports_done += 1

            # Health from LibreNMS API
            cpu_data = lnms_get(lnms_url, token, f"/api/v0/devices/{dev_id}/health/processor")
            if cpu_data and cpu_data.get('status') == 'ok' and cpu_data.get('processor'):
                usages = [float(p.get('processor_usage', 0) or 0) for p in cpu_data['processor']]
                if usages:
                    avg_cpu = round(sum(usages) / len(usages), 2)
                    cur.execute("""
                        INSERT INTO nm_device_stats (node_id, recorded_at, metric_type, metric_key, value)
                        VALUES (%s, %s, 'cpu', 'avg', %s)
                    """, (node_id, now, avg_cpu))
                    for p in cpu_data['processor']:
                        cur.execute("""
                            INSERT INTO nm_device_stats (node_id, recorded_at, metric_type, metric_key, value)
                            VALUES (%s, %s, 'cpu', %s, %s)
                        """, (node_id, now, str(p.get('processor_id', '0')),
                              float(p.get('processor_usage', 0) or 0)))

            mem_data = lnms_get(lnms_url, token, f"/api/v0/devices/{dev_id}/health/mempool")
            if mem_data and mem_data.get('status') == 'ok' and mem_data.get('mempool'):
                for m in mem_data['mempool']:
                    key     = str(m.get('mempool_descr', m.get('mempool_index', '0')))[:200]
                    perc    = float(m.get('mempool_perc', 0) or 0)
                    raw_val = int(m['mempool_used']) if m.get('mempool_used') is not None else None
                    cur.execute("""
                        INSERT INTO nm_device_stats (node_id, recorded_at, metric_type, metric_key, value, raw_value)
                        VALUES (%s, %s, 'memory', %s, %s, %s)
                    """, (node_id, now, key, perc, raw_val))

            dev_data = lnms_get(lnms_url, token, f"/api/v0/devices/{dev_id}")
            if dev_data and dev_data.get('devices'):
                uptime = dev_data['devices'][0].get('uptime', 0) or 0
                cur.execute("""
                    INSERT INTO nm_device_stats (node_id, recorded_at, metric_type, metric_key, value)
                    VALUES (%s, %s, 'uptime', 'seconds', %s)
                """, (node_id, now, float(uptime)))
        else:
            log(f"    Skipping — no SNMP config and no LibreNMS fallback available")
            errors += 1

        try:
            db.commit()
        except Exception as e:                       # a deadlock here must NOT crash the run
            log(f"    commit error (node {node_id}): {e}")
            try: db.rollback()
            except Exception: pass
        nodes_done += 1

    # ── Native alert engine: detect interface/device down→up changes → insights ─
    # Retry on deadlock — the per-host (win/linux/gpu) crons write the same tables, so a
    # transient 1213 must not skip down-detection for a whole cycle.
    for _attempt in range(3):
        try:
            detect_alerts(cur); db.commit(); break
        except Exception as e:
            try: db.rollback()
            except Exception: pass
            if ('Deadlock' in str(e) or '1213' in str(e)) and _attempt < 2:
                log(f"  alert engine deadlock — retry {_attempt+1}/2"); time.sleep(1.5); continue
            log(f"  alert engine error: {e}"); break

    # ── Log this run ─────────────────────────────────────────────────────────
    elapsed_ms = int((time.time() - t_start) * 1000)
    cur.execute("""
        INSERT INTO nm_poller_log (ran_at, duration_ms, nodes_polled, ports_polled, errors, status)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (now, elapsed_ms, nodes_done, ports_done, errors, 'ok' if errors == 0 else 'warn'))
    db.commit()
    cur.close()
    db.close()
    log(f"Poll complete — {nodes_done} nodes, {ports_done} port samples, {errors} errors, {elapsed_ms}ms")

if __name__ == '__main__':
    # Optional single-node mode: `nm_poller.py --node <id>` (used by the dashboard "Poll now"
    # button to refresh just one device on demand). No arg = full cycle (the */2 cron).
    _only = None
    _av = sys.argv[1:]
    for i, a in enumerate(_av):
        if a == '--node' and i + 1 < len(_av):
            try: _only = int(_av[i + 1])
            except ValueError: _only = None
        elif a.startswith('--node='):
            try: _only = int(a.split('=', 1)[1])
            except ValueError: _only = None
    try:
        poll(only_node=_only)
    except Exception as e:
        log(f"FATAL: {e}")
        raise
