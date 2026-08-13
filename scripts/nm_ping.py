#!/usr/bin/env python3
"""
NEURU ICMP ping poller — CONCURRENT worker-pool edition.

Checks every node with monitor_type='ping' using the system `ping` and records
up/down + average latency + packet loss into nm_ping_stats.

Scales to thousands of nodes: instead of pinging nodes one-at-a-time (sequential,
~4 s/node → hours for 2 000 nodes), it fans the probes out across a thread pool.
`ping` is an external process, so each probe releases the GIL → true parallelism.
Workers only GATHER (subprocess); the main thread does a single BATCH insert
(decoupled pipeline — the DB cursor is never touched from a worker thread).
Nodes in maintenance are skipped (no data gathered). Runs safely every minute.
"""
import sys
import re
import time
import subprocess
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mysql.connector            # noqa: E402
from nm_db_config import DB       # noqa: E402
from nm_maint import maint_clause # noqa: E402  # skip nodes in maintenance (no data gathered)


def log(msg):
    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}", flush=True)


def ping_host(ip, count=5, timeout=2):
    """Probe a host once. Return (is_up: bool, latency_ms: float|None, loss_pct: float).

    Sends `count` packets at a fast 0.2 s interval (min allowed for non-root), each
    waiting up to `timeout` s for a reply. `is_up` = any packet returned. The multi-
    packet burst is the source-level guard against a single-packet false DOWN.
    """
    try:
        r = subprocess.run(
            ['/usr/bin/ping', '-c', str(count), '-i', '0.2', '-W', str(timeout), '-n', ip],
            capture_output=True, text=True, timeout=count * timeout + 8
        )
        out = r.stdout
        m_loss = re.search(r'(\d+(?:\.\d+)?)%\s*packet loss', out)
        loss = float(m_loss.group(1)) if m_loss else 100.0
        m_rtt = re.search(r'=\s*[\d.]+/([\d.]+)/', out)   # min/avg/max → avg
        avg = float(m_rtt.group(1)) if m_rtt else None
        return (loss < 100.0), avg, loss
    except Exception as e:
        log(f"  ping error {ip}: {e}")
        return False, None, 100.0


def probe(ip):
    """Probe with a confirmation retry: never record DOWN on a single bad burst.

    If the first burst loses everything, wait briefly and try once more. Only if
    the confirm burst also fails 100% do we report down (source-level false-down
    guard; the alert engine adds a second debounce layer on top). Runs inside a
    worker thread — its sleep/retry never blocks the other nodes."""
    up, avg, loss = ping_host(ip)
    if up:
        return up, avg, loss
    time.sleep(1)
    up2, avg2, loss2 = ping_host(ip)
    if up2:
        return up2, avg2, loss2          # transient — first burst was a blip
    return False, None, 100.0            # confirmed unreachable this cycle


def probe_node(node):
    """Worker unit of work: (id, name, ip) → (id, name, ip, up, avg, loss). Pure gather."""
    nid, name, ip = node
    up, avg, loss = probe(ip)
    return (nid, name, ip, up, avg, loss)


def ensure_table(cur):
    cur.execute("""
        CREATE TABLE IF NOT EXISTS nm_ping_stats (
            id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            node_id INT NOT NULL,
            recorded_at DATETIME NOT NULL,
            is_up TINYINT(1) NOT NULL DEFAULT 0,
            latency_ms DECIMAL(8,2) DEFAULT NULL,
            packet_loss DECIMAL(5,2) DEFAULT NULL,
            INDEX idx_node_time (node_id, recorded_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """)


def worker_count(cur, n_nodes):
    """Concurrency = operator override (nm_settings.poll_workers) or auto: scales with the
    node count — min(100, max(10, nodes/4)) — so a few nodes use a few threads and 2 000
    nodes use 100. Never more workers than nodes."""
    if n_nodes <= 0:
        return 1
    try:
        cur.execute("SELECT setting_val FROM nm_settings WHERE setting_key='poll_workers' LIMIT 1")
        row = cur.fetchone()
        if row and str(row[0]).strip().isdigit() and int(row[0]) > 0:
            return min(int(row[0]), n_nodes)
    except Exception:
        pass
    return min(100, max(10, n_nodes // 4), n_nodes)


def main():
    db = mysql.connector.connect(**DB, autocommit=False)
    cur = db.cursor()

    from nm_job_gate import should_run
    if not should_run(cur, db, 'nm_ping'):
        cur.close(); db.close(); return
    ensure_table(cur)
    db.commit()

    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cur.execute("SELECT id, display_name, ip_address FROM nm_nodes "
                "WHERE monitor_type='ping' AND ip_address IS NOT NULL AND ip_address <> ''"
                + maint_clause(cur))
    nodes = cur.fetchall()
    nw = worker_count(cur, len(nodes))
    log(f"Ping poll: {len(nodes)} node(s) · {nw} workers")

    t0 = time.time()
    results = []
    if nodes:
        # Fan out: each probe runs in its own thread (ping = external process → real parallelism).
        with ThreadPoolExecutor(max_workers=nw) as ex:
            results = list(ex.map(probe_node, nodes))

    # Decoupled write: ONE batch insert from the main thread (workers never touch the cursor).
    rows = [(nid, now, 1 if up else 0, avg, loss) for (nid, name, ip, up, avg, loss) in results]
    if rows:
        cur.executemany(
            "INSERT INTO nm_ping_stats (node_id, recorded_at, is_up, latency_ms, packet_loss) "
            "VALUES (%s, %s, %s, %s, %s)", rows)
    db.commit()

    up_ct = sum(1 for r in results if r[3])
    for (nid, name, ip, up, avg, loss) in results:
        if not up:                              # log DOWN nodes (up ones are just noise at scale)
            log(f"  DOWN {name} ({ip}) loss={loss}%")
    cur.close()
    db.close()
    log(f"Done: {len(results)} node(s) in {time.time()-t0:.1f}s · {up_ct} up / {len(results)-up_ct} down")


if __name__ == '__main__':
    main()
