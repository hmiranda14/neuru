#!/usr/bin/env python3
"""
NetMon ICMP ping poller.
Checks every node with monitor_type='ping' using the system `ping`, and records
up/down + average latency + packet loss into nm_ping_stats. Lightweight — safe to
run frequently (e.g. every minute) on its own cron, separate from the SNMP poller.
"""
import sys
import re
import time
import subprocess
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mysql.connector            # noqa: E402
from nm_db_config import DB       # noqa: E402


def log(msg):
    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}", flush=True)


def ping_host(ip, count=5, timeout=2):
    """Probe a host once. Return (is_up: bool, latency_ms: float|None, loss_pct: float).

    Sends `count` packets, each waiting up to `timeout` s for a reply. `is_up` is
    True if *any* packet came back (loss < 100%). count/timeout are deliberately
    generous: a 1 s / 3-packet burst over the WAN (8.8.8.8, 1.1.1.1) sporadically
    loses every packet to jitter or ICMP rate-limiting, which read as a false DOWN.
    """
    try:
        r = subprocess.run(
            ['/usr/bin/ping', '-c', str(count), '-W', str(timeout), '-n', ip],
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
    the confirm burst also fails 100% do we report down. This is the source-level
    guard against transient false-downs (the alert engine adds a second, debounce
    layer on top)."""
    up, avg, loss = ping_host(ip)
    if up:
        return up, avg, loss
    time.sleep(1)
    up2, avg2, loss2 = ping_host(ip)
    if up2:
        return up2, avg2, loss2          # transient — first burst was a blip
    return False, None, 100.0            # confirmed unreachable this cycle


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


def main():
    db = mysql.connector.connect(**DB, autocommit=False)
    cur = db.cursor()
    ensure_table(cur)
    db.commit()

    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cur.execute("SELECT id, display_name, ip_address FROM nm_nodes "
                "WHERE monitor_type='ping' AND ip_address IS NOT NULL AND ip_address <> ''")
    nodes = cur.fetchall()
    log(f"Ping poll: {len(nodes)} node(s)")

    done = 0
    for (nid, name, ip) in nodes:
        up, avg, loss = probe(ip)
        cur.execute(
            "INSERT INTO nm_ping_stats (node_id, recorded_at, is_up, latency_ms, packet_loss) "
            "VALUES (%s, %s, %s, %s, %s)",
            (nid, now, 1 if up else 0, avg, loss)
        )
        done += 1
        log(f"  {name} ({ip}): {'UP' if up else 'DOWN'} "
            f"{('%.1fms' % avg) if avg is not None else '—'} loss={loss}%")

    db.commit()
    cur.close()
    db.close()
    log(f"Done: {done} node(s) pinged")


if __name__ == '__main__':
    main()
