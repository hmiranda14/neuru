#!/usr/bin/env python3
"""
NEURU syslog server — industrial-grade ingest daemon.

Listens for syslog on UDP (and optionally TCP) and writes parsed records into
the `nm_syslog` table, so the portal works directly off the local database
(Graylog becomes optional). Designed to run continuously and survive load:

  • non-blocking receive threads feed a BOUNDED queue (back-pressure, never OOM)
  • a single writer thread drains the queue in batches (executemany + commit)
  • automatic DB reconnect with backoff; the listeners keep buffering meanwhile
  • tolerant parser: RFC5424, RFC3164, and plain lines all accepted
  • periodic retention pruning + a heartbeat line with throughput counters
  • clean shutdown on SIGTERM/SIGINT (flushes the queue first)

Run (foreground / under a supervisor / container entrypoint):
    /opt/netmon-venv/bin/python3 /var/www/html/netmon/scripts/nm_syslog.py
Background (no systemd):
    nohup /opt/netmon-venv/bin/python3 .../nm_syslog.py >> ~/netmon-logs/nm_syslog.log 2>&1 &

Port/retention come from nm_settings (syslog_port, syslog_retention_days,
syslog_tcp_enabled); env vars NM_SYSLOG_PORT / NM_SYSLOG_BIND override.
"""
import os
import re
import sys
import time
import signal
import socket
import threading
import queue
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mysql.connector                # noqa: E402
from nm_db_config import DB           # noqa: E402

# ── Tunables ──────────────────────────────────────────────────────────────────
QUEUE_MAX     = 50000      # bounded backlog (records); excess is dropped + counted
BATCH_MAX     = 500        # rows per INSERT
FLUSH_SECS    = 2.0        # max time a record waits before being written
PRUNE_SECS    = 3600       # retention sweep interval
HEARTBEAT_SECS = 300       # stats line cadence
UDP_BUF       = 16384

_stop = threading.Event()
_q: "queue.Queue[tuple]" = queue.Queue(maxsize=QUEUE_MAX)
_stats = {"recv": 0, "written": 0, "dropped": 0, "parse_err": 0}
_stats_lock = threading.Lock()


def log(msg):
    print(f"[{datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S} UTC] {msg}", flush=True)


def bump(k, n=1):
    with _stats_lock:
        _stats[k] += n


# ── Settings (best-effort; safe defaults) ─────────────────────────────────────
def load_settings():
    port = int(os.environ.get("NM_SYSLOG_PORT", "0") or 0)
    bind = os.environ.get("NM_SYSLOG_BIND", "0.0.0.0")
    retention = 30
    tcp = True
    try:
        db = mysql.connector.connect(**DB, autocommit=True)
        cur = db.cursor()
        cur.execute("SELECT setting_key, setting_val FROM nm_settings WHERE setting_key IN "
                    "('syslog_port','syslog_retention_days','syslog_tcp_enabled')")
        for k, v in cur.fetchall():
            if k == 'syslog_port' and not port and str(v).isdigit():
                port = int(v)
            elif k == 'syslog_retention_days' and str(v).isdigit():
                retention = max(1, int(v))
            elif k == 'syslog_tcp_enabled':
                tcp = (str(v) != '0')
        cur.close(); db.close()
    except Exception as e:
        log(f"settings: using defaults ({e})")
    if not port:
        port = 514
    return bind, port, retention, tcp


# ── Table ─────────────────────────────────────────────────────────────────────
def ensure_table():
    db = mysql.connector.connect(**DB, autocommit=True)
    cur = db.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS nm_syslog (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            received_at DATETIME NOT NULL,
            host_ip VARCHAR(45) NOT NULL,
            hostname VARCHAR(128) NOT NULL DEFAULT '',
            facility TINYINT NULL,
            severity TINYINT NULL,
            tag VARCHAR(64) NOT NULL DEFAULT '',
            message TEXT,
            INDEX idx_time (received_at),
            INDEX idx_host_time (host_ip, received_at),
            INDEX idx_sev_time (severity, received_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    cur.close(); db.close()


# ── Parser (RFC5424 / RFC3164 / plain) ────────────────────────────────────────
_PRI   = re.compile(r'^<(\d{1,3})>(.*)$', re.S)
_R5424 = re.compile(r'^1\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$', re.S)
_R3164 = re.compile(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)\s+(.*)$', re.S)
_TAG   = re.compile(r'^([\w\-/.]{1,48})(?:\[\d+\])?:\s*(.*)$', re.S)


def parse(raw: bytes, src_ip: str):
    facility = severity = None
    host = tag = ''
    msg = raw.decode('utf-8', 'replace').strip('\x00').rstrip('\r\n')
    m = _PRI.match(msg)
    rest = msg
    if m:
        pri = int(m.group(1))
        if pri <= 191:
            facility, severity = pri >> 3, pri & 7
        rest = m.group(2)
    m5 = _R5424.match(rest)
    if m5:
        host = '' if m5.group(2) == '-' else m5.group(2)
        tag = '' if m5.group(3) == '-' else m5.group(3)
        body = m5.group(6)
        body = re.sub(r'^(?:\[.*?\]|-)\s*', '', body, count=1)   # drop structured-data / nil
        msg = body
    else:
        m3 = _R3164.match(rest)
        if m3:
            host = m3.group(1)
            mt = _TAG.match(m3.group(2))
            if mt:
                tag, msg = mt.group(1), mt.group(2)
            else:
                msg = m3.group(2)
        else:
            msg = rest
    if not host:
        host = src_ip
    return (host[:128], facility, severity, tag[:64], msg[:8000])


# ── Receivers ─────────────────────────────────────────────────────────────────
def udp_listener(bind, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind, port))
    s.settimeout(1.0)
    log(f"UDP listening on {bind}:{port}")
    while not _stop.is_set():
        try:
            data, addr = s.recvfrom(UDP_BUF)
        except socket.timeout:
            continue
        except OSError:
            break
        enqueue(data, addr[0])
    s.close()


def tcp_listener(bind, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind, port))
    s.listen(64)
    s.settimeout(1.0)
    log(f"TCP listening on {bind}:{port}")
    while not _stop.is_set():
        try:
            conn, addr = s.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=tcp_client, args=(conn, addr[0]), daemon=True).start()
    s.close()


def tcp_client(conn, ip):
    conn.settimeout(30)
    buf = b''
    try:
        while not _stop.is_set():
            chunk = conn.recv(UDP_BUF)
            if not chunk:
                break
            buf += chunk
            while b'\n' in buf:
                line, buf = buf.split(b'\n', 1)
                if line.strip():
                    enqueue(line, ip)
    except Exception:
        pass
    finally:
        conn.close()


def enqueue(data, ip):
    bump("recv")
    rec = (datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), ip, data)
    try:
        _q.put_nowait(rec)
    except queue.Full:
        bump("dropped")


# ── Writer (batched, reconnecting) ────────────────────────────────────────────
def writer(retention_days):
    db = cur = None
    last_prune = 0.0
    pending = []        # a parsed batch awaiting a successful commit (retried on reconnect)
    INSERT = ("INSERT INTO nm_syslog (received_at,host_ip,hostname,facility,severity,tag,message) "
              "VALUES (%s,%s,%s,%s,%s,%s,%s)")
    while not (_stop.is_set() and _q.empty() and not pending):
        if db is None:
            try:
                db = mysql.connector.connect(**DB, autocommit=False)
                cur = db.cursor()
                log("DB connected")
            except Exception as e:
                log(f"DB connect failed, retrying in 5s: {e}")
                time.sleep(5)
                continue
        # retry the failed batch first; otherwise gather a fresh one
        if pending:
            batch = pending
        else:
            batch = []
            deadline = time.monotonic() + FLUSH_SECS
            while len(batch) < BATCH_MAX and time.monotonic() < deadline:
                try:
                    ts, ip, data = _q.get(timeout=0.3)
                except queue.Empty:
                    if _stop.is_set():
                        break
                    continue
                try:
                    host, fac, sev, tag, msg = parse(data, ip)
                    batch.append((ts, ip, host, fac, sev, tag, msg))
                except Exception:
                    bump("parse_err")
        if batch:
            try:
                cur.executemany(INSERT, batch)
                db.commit()
                bump("written", len(batch))
                pending = []
            except Exception as e:
                log(f"insert failed ({e}); will reconnect and retry batch")
                pending = batch
                try:
                    db.close()
                except Exception:
                    pass
                db = cur = None
                time.sleep(2)
                continue
        # retention sweep
        now = time.monotonic()
        if now - last_prune > PRUNE_SECS:
            last_prune = now
            try:
                cur.execute(f"DELETE FROM nm_syslog WHERE received_at < (UTC_TIMESTAMP() - INTERVAL {int(retention_days)} DAY)")
                db.commit()
            except Exception as e:
                log(f"prune failed: {e}")
    if db:
        try:
            db.close()
        except Exception:
            pass


def heartbeat():
    while not _stop.wait(HEARTBEAT_SECS):
        with _stats_lock:
            s = dict(_stats)
        log(f"stats: recv={s['recv']} written={s['written']} dropped={s['dropped']} "
            f"parse_err={s['parse_err']} queue={_q.qsize()}")


def _shutdown(signum, _frame):
    log(f"signal {signum} — draining queue and shutting down")
    _stop.set()


def main():
    bind, port, retention, tcp = load_settings()
    log(f"NEURU syslog server starting (bind={bind} port={port} tcp={tcp} retention={retention}d)")
    try:
        ensure_table()
    except Exception as e:
        log(f"FATAL: cannot ensure nm_syslog table: {e}")
        sys.exit(1)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    threads = [
        threading.Thread(target=writer, args=(retention,), daemon=True),
        threading.Thread(target=heartbeat, daemon=True),
    ]
    try:
        threads.append(threading.Thread(target=udp_listener, args=(bind, port), daemon=True))
    except Exception as e:
        log(f"UDP bind error: {e}")
    if tcp:
        threads.append(threading.Thread(target=tcp_listener, args=(bind, port), daemon=True))
    for t in threads:
        t.start()
    # surface a bind failure fast
    time.sleep(0.5)
    try:
        while not _stop.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        _stop.set()
    log("waiting for writer to flush…")
    time.sleep(FLUSH_SECS + 1)
    with _stats_lock:
        log(f"stopped. totals recv={_stats['recv']} written={_stats['written']} dropped={_stats['dropped']}")


if __name__ == "__main__":
    main()
