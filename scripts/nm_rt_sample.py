#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
# NEURU — Realtime interface sampler for the Realtime Traffic Viewer.
# Reads live SNMP counters (HC octets + errors + discards) for a batch of
# interfaces IN PARALLEL and prints the raw counters as JSON. The PHP endpoint
# computes bps / err-per-s / disc-per-s from consecutive samples (delta / dt),
# so the viewer shows TRUE realtime traffic (not the 2-min poller data).
#
# stdin: {"targets":[{"pid":1,"ip":"10.0.0.1","comm":"public","ver":"v2c","idx":2}, ...]}
# stdout:{"1":{"in":<oct>,"out":<oct>,"ie":<inErr>,"oe":<outErr>,"id":<inDisc>,"od":<outDisc>,"ok":1}, ...}
# Only SNMP v1/v2c (v3 needs auth params → skipped; the endpoint falls back to DB).
# ─────────────────────────────────────────────────────────────────────────────
import sys, json, subprocess
from concurrent.futures import ThreadPoolExecutor

# ifHCInOctets, ifHCOutOctets, ifInErrors, ifOutErrors, ifInDiscards, ifOutDiscards
OIDS = ["1.3.6.1.2.1.31.1.1.1.6.", "1.3.6.1.2.1.31.1.1.1.10.",
        "1.3.6.1.2.1.2.2.1.14.",  "1.3.6.1.2.1.2.2.1.20.",
        "1.3.6.1.2.1.2.2.1.13.",  "1.3.6.1.2.1.2.2.1.19."]
KEYS = ["in", "out", "ie", "oe", "id", "od"]

def sample(t):
    pid = t.get("pid")
    ip  = str(t.get("ip", "")); comm = str(t.get("comm", "")); idx = int(t.get("idx", 0))
    ver = "1" if str(t.get("ver", "v2c")) == "v1" else "2c"
    if not ip or not comm or idx <= 0:
        return pid, {"ok": 0}
    oids = [o + str(idx) for o in OIDS]
    try:
        r = subprocess.run(["snmpget", "-v" + ver, "-c", comm, "-t", "1", "-r", "0", "-OqvU", ip] + oids,
                           capture_output=True, text=True, timeout=3)
        if r.returncode != 0:
            return pid, {"ok": 0}
        vals = [ln.strip() for ln in r.stdout.splitlines() if ln.strip() != ""]
        if len(vals) < 6:
            return pid, {"ok": 0}
        out = {"ok": 1}
        for k, v in zip(KEYS, vals):
            # snmpget -Oqv may still emit e.g. "Counter64: N" on some builds; grab the last int token
            tok = v.replace("Counter64:", "").replace("Counter32:", "").strip().split()
            try: out[k] = int(tok[-1])
            except Exception: out[k] = 0
        return pid, out
    except Exception:
        return pid, {"ok": 0}

def main():
    try:
        req = json.load(sys.stdin)
    except Exception:
        print("{}"); return
    targets = req.get("targets", [])[:64]      # hard cap
    res = {}
    if targets:
        with ThreadPoolExecutor(max_workers=min(16, len(targets))) as ex:
            for pid, d in ex.map(sample, targets):
                res[str(pid)] = d
    print(json.dumps(res))

if __name__ == "__main__":
    main()
