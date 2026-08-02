#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
# NEURU — Cisco-specific SNMP collector (F0).
# Collects the extras the generic poller can't express as flat metrics:
#   · Environmental sensors (CISCO-ENVMON-MIB): temperature / fan / power-supply
#     with per-sensor STATE (normal|warning|critical|shutdown|…).
#   · Neighbor adjacencies (CISCO-CDP-MIB): device id / port / platform / address.
# CPU/mem/interfaces stay with the generic template poller → not duplicated here.
#
# stdin : {"targets":[{"node_id":5,"ip":"10.0.0.1","comm":"public","ver":"v2c"}, ...]}
# stdout: {"5":{"env":[{kind,sensor,value,unit,state,threshold}],
#               "neighbors":[{local_if,neighbor_name,neighbor_ip,remote_if,platform,proto}],
#               "ok":1}, ...}
# SNMP v1/v2c only (matches nm_poller.py; v3 falls back to no data). NET-SNMP CLI
# ships in the container. Everything is wrapped so one dead device never aborts the batch.
# ─────────────────────────────────────────────────────────────────────────────
import sys, json, subprocess
from concurrent.futures import ThreadPoolExecutor

# ── OID bases (CISCO-ENVMON-MIB 1.3.6.1.4.1.9.9.13, CISCO-CDP-MIB .23, IF-MIB) ──
ENV_TEMP_DESCR  = ".1.3.6.1.4.1.9.9.13.1.3.1.2"
ENV_TEMP_VALUE  = ".1.3.6.1.4.1.9.9.13.1.3.1.3"
ENV_TEMP_THRESH = ".1.3.6.1.4.1.9.9.13.1.3.1.4"
ENV_TEMP_STATE  = ".1.3.6.1.4.1.9.9.13.1.3.1.6"
ENV_FAN_DESCR   = ".1.3.6.1.4.1.9.9.13.1.4.1.2"
ENV_FAN_STATE   = ".1.3.6.1.4.1.9.9.13.1.4.1.3"
ENV_PSU_DESCR   = ".1.3.6.1.4.1.9.9.13.1.5.1.2"
ENV_PSU_STATE   = ".1.3.6.1.4.1.9.9.13.1.5.1.3"

CDP_ADDR     = ".1.3.6.1.4.1.9.9.23.1.2.1.1.4"   # cdpCacheAddress (hex IPv4)
CDP_DEVID    = ".1.3.6.1.4.1.9.9.23.1.2.1.1.6"   # cdpCacheDeviceId
CDP_DEVPORT  = ".1.3.6.1.4.1.9.9.23.1.2.1.1.7"   # cdpCacheDevicePort
CDP_PLATFORM = ".1.3.6.1.4.1.9.9.23.1.2.1.1.8"   # cdpCachePlatform
IF_NAME      = ".1.3.6.1.2.1.31.1.1.1.1"         # ifName
IF_DESCR     = ".1.3.6.1.2.1.2.2.1.2"            # ifDescr

# ── Switch front-panel (F1) ───────────────────────────────────────────────────
IF_ADMIN     = ".1.3.6.1.2.1.2.2.1.7"            # ifAdminStatus
IF_OPER      = ".1.3.6.1.2.1.2.2.1.8"            # ifOperStatus
IF_HISPEED   = ".1.3.6.1.2.1.31.1.1.1.15"        # ifHighSpeed (Mbps)
IF_SPEED     = ".1.3.6.1.2.1.2.2.1.5"            # ifSpeed (bps, fallback)
IF_TYPE      = ".1.3.6.1.2.1.2.2.1.3"            # ifType (6=ethernetCsmacd)
DUPLEX       = ".1.3.6.1.2.1.10.7.2.1.19"        # dot3StatsDuplexStatus (idx=ifIndex)
VM_VLAN      = ".1.3.6.1.4.1.9.9.68.1.2.2.1.2"   # vmVlan access VLAN (idx=ifIndex)
VTP_NAME     = ".1.3.6.1.4.1.9.9.46.1.3.1.1.4"   # vtpVlanName (idx=domain.vlan)
VTP_STATE    = ".1.3.6.1.4.1.9.9.46.1.3.1.1.2"   # vtpVlanState (1=operational)
PETH_DETECT  = ".1.3.6.1.2.1.105.1.1.1.1.6"      # pethPsePortDetectionStatus (idx=group.port)
CPE_PWR      = ".1.3.6.1.4.1.9.9.402.1.2.1.7"    # cpeExtPsePortPwrConsumption mW (idx=group.port)

STATE_MAP = {"1": "normal", "2": "warning", "3": "critical", "4": "shutdown",
             "5": "notPresent", "6": "notFunctioning"}
IF_STATE  = {"1": "up", "2": "down", "3": "testing", "4": "unknown",
             "5": "dormant", "6": "notPresent", "7": "lowerLayerDown"}
DUPLEX_MAP = {"1": "unknown", "2": "half", "3": "full"}
POE_MAP    = {"1": "disabled", "2": "searching", "3": "delivering",
              "4": "fault", "5": "test", "6": "fault"}


def _trailing_num(s):
    """Last integer token in an interface name, e.g. 'GigabitEthernet1/0/7' → 7."""
    num = ""
    for ch in reversed(str(s)):
        if ch.isdigit():
            num = ch + num
        elif num:
            break
    return num


def _snmpwalk(ver, comm, ip, base):
    """Return {suffix: value} for an OID subtree. suffix = OID tail after `base`."""
    try:
        r = subprocess.run(
            ["snmpwalk", "-v" + ver, "-c", comm, "-Oqn", "-t", "2", "-r", "1", ip, base],
            capture_output=True, text=True, timeout=12)
        if r.returncode != 0:
            return {}
        out = {}
        blen = len(base if base.startswith(".") else "." + base)
        for ln in r.stdout.splitlines():
            ln = ln.strip()
            if not ln or " " not in ln:
                continue
            oid, val = ln.split(" ", 1)
            if not oid.startswith("."):
                oid = "." + oid
            b = base if base.startswith(".") else "." + base
            if not oid.startswith(b):
                continue
            suffix = oid[len(b):].lstrip(".")
            val = val.strip().strip('"')
            # NET-SNMP emits these as the "value" for absent OIDs — never real data
            if val.startswith(("No Such Instance", "No Such Object", "No more variables",
                               "End of MIB")) or val == "":
                continue
            # strip SNMP type prefixes some builds still emit
            for pfx in ("INTEGER:", "STRING:", "Gauge32:", "Counter32:", "Counter64:",
                        "Hex-STRING:", "IpAddress:"):
                if val.startswith(pfx):
                    val = val[len(pfx):].strip()
            out[suffix] = val
        return out
    except Exception:
        return {}


def _snmpget(ver, comm, ip, oid):
    """Single scalar OID → value string, or None if absent/error."""
    try:
        r = subprocess.run(
            ["snmpget", "-v" + ver, "-c", comm, "-Oqv", "-t", "2", "-r", "1", ip, oid],
            capture_output=True, text=True, timeout=6)
        if r.returncode != 0:
            return None
        v = r.stdout.strip().strip('"')
        if not v or v.startswith(("No Such", "No more")):
            return None
        for pfx in ("INTEGER:", "STRING:", "Gauge32:", "Counter32:", "Counter64:"):
            if v.startswith(pfx):
                v = v[len(pfx):].strip()
        return v
    except Exception:
        return None


# ── ASA firewall (F2) ─────────────────────────────────────────────────────────
ASA_CONN_CUR = ".1.3.6.1.4.1.9.9.147.1.2.2.2.1.5.40.6"   # cfwConnectionStatValue currentInUse
ASA_CONN_PK  = ".1.3.6.1.4.1.9.9.147.1.2.2.2.1.5.40.7"   # highWaterMark
ASA_RA_SESS  = ".1.3.6.1.4.1.9.9.392.1.3.1.0"            # crasNumSessions
ASA_RA_USERS = ".1.3.6.1.4.1.9.9.392.1.3.2.0"           # crasNumUsers
ASA_RA_MAX   = ".1.3.6.1.4.1.9.9.392.1.3.36.0"          # crasMaxSessionsSupported
ASA_IKE_TUN  = ".1.3.6.1.4.1.9.9.171.1.2.1.1.0"         # cikeGlobalActiveTunnels
ASA_IPSEC_TUN= ".1.3.6.1.4.1.9.9.171.1.3.1.1.0"         # cipSecGlobalActiveTunnels
ASA_HW_DETAIL= ".1.3.6.1.4.1.9.9.147.1.2.1.1.1.2"       # cfwHardwareStatusDetail (walk; idx 6=primary,7=secondary)


def collect_asa(ver, comm, ip):
    """ASA scalars: connections, remote-access + IPsec VPN, failover. SNMP-only;
    per-session VPN detail + ACL drops need SSH (F2.5)."""
    a = {}
    def num(oid, key):
        v = _snmpget(ver, comm, ip, oid)
        if v is not None:
            try: a[key] = int(v)
            except Exception: pass
    num(ASA_CONN_CUR, "conn_current"); num(ASA_CONN_PK, "conn_peak")
    num(ASA_RA_SESS, "ra_sessions");   num(ASA_RA_USERS, "ra_users"); num(ASA_RA_MAX, "ra_max")
    num(ASA_IKE_TUN, "ipsec_ike");     num(ASA_IPSEC_TUN, "ipsec_tunnels")
    # failover: pick the "this device" unit detail string (primary=6, else secondary=7)
    det = _snmpwalk(ver, comm, ip, ASA_HW_DETAIL)
    detail = det.get("6") or det.get("7") or ""
    if detail:
        a["failover_role"] = "primary" if "6" in det and det["6"] else "secondary"
        a["failover_detail"] = detail
        dl = detail.lower()
        a["failover_state"] = ("active" if "active" in dl else
                               "standby" if "standby" in dl else
                               "failed" if ("fail" in dl or "error" in dl) else None)
    return a


# ── Router control-plane (F3) ─────────────────────────────────────────────────
BGP_STATE   = ".1.3.6.1.2.1.15.3.1.2"    # bgpPeerState (idx=peerIP)
BGP_REMAS   = ".1.3.6.1.2.1.15.3.1.9"    # bgpPeerRemoteAs
BGP_ESTTIME = ".1.3.6.1.2.1.15.3.1.16"   # bgpPeerFsmEstablishedTime (secs)
OSPF_NBR_ST = ".1.3.6.1.2.1.14.10.1.6"   # ospfNbrState (idx=nbrIP.ifIndex)
OSPF_NBR_ID = ".1.3.6.1.2.1.14.10.1.3"   # ospfNbrRtrId
HSRP_STATE  = ".1.3.6.1.4.1.9.9.106.1.2.1.1.15"  # cHsrpGrpStandbyState (idx=ifIndex.group)
HSRP_VIP    = ".1.3.6.1.4.1.9.9.106.1.2.1.1.11"  # cHsrpGrpVirtualIpAddr
SLA_TAG     = ".1.3.6.1.4.1.9.9.42.1.2.1.1.3"    # rttMonCtrlAdminTag (idx=operIndex)
SLA_RTT     = ".1.3.6.1.4.1.9.9.42.1.2.10.1.1"   # rttMonLatestRttOperCompletionTime (ms)
SLA_SENSE   = ".1.3.6.1.4.1.9.9.42.1.2.10.1.2"   # rttMonLatestRttOperSense

BGP_MAP  = {"1": "idle", "2": "connect", "3": "active", "4": "opensent",
            "5": "openconfirm", "6": "established"}
OSPF_MAP = {"1": "down", "2": "attempt", "3": "init", "4": "twoWay",
            "5": "exchStart", "6": "exchange", "7": "loading", "8": "full"}
HSRP_MAP = {"1": "initial", "2": "learn", "3": "listen", "4": "speak",
            "5": "standby", "6": "active"}
SLA_MAP  = {"1": "ok", "2": "disconnected", "3": "overThreshold", "4": "timeout",
            "5": "busy", "6": "notConnected", "7": "dropped"}


def collect_router(ver, comm, ip):
    """BGP/OSPF/HSRP neighbors (unified) + IP SLA operations."""
    routing, ipsla = [], []
    try:
        # BGP
        st = _snmpwalk(ver, comm, ip, BGP_STATE)
        ras = _snmpwalk(ver, comm, ip, BGP_REMAS)
        est = _snmpwalk(ver, comm, ip, BGP_ESTTIME)
        for peer, sv in st.items():
            info = ("AS " + ras[peer]) if peer in ras else None
            up = None
            if peer in est:
                try: up = int(est[peer])
                except Exception: pass
            routing.append({"proto": "bgp", "peer": peer,
                            "state": BGP_MAP.get(sv, sv), "info": info, "uptime_secs": up})
        # OSPF (idx = nbrIP.ifIndex → peer = first 4 octets)
        ost = _snmpwalk(ver, comm, ip, OSPF_NBR_ST)
        oid_rtr = _snmpwalk(ver, comm, ip, OSPF_NBR_ID)
        for idx, sv in ost.items():
            peer = ".".join(idx.split(".")[:4])
            info = ("RID " + oid_rtr[idx]) if idx in oid_rtr else None
            routing.append({"proto": "ospf", "peer": peer,
                            "state": OSPF_MAP.get(sv, sv), "info": info})
        # HSRP (idx = ifIndex.group)
        hst = _snmpwalk(ver, comm, ip, HSRP_STATE)
        hvip = _snmpwalk(ver, comm, ip, HSRP_VIP)
        for idx, sv in hst.items():
            parts = idx.split(".")
            label = "if%s/grp%s" % (parts[0], parts[-1]) if len(parts) >= 2 else idx
            vip = _hex_to_ip(hvip.get(idx, "")) or hvip.get(idx)
            routing.append({"proto": "hsrp", "peer": label,
                            "state": HSRP_MAP.get(sv, sv),
                            "info": ("vip=" + vip) if vip else None})
        # IP SLA
        tag = _snmpwalk(ver, comm, ip, SLA_TAG)
        rtt = _snmpwalk(ver, comm, ip, SLA_RTT)
        sen = _snmpwalk(ver, comm, ip, SLA_SENSE)
        seen = set(list(tag.keys()) + list(rtt.keys()))
        for oi in seen:
            try: oin = int(oi)
            except Exception: continue
            r = None
            if oi in rtt:
                try: r = int(rtt[oi])
                except Exception: pass
            ipsla.append({"oper_index": oin, "tag": tag.get(oi),
                          "rtt_ms": r, "sense": SLA_MAP.get(sen.get(oi, ""), None)})
    except Exception:
        pass
    return routing, ipsla


def _hex_to_ip(v):
    """cdpCacheAddress is a 4-byte hex string like 'C0 A8 00 09' → dotted quad."""
    try:
        parts = v.replace(":", " ").split()
        if len(parts) == 4 and all(len(p) <= 2 for p in parts):
            return ".".join(str(int(p, 16)) for p in parts)
    except Exception:
        pass
    return None


def collect_switch(ver, comm, ip):
    """Per-port facts (status/speed/duplex/vlan/type + PoE) and the VLAN list."""
    ports, vlans = [], []
    try:
        names = _snmpwalk(ver, comm, ip, IF_NAME) or _snmpwalk(ver, comm, ip, IF_DESCR)
        if not names:
            # primary walk empty → SNMP transiently unreachable; signal "no data" (None)
            # so the ingest layer PRESERVES last-known ports instead of blanking the panel.
            return None, None
        admin = _snmpwalk(ver, comm, ip, IF_ADMIN)
        oper  = _snmpwalk(ver, comm, ip, IF_OPER)
        hisp  = _snmpwalk(ver, comm, ip, IF_HISPEED)
        spd   = _snmpwalk(ver, comm, ip, IF_SPEED)
        ityp  = _snmpwalk(ver, comm, ip, IF_TYPE)
        dpx   = _snmpwalk(ver, comm, ip, DUPLEX)
        vlan  = _snmpwalk(ver, comm, ip, VM_VLAN)

        # PoE (keyed group.port) → best-effort map to ifIndex by trailing port number
        pdet  = _snmpwalk(ver, comm, ip, PETH_DETECT)
        ppwr  = _snmpwalk(ver, comm, ip, CPE_PWR)
        poe_by_trail = {}
        for pidx, det in pdet.items():
            trail = pidx.split(".")[-1] if "." in pidx else pidx
            watts = None
            if pidx in ppwr:
                try: watts = round(int(ppwr[pidx]) / 1000.0, 2)  # mW → W
                except Exception: pass
            poe_by_trail[trail] = {"status": POE_MAP.get(det), "watts": watts}

        for ifx, nm in names.items():
            typ = None
            try: typ = int(ityp.get(ifx)) if ifx in ityp else None
            except Exception: typ = None
            speed = None
            if ifx in hisp:
                try: speed = int(hisp[ifx])
                except Exception: speed = None
            if not speed and ifx in spd:
                try: speed = int(int(spd[ifx]) / 1000000)
                except Exception: speed = None
            row = {"if_index": int(ifx) if str(ifx).isdigit() else ifx,
                   "if_name": nm,
                   "admin_status": IF_STATE.get(admin.get(ifx, ""), None),
                   "oper_status": IF_STATE.get(oper.get(ifx, ""), None),
                   "speed_mbps": speed, "if_type": typ,
                   "duplex": DUPLEX_MAP.get(dpx.get(ifx, ""), None)}
            if ifx in vlan:
                try: row["vlan"] = int(vlan[ifx])
                except Exception: pass
            # Attach PoE by trailing port number — ONLY for access copper ports
            # (uplinks/SFP/10G+ never source PoE; skip them to avoid false matches
            # when an uplink's trailing number collides with a PoE port index).
            nm_l = (nm or "").lower()
            is_uplink = (speed and speed > 1000) or any(
                k in nm_l for k in ("ten", "twenty", "forty", "hundred", "sfp", "xe-", "te-"))
            if not is_uplink:
                trail = _trailing_num(nm)
                if trail and trail in poe_by_trail:
                    row["poe_status"] = poe_by_trail[trail]["status"]
                    row["poe_watts"]  = poe_by_trail[trail]["watts"]
            ports.append(row)

        # VLAN list (VTP): index = <domain>.<vlanId>
        vnames = _snmpwalk(ver, comm, ip, VTP_NAME)
        vstate = _snmpwalk(ver, comm, ip, VTP_STATE)
        # count access-port membership per vlan
        pcount = {}
        for v in vlan.values():
            try: pcount[int(v)] = pcount.get(int(v), 0) + 1
            except Exception: pass
        for vidx, vn in vnames.items():
            vid = vidx.split(".")[-1] if "." in vidx else vidx
            try: vidn = int(vid)
            except Exception: continue
            st = vstate.get(vidx, "")
            vlans.append({"vlan_id": vidn, "name": vn,
                          "state": "active" if st == "1" else (st or None),
                          "port_count": pcount.get(vidn, 0)})
    except Exception:
        pass
    return ports, vlans


def collect(t):
    node_id = t.get("node_id")
    ip = str(t.get("ip", "")); comm = str(t.get("comm", ""))
    ver = "1" if str(t.get("ver", "v2c")) == "v1" else "2c"
    mods = t.get("mods") or ["env", "cdp"]
    if not ip or not comm:
        return node_id, {"ok": 0, "env": [], "neighbors": []}

    env, neigh, ports, vlans = [], [], None, None
    # ── Environmental ────────────────────────────────────────────────────────
    try:
        td = _snmpwalk(ver, comm, ip, ENV_TEMP_DESCR)
        tv = _snmpwalk(ver, comm, ip, ENV_TEMP_VALUE)
        tt = _snmpwalk(ver, comm, ip, ENV_TEMP_THRESH)
        ts = _snmpwalk(ver, comm, ip, ENV_TEMP_STATE)
        for idx, descr in td.items():
            row = {"kind": "temp", "sensor": descr or ("Temp " + idx), "unit": "C",
                   "state": STATE_MAP.get(ts.get(idx, ""), None)}
            if idx in tv:
                try: row["value"] = float(tv[idx])
                except Exception: pass
            if idx in tt:
                try: row["threshold"] = float(tt[idx])
                except Exception: pass
            env.append(row)

        fd = _snmpwalk(ver, comm, ip, ENV_FAN_DESCR)
        fs = _snmpwalk(ver, comm, ip, ENV_FAN_STATE)
        for idx, descr in fd.items():
            env.append({"kind": "fan", "sensor": descr or ("Fan " + idx),
                        "state": STATE_MAP.get(fs.get(idx, ""), None)})

        pd = _snmpwalk(ver, comm, ip, ENV_PSU_DESCR)
        ps = _snmpwalk(ver, comm, ip, ENV_PSU_STATE)
        for idx, descr in pd.items():
            env.append({"kind": "psu", "sensor": descr or ("PSU " + idx),
                        "state": STATE_MAP.get(ps.get(idx, ""), None)})
    except Exception:
        pass

    # ── CDP neighbors ────────────────────────────────────────────────────────
    try:
        names = _snmpwalk(ver, comm, ip, IF_NAME)
        if not names:
            names = _snmpwalk(ver, comm, ip, IF_DESCR)
        devid = _snmpwalk(ver, comm, ip, CDP_DEVID)
        port  = _snmpwalk(ver, comm, ip, CDP_DEVPORT)
        plat  = _snmpwalk(ver, comm, ip, CDP_PLATFORM)
        addr  = _snmpwalk(ver, comm, ip, CDP_ADDR)
        for cdpidx, dev in devid.items():
            # cdp index = <ifIndex>.<neighborIndex>
            ifidx = cdpidx.split(".")[0] if "." in cdpidx else cdpidx
            local = names.get(ifidx) or ("if" + ifidx)
            nip = _hex_to_ip(addr.get(cdpidx, "")) if cdpidx in addr else None
            neigh.append({"proto": "cdp", "local_if": local,
                          "neighbor_name": dev, "neighbor_ip": nip,
                          "remote_if": port.get(cdpidx), "platform": plat.get(cdpidx)})
    except Exception:
        pass

    # ── Switch front-panel (only for switches) ───────────────────────────────
    if "switch" in mods:
        ports, vlans = collect_switch(ver, comm, ip)

    # ── ASA firewall scalars (only for firewalls) ────────────────────────────
    asa = None
    if "asa" in mods:
        asa = collect_asa(ver, comm, ip)

    # ── Router control-plane (only for routers) ──────────────────────────────
    routing = vpn_sla = None
    if "router" in mods:
        routing, vpn_sla = collect_router(ver, comm, ip)

    ok = 1 if (env or neigh or ports or vlans or asa or routing or vpn_sla) else 0
    out = {"ok": ok, "env": env, "neighbors": neigh}
    if ports is not None: out["ports"] = ports
    if vlans is not None: out["vlans"] = vlans
    if asa is not None: out["asa"] = asa
    if routing is not None: out["routing"] = routing
    if vpn_sla is not None: out["ipsla"] = vpn_sla
    return node_id, out


def main():
    try:
        req = json.load(sys.stdin)
    except Exception:
        print("{}"); return
    targets = req.get("targets", [])[:64]
    res = {}
    if targets:
        with ThreadPoolExecutor(max_workers=min(12, len(targets))) as ex:
            for node_id, d in ex.map(collect, targets):
                res[str(node_id)] = d
    print(json.dumps(res))


if __name__ == "__main__":
    main()
