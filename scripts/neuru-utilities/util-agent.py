#!/usr/bin/env python3
"""
util-agent.py — the NEURU Utilities control agent.

Runs inside the neuru-utilities container. It is the ONLY thing that writes service
configs on this box: it enrols with NEURU (shared token), then loops —

    pull desired-state  ──►  reconcile (render each service's config + start/stop
                             via supervisord)  ──►  report status + file manifest + events

That is what makes "configure everything from NEURU, never SSH the box" structurally
true. Outbound HTTPS only (works behind NAT). Mirrors the neuru-agent model.

Env:
  NEURU_URL      https://neuru.example.com           (required — the NEURU base URL)
  UTIL_TOKEN     neu_utl_...                          (required — shared enrolment token)
  UTIL_UID       stable id (default: /etc/machine-id or hostname)
  UTIL_NAME      display name (default: hostname)
  POLL_SECONDS   reconcile/report interval (default 20)
  UTIL_ROOT      shared file store (default /srv/neuru-utils)
  VERIFY_TLS     "0" to skip TLS verify (self-signed NEURU) (default 1)
"""
import os, sys, ssl, re, json, time, socket, hashlib, subprocess, urllib.request, urllib.error, urllib.parse

AGENT_VERSION = "0.1.0"
NEURU_URL   = os.environ.get("NEURU_URL", "").rstrip("/")
TOKEN       = os.environ.get("UTIL_TOKEN", "")
ROOT        = os.environ.get("UTIL_ROOT", "/srv/neuru-utils")
POLL        = int(os.environ.get("POLL_SECONDS", "20") or 20)
VERIFY_TLS  = os.environ.get("VERIFY_TLS", "1") != "0"
SUPERVISOR_D = "/etc/supervisor/conf.d"
STATE_FILE   = "/var/lib/neuru-util-agent/state.json"


def log(m): print(f"[util-agent] {m}", flush=True)

def uid():
    u = os.environ.get("UTIL_UID", "").strip()
    if u: return u
    try:
        with open("/etc/machine-id") as f:
            mid = f.read().strip()
        if mid: return "util-" + mid[:24]
    except Exception:
        pass
    return "util-" + socket.gethostname()

def host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close(); return ip
    except Exception:
        return ""

def arch():
    try: return subprocess.run(["uname","-m"],capture_output=True,text=True).stdout.strip()
    except Exception: return ""

def _ctx():
    if NEURU_URL.startswith("https") and not VERIFY_TLS:
        c = ssl.create_default_context(); c.check_hostname=False; c.verify_mode=ssl.CERT_NONE; return c
    return None

def api(path, payload):
    """POST JSON to NEURU utilities endpoint with the token header. Returns dict or None."""
    url = f"{NEURU_URL}/utilities.php?api={path}"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST",
        headers={"Content-Type":"application/json","X-Neuru-Util-Token":TOKEN})
    try:
        with urllib.request.urlopen(req, timeout=30, context=_ctx()) as r:
            return json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        log(f"{path} HTTP {e.code}: {e.read()[:200]}"); return None
    except Exception as e:
        log(f"{path} error: {e}"); return None

# ── supervisord helpers ──────────────────────────────────────────────────────
def supervisorctl(*args):
    try: return subprocess.run(["supervisorctl", *args], capture_output=True, text=True, timeout=30)
    except Exception as e: log(f"supervisorctl {args} err: {e}"); return None

def write_program(name, command, extra=""):
    os.makedirs(SUPERVISOR_D, exist_ok=True)
    conf = (f"[program:{name}]\ncommand={command}\nautostart=true\nautorestart=true\n"
            f"stdout_logfile=/var/log/neuru-util/{name}.log\nstderr_logfile=/var/log/neuru-util/{name}.err\n"
            f"stopasgroup=true\nkillasgroup=true\n{extra}\n")
    p = f"{SUPERVISOR_D}/util-{name}.conf"
    old = open(p).read() if os.path.exists(p) else ""
    if old != conf:
        open(p, "w").write(conf); return True
    return False

def remove_program(name):
    p = f"{SUPERVISOR_D}/util-{name}.conf"
    if os.path.exists(p):
        supervisorctl("stop", name); os.remove(p); return True
    return False

def ensure_dir(d):
    try: os.makedirs(d, exist_ok=True)
    except Exception: pass

# ── per-service renderers: (config) -> supervisor command (writes config files) ─
def r_filebrowser(c):
    port = int(c.get("port", 8088)); db = f"{ROOT}/.filebrowser.db"; ensure_dir(ROOT)
    if not os.path.exists(db):
        subprocess.run(["filebrowser","config","init","-d",db],capture_output=True)
        subprocess.run(["filebrowser","config","set","-d",db,"-a","0.0.0.0","-p",str(port),"-r",ROOT],capture_output=True)
        u=c.get("admin_user","admin") or "admin"; pw=c.get("admin_pass","") or "admin"
        subprocess.run(["filebrowser","users","add",u,pw,"-d",db,"--perm.admin"],capture_output=True)
    return f"filebrowser -d {db} -a 0.0.0.0 -p {port} -r {ROOT}"

def r_tftp(c):
    root=c.get("root",f"{ROOT}/tftp"); ensure_dir(root)
    opts="--secure"+(" --create --umask 0" if c.get("writable") else "")
    return f"/usr/sbin/in.tftpd --foreground --address 0.0.0.0:69 {opts} {root}"

def r_sftp(c):
    port=int(c.get("port",2222)); root=c.get("root",ROOT); user=c.get("username","neuru") or "neuru"; ensure_dir(root)
    # ensure user + creds
    subprocess.run(["useradd","-M","-d",root,"-s","/usr/sbin/nologin",user],capture_output=True)
    if c.get("password"):
        subprocess.run(["chpasswd"],input=f"{user}:{c['password']}",text=True,capture_output=True)
    if c.get("pubkey"):
        sd=f"{root}/.ssh"; ensure_dir(sd); open(f"{sd}/authorized_keys","w").write(c["pubkey"]+"\n")
        subprocess.run(["chown","-R",f"{user}:{user}",sd],capture_output=True)
    cfg=f"/etc/ssh/sshd_util_config"
    open(cfg,"w").write(
        f"Port {port}\nHostKey /etc/ssh/ssh_host_ed25519_key\nHostKey /etc/ssh/ssh_host_rsa_key\n"
        f"Subsystem sftp internal-sftp\nPasswordAuthentication yes\nPubkeyAuthentication yes\n"
        f"Match User {user}\n  ChrootDirectory {root}\n  ForceCommand internal-sftp\n  AllowTcpForwarding no\n")
    subprocess.run(["ssh-keygen","-A"],capture_output=True)
    return f"/usr/sbin/sshd -D -f {cfg}"

def r_ftp(c):
    root=c.get("root",f"{ROOT}/backups"); ensure_dir(root); user=c.get("username","neuru") or "neuru"
    subprocess.run(["useradd","-M","-d",root,"-s","/usr/sbin/nologin",user],capture_output=True)
    if c.get("password"): subprocess.run(["chpasswd"],input=f"{user}:{c['password']}",text=True,capture_output=True)
    tls="YES" if c.get("tls") else "NO"
    cfg="/etc/vsftpd_util.conf"
    open(cfg,"w").write(
        f"listen=YES\nanonymous_enable=NO\nlocal_enable=YES\nwrite_enable=YES\nchroot_local_user=YES\n"
        f"allow_writeable_chroot=YES\nlocal_root={root}\npasv_min_port={int(c.get('pasv_min',21000))}\n"
        f"pasv_max_port={int(c.get('pasv_max',21010))}\nssl_enable={tls}\nbackground=NO\nseccomp_sandbox=NO\n")
    return f"/usr/sbin/vsftpd {cfg}"

def r_http(c):
    root=c.get("root",f"{ROOT}/firmware"); ensure_dir(root); port=int(c.get("port",8080))
    autoindex="on" if c.get("autoindex",True) else "off"
    dav=("dav_methods PUT DELETE MKCOL COPY MOVE; create_full_put_path on; dav_access user:rw group:rw all:r;"
         if c.get("webdav") else "")
    cfg="/etc/nginx/nginx_util.conf"
    open(cfg,"w").write(
        "worker_processes 1;\nerror_log /var/log/neuru-util/nginx.err;\npid /run/nginx_util.pid;\n"
        "events { worker_connections 256; }\nhttp {\n include /etc/nginx/mime.types;\n"
        " access_log /var/log/neuru-util/http_access.log;\n"
        f" server {{\n  listen {port};\n  root {root};\n  autoindex {autoindex};\n  location / {{ {dav} }}\n }}\n}}\n")
    return f"nginx -c {cfg} -g 'daemon off;'"

def r_ntp(c):
    ups=[u.strip() for u in str(c.get("upstreams","pool.ntp.org")).split(",") if u.strip()]
    allow=[a.strip() for a in str(c.get("allow","0.0.0.0/0")).split(",") if a.strip()]
    cfg="/etc/chrony_util.conf"
    lines=[f"server {u} iburst" for u in ups]+[f"allow {a}" for a in allow]
    lines+=[f"local stratum {int(c.get('local_stratum',10))}","driftfile /var/lib/chrony/util.drift","rtcsync"]
    open(cfg,"w").write("\n".join(lines)+"\n")
    return f"/usr/sbin/chronyd -d -f {cfg}"

def r_iperf3(c):
    return f"iperf3 -s -p {int(c.get('port',5201))}"

def r_syslog(c):
    port=514; retention=int(c.get("retention_days",14)); ensure_dir("/var/log/neuru-util/remote")
    fwd=""
    if c.get("forward") and NEURU_URL:
        host=urllib.parse.urlparse(NEURU_URL).hostname or ""
        sev=c.get("filter","warning")
        if host: fwd=f'*.{sev};*.=info @{host}:514\n'
    cfg="/etc/rsyslog_util.conf"
    inputs=""
    if c.get("udp",True): inputs+='module(load="imudp")\ninput(type="imudp" port="514")\n'
    if c.get("tcp"):      inputs+='module(load="imtcp")\ninput(type="imtcp" port="514")\n'
    open(cfg,"w").write(
        f'$ModLoad imuxsock\n{inputs}'
        f'$template RemoteFile,"/var/log/neuru-util/remote/%HOSTNAME%.log"\n'
        f'*.* ?RemoteFile\n{fwd}')
    return f"rsyslogd -n -f {cfg}"

def r_dnsmasq(c):
    root=c.get("tftp_root",f"{ROOT}/tftp"); ensure_dir(root)
    lines=["port=0" if not c.get("dns") else "port=53","log-dhcp","bind-interfaces"]
    if c.get("dns"):
        lines=["port=53","domain-needed","bogus-priv","expand-hosts",f"domain={c.get('domain','lan')}"]
        for u in str(c.get("dns_upstream","1.1.1.1")).split(","):
            u=u.strip();
            if u: lines.append(f"server={u}")
    if c.get("proxydhcp"):
        subnet=str(c.get("proxy_subnet","")).strip()
        if subnet: lines.append(f"dhcp-range={subnet},proxy")
        lines.append("enable-tftp"); lines.append(f"tftp-root={root}")
        if c.get("ipxe"):
            # PXE → chainload iPXE → NEURU boot menu
            lines += ["dhcp-match=set:ipxe,175",
                      "dhcp-boot=tag:!ipxe,undionly.kpxe",
                      "dhcp-boot=tag:ipxe,menu.ipxe"]
            # write the iPXE menu from NEURU config
            menu=["#!ipxe","menu NEURU Boot"]
            for ln in str(c.get("boot_menu","")).splitlines():
                if "|" in ln:
                    lbl,url=ln.split("|",1); menu.append(f"item {url.strip()} {lbl.strip()}")
            menu+=["choose target && chain ${target}"]
            try: open(os.path.join(root,"menu.ipxe"),"w").write("\n".join(menu)+"\n")
            except Exception: pass
    open("/etc/dnsmasq_util.conf","w").write("\n".join(lines)+"\n")
    return "dnsmasq -k -C /etc/dnsmasq_util.conf"

def r_listeners(c):
    tcp=str(c.get("tcp_ports","")).strip(); udp=str(c.get("udp_ports","")).strip()
    banner=c.get("banner","NEURU-UTIL-OK")
    return f"python3 /opt/neuru/util-listeners.py --tcp '{tcp}' --udp '{udp}' --banner '{banner}'"

RENDERERS = {
    "filebrowser": r_filebrowser, "tftp": r_tftp, "sftp": r_sftp, "ftp": r_ftp,
    "http": r_http, "ntp": r_ntp, "iperf3": r_iperf3, "syslog": r_syslog,
    "dnsmasq": r_dnsmasq, "listeners": r_listeners,
}
VERSIONS = {  # best-effort version string reported per service
    "tftp":"tftpd-hpa","sftp":"openssh","ftp":"vsftpd","http":"nginx","ntp":"chrony",
    "iperf3":"iperf3","syslog":"rsyslog","filebrowser":"filebrowser",
}

# ── command / task channel (NEURU → agent) ───────────────────────────────────
def _safe_join(rel):
    p = os.path.normpath(os.path.join(ROOT, str(rel).lstrip("/")))
    if not p.startswith(os.path.abspath(ROOT)): raise ValueError("path escape")
    return p

def cmd_wol(a):
    mac = str(a.get("mac","")).replace(":","").replace("-","").replace(".","")
    if len(mac) != 12: return {"error":"bad mac"}
    pkt = bytes.fromhex("ff"*6 + mac*16)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.sendto(pkt, ("255.255.255.255", 9)); s.sendto(pkt, ("255.255.255.255", 7)); s.close()
    return {"sent": True, "mac": a.get("mac")}

def cmd_iperf(a):
    tgt=str(a.get("target","")); port=int(a.get("port",5201)); dur=int(a.get("duration",5))
    r=subprocess.run(["iperf3","-c",tgt,"-p",str(port),"-t",str(dur),"-J"],capture_output=True,text=True,timeout=dur+25)
    try:
        j=json.loads(r.stdout); s=j["end"]["sum_received"]["bits_per_second"]
        return {"mbps":round(s/1e6,2),"target":tgt,"seconds":dur}
    except Exception as e:
        return {"error":(r.stderr.strip() or str(e))[:200]}

def cmd_tcp_test(a):
    host=str(a.get("host","")); port=int(a.get("port",0)); t0=time.time()
    try:
        c=socket.create_connection((host,port),timeout=5); c.close()
        return {"open":True,"ms":round((time.time()-t0)*1000,1)}
    except Exception as e:
        return {"open":False,"error":str(e)[:120]}

def cmd_udp_test(a):
    host=str(a.get("host","")); port=int(a.get("port",0))
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3); s.sendto(b"NEURU-PROBE",(host,port))
        try: s.recvfrom(512); ans=True
        except Exception: ans=False
        s.close(); return {"sent":True,"replied":ans}
    except Exception as e:
        return {"error":str(e)[:120]}

def cmd_write_file(a):
    rel=str(a.get("path","")); content=str(a.get("content",""))
    fp=_safe_join(rel); ensure_dir(os.path.dirname(fp)); open(fp,"w").write(content)
    return {"written":rel,"bytes":len(content)}

COMMANDS = {"wol":cmd_wol,"iperf":cmd_iperf,"tcp_test":cmd_tcp_test,"udp_test":cmd_udp_test,"write_file":cmd_write_file}

def run_commands(cmds):
    out=[]
    for c in cmds or []:
        cid=c.get("id"); fn=COMMANDS.get(c.get("cmd"))
        if not fn: out.append({"id":cid,"status":"error","result":{"error":"unknown command"}}); continue
        try: out.append({"id":cid,"status":"done","result":fn(c.get("args",{}) or {})})
        except Exception as e: out.append({"id":cid,"status":"error","result":{"error":str(e)[:200]}})
        log(f"cmd {c.get('cmd')} -> {out[-1]['status']}")
    return out

# ── reconcile ────────────────────────────────────────────────────────────────
def reconcile(desired):
    services = desired.get("services", {})
    changed = False; states = {}
    for name, renderer in RENDERERS.items():
        want = services.get(name, {})
        enabled = bool(want.get("enabled"))
        cfg = want.get("config", {}) or {}
        if enabled:
            try:
                cmd = renderer(cfg)
                if write_program(name, cmd): changed = True
                states[name] = {"state":"running","version":VERSIONS.get(name)}
            except Exception as e:
                log(f"render {name} failed: {e}"); states[name] = {"state":"error","error":str(e)[:200]}
        else:
            if remove_program(name): changed = True
    if changed:
        supervisorctl("reread"); supervisorctl("update")
    for name in RENDERERS:
        if os.path.exists(f"{SUPERVISOR_D}/util-{name}.conf"): supervisorctl("start", name)
    return states

def scan_files():
    out=[];
    for base, _, files in os.walk(ROOT):
        for fn in files:
            if fn.startswith("."): continue
            fp=os.path.join(base,fn); rel=os.path.relpath(fp,ROOT)
            try:
                stt=os.stat(fp); top=rel.split(os.sep)[0]
                kind={"firmware":"firmware","images":"iso","tftp":"config","backups":"backup"}.get(top,"other")
                out.append({"path":rel,"size":stt.st_size,"mtime":int(stt.st_mtime),"kind":kind})
            except Exception: pass
            if len(out)>=5000: return out
    return out

_GRAB_OFF="/var/lib/neuru-util-agent/http.offset"
def scan_grabs():
    """Tail the HTTP access log for firmware/ZTP downloads → grab events (firmware audit +
    ZTP 'served' confirmation). TFTP grabs aren't logged by default (documented limitation)."""
    lp="/var/log/neuru-util/http_access.log"
    if not os.path.exists(lp): return []
    try: off=int(open(_GRAB_OFF).read().strip())
    except Exception: off=0
    ev=[]
    try:
        if off>os.path.getsize(lp): off=0
        with open(lp, errors="replace") as f:
            f.seek(off)
            for line in f:
                m=re.search(r'^(\S+).*"(?:GET|HEAD) (\S+) ', line)
                if not m: continue
                path=m.group(2)
                if "/ztp/" in path or "/firmware/" in path:
                    ev.append({"service":"http","type":"grab","ref":m.group(1),"detail":{"file":path.lstrip("/")}})
            off=f.tell()
        open(_GRAB_OFF,"w").write(str(off))
    except Exception: pass
    return ev[:200]

def load_state():
    try: return json.load(open(STATE_FILE))
    except Exception: return {}
def save_state(s):
    ensure_dir(os.path.dirname(STATE_FILE))
    try: json.dump(s, open(STATE_FILE,"w"))
    except Exception: pass

def main():
    if not NEURU_URL or not TOKEN:
        log("NEURU_URL and UTIL_TOKEN are required"); sys.exit(2)
    for d in ["/var/log/neuru-util","/var/lib/chrony",ROOT]: ensure_dir(d)
    U=uid(); NAME=os.environ.get("UTIL_NAME") or socket.gethostname()
    log(f"starting v{AGENT_VERSION} uid={U} → {NEURU_URL}")

    # enrol (retry until NEURU answers)
    while True:
        r=api("enroll",{"uid":U,"hostname":NAME,"ip":host_ip(),"arch":arch(),"agent_version":AGENT_VERSION,"os":" ".join(os.uname())})
        if r and r.get("ok"): log(f"enrolled node_id={r.get('node_id')}"); break
        log("enroll failed, retry in 15s"); time.sleep(15)

    st=load_state(); applied=st.get("applied_rev",-1); files_tick=0
    while True:
        d=api("desired",{"uid":U})
        states={}
        if d and d.get("ok"):
            rev=int(d.get("rev",0))
            if rev!=applied:
                log(f"reconciling desired rev {applied} → {rev}")
                states=reconcile(d); applied=rev; save_state({"applied_rev":applied})
            else:
                # still collect current states cheaply
                for n in RENDERERS:
                    if os.path.exists(f"{SUPERVISOR_D}/util-{n}.conf"): states[n]={"state":"running","version":VERSIONS.get(n)}
            # execute any queued commands (wol / iperf / tcp_test / write_file / …)
            cmd_results = run_commands(d.get("commands"))
        else:
            cmd_results = []
        report={"uid":U,"applied_rev":applied,"services":states}
        if cmd_results: report["command_results"]=cmd_results
        report["events"]=scan_grabs()
        files_tick+=1
        if files_tick % 5 == 1:   # refresh the file manifest every ~5 polls
            report["files"]=scan_files()
        api("report",report)
        time.sleep(POLL)

if __name__=="__main__":
    main()
