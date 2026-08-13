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
import os, sys, ssl, json, time, socket, hashlib, subprocess, urllib.request, urllib.error, urllib.parse

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

RENDERERS = {
    "filebrowser": r_filebrowser, "tftp": r_tftp, "sftp": r_sftp, "ftp": r_ftp,
    "http": r_http, "ntp": r_ntp, "iperf3": r_iperf3, "syslog": r_syslog,
}
VERSIONS = {  # best-effort version string reported per service
    "tftp":"tftpd-hpa","sftp":"openssh","ftp":"vsftpd","http":"nginx","ntp":"chrony",
    "iperf3":"iperf3","syslog":"rsyslog","filebrowser":"filebrowser",
}

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
        report={"uid":U,"applied_rev":applied,"services":states}
        files_tick+=1
        if files_tick % 5 == 1:   # refresh the file manifest every ~5 polls
            report["files"]=scan_files()
        api("report",report)
        time.sleep(POLL)

if __name__=="__main__":
    main()
