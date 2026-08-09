<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Container Template library + one-click deploy (over Portainer).
// Curated, editable templates (image, ports, env, volumes, restart) the operator
// launches to any Docker host from the portal — no SSH into the box. Builds on
// nm_portainer_container_create() (pull → create → start).
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_portainer.php';

if (!function_exists('nm_ctr_ensure')) {

function nm_ctr_ensure($conn): void {
    static $done = false; if ($done) return; $done = true;
    $conn->query("CREATE TABLE IF NOT EXISTS nm_ctr_templates (
        id           INT AUTO_INCREMENT PRIMARY KEY,
        name         VARCHAR(80) NOT NULL,
        category     VARCHAR(40) DEFAULT 'Custom',
        image        VARCHAR(200) NOT NULL,
        description  VARCHAR(255) DEFAULT '',
        icon         VARCHAR(60)  DEFAULT 'fa-solid fa-cube',
        ports_json   TEXT, env_json TEXT, volumes_json TEXT,
        restart      VARCHAR(20) DEFAULT 'unless-stopped',
        is_builtin   TINYINT DEFAULT 0,
        created_by   INT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uq_name (name)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    // Privileged host-namespace flags (only builtin templates that need them set these; the
    // deploy path reads them SERVER-SIDE so a user can't set pid=host on an arbitrary image).
    $have = [];
    $rc = $conn->query("SELECT COLUMN_NAME FROM information_schema.COLUMNS
                        WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_ctr_templates' AND COLUMN_NAME IN ('pid_mode','network_mode')");
    while ($rc && ($x=$rc->fetch_assoc())) $have[$x['COLUMN_NAME']]=1;
    if (!isset($have['pid_mode']))     { try { $conn->query("ALTER TABLE nm_ctr_templates ADD COLUMN pid_mode VARCHAR(16) NULL"); } catch (\Throwable $e) {} }
    if (!isset($have['network_mode'])) { try { $conn->query("ALTER TABLE nm_ctr_templates ADD COLUMN network_mode VARCHAR(32) NULL"); } catch (\Throwable $e) {} }
    @$conn->query("INSERT IGNORE INTO role_profiles (role_name,button_key,enabled) VALUES ('admin','containers',1)");
    nm_ctr_seed($conn);
}

// Curated library — seeded once (INSERT IGNORE on name; editing the row won't be clobbered
// because we only insert when the name is absent).
function nm_ctr_seed($conn): void {
    $T = [
      ['Nginx','Web','nginx:alpine','Lightweight web server / reverse proxy','fa-solid fa-server',
        ['80/tcp'=>'8080'], [], ['/srv/nginx/html:/usr/share/nginx/html:ro']],
      ['Apache httpd','Web','httpd:alpine','Apache HTTP server','fa-solid fa-server',
        ['80/tcp'=>'8081'], [], []],
      ['Redis','Cache','redis:7-alpine','In-memory key/value cache','fa-solid fa-bolt',
        ['6379/tcp'=>'6379'], [], ['/srv/redis:/data']],
      ['PostgreSQL','Database','postgres:16-alpine','PostgreSQL database','fa-solid fa-database',
        ['5432/tcp'=>'5432'], ['POSTGRES_PASSWORD=change_me','POSTGRES_DB=app'], ['/srv/pg:/var/lib/postgresql/data']],
      ['MySQL','Database','mysql:8','MySQL database','fa-solid fa-database',
        ['3306/tcp'=>'3306'], ['MYSQL_ROOT_PASSWORD=change_me','MYSQL_DATABASE=app'], ['/srv/mysql:/var/lib/mysql']],
      ['MariaDB','Database','mariadb:11','MariaDB database','fa-solid fa-database',
        ['3306/tcp'=>'3307'], ['MARIADB_ROOT_PASSWORD=change_me','MARIADB_DATABASE=app'], ['/srv/mariadb:/var/lib/mysql']],
      ['MongoDB','Database','mongo:7','MongoDB document database','fa-solid fa-leaf',
        ['27017/tcp'=>'27017'], ['MONGO_INITDB_ROOT_USERNAME=root','MONGO_INITDB_ROOT_PASSWORD=change_me'], ['/srv/mongo:/data/db']],
      ['Grafana','Observability','grafana/grafana:latest','Dashboards & visualization','fa-solid fa-chart-line',
        ['3000/tcp'=>'3000'], ['GF_SECURITY_ADMIN_PASSWORD=change_me'], ['/srv/grafana:/var/lib/grafana']],
      ['Prometheus','Observability','prom/prometheus:latest','Metrics time-series DB','fa-solid fa-fire',
        ['9090/tcp'=>'9090'], [], ['/srv/prometheus:/prometheus']],
      ['Uptime Kuma','Monitoring','louislam/uptime-kuma:1','Self-hosted uptime monitor','fa-solid fa-heart-pulse',
        ['3001/tcp'=>'3001'], [], ['/srv/uptime-kuma:/app/data']],
      ['Portainer Agent','Infra','portainer/agent:latest','Adopt a new Docker host into Portainer','fa-brands fa-docker',
        ['9001/tcp'=>'9001'], [], ['/var/run/docker.sock:/var/run/docker.sock','/var/lib/docker/volumes:/var/lib/docker/volumes']],
      ['Watchtower','Infra','containrrr/watchtower:latest','Auto-update running containers','fa-solid fa-arrows-rotate',
        [], [], ['/var/run/docker.sock:/var/run/docker.sock']],
      ['Adminer','Database','adminer:latest','Web DB management UI','fa-solid fa-table',
        ['8080/tcp'=>'8082'], [], []],
      ['Vaultwarden','Security','vaultwarden/server:latest','Self-hosted Bitwarden','fa-solid fa-shield-halved',
        ['80/tcp'=>'8200'], ['ADMIN_TOKEN=change_me'], ['/srv/vaultwarden:/data']],
      ['Nextcloud','Productivity','nextcloud:apache','Self-hosted file cloud','fa-solid fa-cloud',
        ['80/tcp'=>'8300'], [], ['/srv/nextcloud:/var/www/html']],
      ['Pi-hole','Network','pihole/pihole:latest','Network-wide ad/DNS blocker','fa-solid fa-shield-virus',
        ['53/tcp'=>'53','53/udp'=>'53','80/tcp'=>'8888'], ['TZ=America/Puerto_Rico','WEBPASSWORD=change_me'], ['/srv/pihole/etc:/etc/pihole','/srv/pihole/dnsmasq.d:/etc/dnsmasq.d']],
    ];
    $st = $conn->prepare("INSERT IGNORE INTO nm_ctr_templates (name,category,image,description,icon,ports_json,env_json,volumes_json,restart,is_builtin)
                          VALUES (?,?,?,?,?,?,?,?,'unless-stopped',1)");
    foreach ($T as $t) {
        [$name,$cat,$img,$desc,$icon,$ports,$env,$vols] = $t;
        $pj=json_encode($ports); $ej=json_encode($env); $vj=json_encode($vols);
        $st->bind_param('ssssssss', $name,$cat,$img,$desc,$icon,$pj,$ej,$vj);
        $st->execute();
    }
    $st->close();

    // ── NEURU Agent — our own one-click remote collector ──────────────────────
    // Needs host namespaces (pid_mode/network_mode = 'host') so it reads the target box's
    // /proc,/sys and reports host network. Env (NEURU_URL/NEURU_TOKEN) is auto-filled live
    // in nm_ctr_templates() so the operator just clicks Deploy. Ports omitted (host net).
    $vols = json_encode(['/proc:/host/proc:ro','/sys:/host/sys:ro','/:/host/root:ro','/var/run/docker.sock:/var/run/docker.sock:ro']);
    $env  = json_encode(['NEURU_URL=__AUTO__','NEURU_TOKEN=__AUTO__','NEURU_INTERVAL=30']);
    if ($ag = $conn->prepare("INSERT IGNORE INTO nm_ctr_templates
            (name,category,image,description,icon,ports_json,env_json,volumes_json,restart,is_builtin,pid_mode,network_mode)
            VALUES ('NEURU Agent','Monitoring','ghcr.io/hmiranda14/neuru-agent:latest',
                    'Featherweight remote collector — pushes CPU/mem/disk/net + Docker stats to NEURU',
                    'fa-solid fa-satellite-dish','{}',?,?,'unless-stopped',1,'host','host')")) {
        $ag->bind_param('ss', $env, $vols); $ag->execute(); $ag->close();
    }
}

function nm_ctr_templates($conn): array {
    nm_ctr_ensure($conn);
    $out = [];
    $r = $conn->query("SELECT * FROM nm_ctr_templates ORDER BY is_builtin DESC, category, name");
    while ($r && ($x=$r->fetch_assoc())) {
        $x['ports']   = json_decode((string)$x['ports_json'], true) ?: [];
        $x['env']     = json_decode((string)$x['env_json'], true) ?: [];
        $x['volumes'] = json_decode((string)$x['volumes_json'], true) ?: [];
        unset($x['ports_json'],$x['env_json'],$x['volumes_json']);
        // NEURU Agent: pre-fill the live endpoint + enrollment token so the operator just clicks Deploy.
        if (($x['image'] ?? '') === 'ghcr.io/hmiranda14/neuru-agent:latest') {
            $x['env'] = nm_ctr_agent_env($conn);
            $x['autofill'] = true;
        }
        $out[] = $x;
    }
    return $out;
}
// Live env for the NEURU Agent template (endpoint from this request + the enrollment token).
function nm_ctr_agent_env($conn): array {
    require_once __DIR__ . '/nm_agent.php';
    $tok = nm_agent_token($conn); if ($tok === '') $tok = nm_agent_token_rotate($conn);
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host   = $_SERVER['HTTP_HOST'] ?? 'YOUR-NEURU-HOST';
    $env = ['NEURU_URL=' . $scheme . '://' . $host . '/nm_agent_api.php',
            'NEURU_TOKEN=' . $tok,
            'NEURU_INTERVAL=30'];
    if (nm_agent_selfsigned_likely($scheme, $host)) $env[] = 'NEURU_VERIFY_TLS=0';   // self-signed NEURU
    return $env;
}
function nm_ctr_template_save($conn, array $in, ?int $uid=null): array {
    nm_ctr_ensure($conn);
    $name = trim((string)($in['name'] ?? '')); if ($name==='') return ['ok'=>false,'error'=>'Name required'];
    $image= trim((string)($in['image'] ?? '')); if (!nm_ctr_valid_image($image)) return ['ok'=>false,'error'=>'Invalid image reference'];
    $cat  = substr(trim((string)($in['category'] ?? 'Custom')),0,40) ?: 'Custom';
    $desc = substr(trim((string)($in['description'] ?? '')),0,255);
    $icon = substr(trim((string)($in['icon'] ?? 'fa-solid fa-cube')),0,60) ?: 'fa-solid fa-cube';
    $pj=json_encode((object)($in['ports']??[])); $ej=json_encode(array_values($in['env']??[])); $vj=json_encode(array_values($in['volumes']??[]));
    $rst = in_array(($in['restart']??'unless-stopped'),['no','always','unless-stopped','on-failure'],true)?$in['restart']:'unless-stopped';
    $id=(int)($in['id']??0);
    if ($id) {
        // never let an edit flip a builtin's identity name to collide; just update fields
        $st=$conn->prepare("UPDATE nm_ctr_templates SET category=?,image=?,description=?,icon=?,ports_json=?,env_json=?,volumes_json=?,restart=? WHERE id=?");
        $st->bind_param('ssssssssi',$cat,$image,$desc,$icon,$pj,$ej,$vj,$rst,$id); $st->execute(); $st->close();
        return ['ok'=>true,'id'=>$id];
    }
    $st=$conn->prepare("INSERT INTO nm_ctr_templates (name,category,image,description,icon,ports_json,env_json,volumes_json,restart,is_builtin,created_by)
                        VALUES (?,?,?,?,?,?,?,?,?,0,?)");
    $st->bind_param('sssssssssi',$name,$cat,$image,$desc,$icon,$pj,$ej,$vj,$rst,$uid);
    try { $st->execute(); } catch (\Throwable $e) { $st->close(); return ['ok'=>false,'error'=>'A template with that name already exists']; }
    $nid=$st->insert_id; $st->close();
    return ['ok'=>true,'id'=>$nid];
}
function nm_ctr_template_delete($conn, int $id): array {
    nm_ctr_ensure($conn);
    $r=$conn->query("SELECT is_builtin FROM nm_ctr_templates WHERE id=".(int)$id);
    $row=$r?$r->fetch_assoc():null;
    if (!$row) return ['ok'=>false,'error'=>'Not found'];
    if ((int)$row['is_builtin']===1) return ['ok'=>false,'error'=>'Built-in templates cannot be deleted (edit a copy instead)'];
    $conn->query("DELETE FROM nm_ctr_templates WHERE id=".(int)$id);
    return ['ok'=>true];
}

// ── Validation ───────────────────────────────────────────────────────────────
function nm_ctr_valid_image(string $s): bool {
    return $s !== '' && (bool)preg_match('#^[a-zA-Z0-9][a-zA-Z0-9._/\-:@]{0,200}$#', $s);
}
function nm_ctr_valid_name(string $s): bool {
    return $s === '' || (bool)preg_match('/^[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,60}$/', $s);
}

// ── Deploy (validate the operator's spec → Portainer create+start) ───────────
function nm_ctr_deploy($conn, array $cfg, int $eid, array $in, ?int $uid=null): array {
    nm_ctr_ensure($conn);
    if (!$eid) return ['ok'=>false,'error'=>'Pick a host'];
    $image = trim((string)($in['image'] ?? ''));
    if (!nm_ctr_valid_image($image)) return ['ok'=>false,'error'=>'Invalid image reference'];
    $name = trim((string)($in['name'] ?? ''));
    if (!nm_ctr_valid_name($name)) return ['ok'=>false,'error'=>'Invalid container name (letters, digits, . _ -)'];
    // ports: [{container:"80/tcp"|"80", host:"8080"}] → {cport:hport}
    $ports = [];
    foreach (($in['ports'] ?? []) as $p) {
        $cp = trim((string)($p['container'] ?? '')); $hp = trim((string)($p['host'] ?? ''));
        if ($cp==='' || $hp==='') continue;
        if (!preg_match('#^\d{1,5}(/(tcp|udp))?$#', $cp) || !preg_match('/^\d{1,5}$/', $hp)) return ['ok'=>false,'error'=>"Bad port mapping {$cp}:{$hp}"];
        $ports[$cp] = $hp;
    }
    // env: ["KEY=VAL"] — keep only valid
    $env = [];
    foreach (($in['env'] ?? []) as $e) { $e=trim((string)$e); if ($e!=='' && strpos($e,'=')!==false && preg_match('/^[A-Za-z_][A-Za-z0-9_]*=/', $e)) $env[]=$e; }
    // volumes: ["/host:/container[:ro]"]
    $binds = [];
    foreach (($in['volumes'] ?? []) as $v) { $v=trim((string)$v); if ($v!=='' && substr_count($v,':')>=1) $binds[]=$v; }
    $restart = in_array(($in['restart']??'unless-stopped'),['no','always','unless-stopped','on-failure'],true)?$in['restart']:'unless-stopped';

    $spec = ['image'=>$image,'name'=>$name,'ports'=>$ports,'env'=>$env,'binds'=>$binds,'restart'=>$restart];

    // Privileged host-namespace flags are NEVER taken from client input — only from the referenced
    // BUILTIN template (prevents a user from setting pid=host on an arbitrary image). If the operator
    // deploys the NEURU Agent, also guarantee its env carries the real endpoint + token.
    $tplId = (int)($in['tpl'] ?? 0);
    if ($tplId > 0) {
        $tr = $conn->query("SELECT image,pid_mode,network_mode FROM nm_ctr_templates WHERE id=".$tplId." AND is_builtin=1");
        if ($tr && ($trow = $tr->fetch_assoc())) {
            if (!empty($trow['pid_mode']))     $spec['pid_mode']     = (string)$trow['pid_mode'];
            if (!empty($trow['network_mode'])) $spec['network_mode'] = (string)$trow['network_mode'];
            if (($trow['image'] ?? '') === 'ghcr.io/hmiranda14/neuru-agent:latest') {
                // ensure NEURU_URL/NEURU_TOKEN are present + correct even if the form was cleared
                $keys = [];
                foreach ($spec['env'] as $e) { $k = strtok($e,'='); if ($k!==false) $keys[$k]=1; }
                $auto = nm_ctr_agent_env($conn);
                foreach ($auto as $ae) { $ak = strtok($ae,'='); if (empty($keys[$ak])) $spec['env'][] = $ae; }
            }
        }
    }
    $r = nm_portainer_container_create($cfg, $eid, $spec);
    nm_audit($conn, 'container.deploy', ['target_type'=>'docker','target_id'=>'endpoint:'.$eid,
        'details'=>['image'=>$image,'name'=>$name,'ok'=>$r['ok'],'status'=>$r['status']??0,'error'=>$r['error']??'']]);
    return $r;
}

} // end guard
