<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU Data Core — Database Observatory engine (Phase 1: targets + abstraction + test)
//
// Agnostic DBMS monitoring. A DB target is LINKED to an already-monitored node
// (nm_db_targets.node_id → nm_nodes) and reached by one of two transports:
//   • direct : a TCP connection from the portal via PDO (mysql now; pgsql if the
//              php8.3-pgsql extension is baked into the image — auto-detected).
//   • ssh    : run the engine's native client (mysql/psql) ON the node over the
//              existing SSH infra (nm_ssh_resolve + nm_cm_ssh_fetch). Zero install,
//              reboot/recreate-proof — this is the universal fallback.
//
// Every Monitor returns an IDENTICAL JSON shape regardless of engine/transport, so
// the UI renders one way. Phase 1 implements connectivity + probe(); the richer
// methods (locks, slow queries, table heatmap, schema) land in Phase 2.
//
// Secrets: passwords are stored with nm_secret_encrypt and only decrypt under the
// web/Apache user — so the poller runs via curl→localhost (like cron_gpu.php).
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_secrets.php';     // nm_secret_encrypt/decrypt, nm_ssh_resolve
require_once __DIR__ . '/nm_confmgr.php';      // nm_cm_ssh_fetch

if (!function_exists('nm_db_ensure')) {

// ── Schema ───────────────────────────────────────────────────────────────────
function nm_db_ensure($conn): void {
    static $done = false; if ($done) return; $done = true;
    $conn->query("CREATE TABLE IF NOT EXISTS nm_db_targets (
        id            INT AUTO_INCREMENT PRIMARY KEY,
        node_id       INT NULL,                                  -- the monitored box the DB runs on
        display_name  VARCHAR(120) NOT NULL,
        engine        VARCHAR(20)  NOT NULL DEFAULT 'mysql',     -- mysql|mariadb|postgres
        transport     VARCHAR(10)  NOT NULL DEFAULT 'direct',    -- direct|ssh
        host          VARCHAR(190) NOT NULL DEFAULT '127.0.0.1', -- DB host as seen from the chosen vantage
        port          INT NULL,
        db_name       VARCHAR(190) NULL,
        username      VARCHAR(190) NULL,
        password_enc  TEXT NULL,
        ssl_mode      VARCHAR(20)  NULL,                         -- direct PG/MySQL: disable|prefer|require
        enabled       TINYINT NOT NULL DEFAULT 1,
        last_status   VARCHAR(20) NULL,                          -- ok|error|unknown
        last_error    VARCHAR(400) NULL,
        last_version  VARCHAR(120) NULL,
        last_checked  DATETIME NULL,
        created_by    INT NULL,
        created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
        KEY idx_node (node_id), KEY idx_enabled (enabled)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    // replication role columns (guarded — mysqli is in EXCEPTION mode, @ won't suppress)
    foreach (['role'=>"role VARCHAR(12) NOT NULL DEFAULT 'standalone'", 'replica_of'=>"replica_of INT NULL"] as $col=>$ddl) {
        $c = $conn->query("SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_db_targets' AND COLUMN_NAME='".$col."' LIMIT 1");
        if (!$c || $c->num_rows === 0) $conn->query("ALTER TABLE nm_db_targets ADD COLUMN {$ddl}");
    }
    // replication health time-series (one row per poll of a replica)
    $conn->query("CREATE TABLE IF NOT EXISTS nm_db_repl (
        id BIGINT AUTO_INCREMENT PRIMARY KEY, target_id INT NOT NULL,
        sampled_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        io_running TINYINT DEFAULT 0, sql_running TINYINT DEFAULT 0,
        seconds_behind INT NULL, last_error VARCHAR(400) NULL, source_host VARCHAR(190) NULL,
        KEY idx_t (target_id, sampled_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    // time-series samples (counters) for trends + lock-storm / saturation detection
    $conn->query("CREATE TABLE IF NOT EXISTS nm_db_samples (
        id            BIGINT AUTO_INCREMENT PRIMARY KEY,
        target_id     INT NOT NULL,
        sampled_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
        connections   INT NULL, max_connections INT NULL, threads_running INT NULL,
        uptime_s      BIGINT NULL, blocked INT DEFAULT 0, slow INT DEFAULT 0,
        KEY idx_t (target_id, sampled_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    // schema fingerprints (one row per change) + the human-readable drift events
    $conn->query("CREATE TABLE IF NOT EXISTS nm_db_schema_snap (
        id BIGINT AUTO_INCREMENT PRIMARY KEY, target_id INT NOT NULL,
        captured_at DATETIME DEFAULT CURRENT_TIMESTAMP, schema_hash CHAR(40) NOT NULL,
        item_count INT DEFAULT 0, items_json LONGTEXT, KEY idx_t (target_id, captured_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    $conn->query("CREATE TABLE IF NOT EXISTS nm_db_schema_drift (
        id BIGINT AUTO_INCREMENT PRIMARY KEY, target_id INT NOT NULL,
        detected_at DATETIME DEFAULT CURRENT_TIMESTAMP, summary VARCHAR(255),
        changes_json LONGTEXT, KEY idx_t (target_id, detected_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    // "Accept schema" — mark a drift as an approved/expected change so it stops raising incidents.
    foreach (['acknowledged_at'=>'DATETIME DEFAULT NULL', 'acknowledged_by'=>'VARCHAR(60) DEFAULT NULL'] as $col=>$ddl) {
        $c = $conn->query("SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_db_schema_drift' AND COLUMN_NAME='".$col."' LIMIT 1");
        if (!$c || !$c->num_rows) $conn->query("ALTER TABLE nm_db_schema_drift ADD COLUMN $col $ddl");
    }
    // AI / heuristic recommendations (Index Archaeologist + Solution Center)
    $conn->query("CREATE TABLE IF NOT EXISTS nm_db_advice (
        id BIGINT AUTO_INCREMENT PRIMARY KEY, target_id INT NOT NULL,
        kind VARCHAR(16) NOT NULL DEFAULT 'index',         -- index | maintenance | kill | config | other
        title VARCHAR(255), rationale TEXT, ddl TEXT, risk VARCHAR(10) DEFAULT 'low',
        benefit VARCHAR(160), source VARCHAR(12) DEFAULT 'ai',
        status VARCHAR(12) NOT NULL DEFAULT 'proposed',     -- proposed | applied | dismissed | failed
        result TEXT, fingerprint VARCHAR(120) NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP, applied_at DATETIME NULL, applied_by INT NULL,
        UNIQUE KEY uq_fp (target_id, fingerprint), KEY idx_t (target_id, status)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    // seed RBAC so the page is grantable
    @$conn->query("INSERT IGNORE INTO role_profiles (role_name,button_key,enabled) VALUES ('admin','dbmon',1)");
}

// Slow / long-running query threshold (seconds) — operator-tunable in nm_settings.
function nm_db_slow_secs($conn): int {
    $s = 5;
    if ($r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='db_slow_secs' LIMIT 1"))
        if ($x = $r->fetch_row()) { $v = (int)$x[0]; if ($v > 0) $s = $v; }
    return max(1, min(3600, $s));
}

// ── Engine metadata (default ports, native client, family) ───────────────────
function nm_db_engines(): array {
    return [
        'mysql'    => ['label'=>'MySQL',       'port'=>3306, 'family'=>'mysql',    'client'=>'mysql', 'pdo'=>'mysql'],
        'mariadb'  => ['label'=>'MariaDB',     'port'=>3306, 'family'=>'mysql',    'client'=>'mysql', 'pdo'=>'mysql'],
        'postgres' => ['label'=>'PostgreSQL',  'port'=>5432, 'family'=>'postgres', 'client'=>'psql',  'pdo'=>'pgsql'],
    ];
}
// Which transports are usable for an engine in THIS environment (driver presence).
function nm_db_transport_caps(string $engine): array {
    $e = nm_db_engines()[$engine] ?? null;
    $caps = ['ssh' => true, 'direct' => false, 'direct_reason' => ''];
    if (!$e) { $caps['ssh'] = false; return $caps; }
    $pdo = $e['pdo'];
    if (in_array($pdo, PDO::getAvailableDrivers(), true)) $caps['direct'] = true;
    else $caps['direct_reason'] = "PDO driver '{$pdo}' not installed in this image — use SSH, or add php8.3-{$pdo} to your Dockerfile.";
    return $caps;
}

// ── Target CRUD ──────────────────────────────────────────────────────────────
function nm_db_targets($conn): array {
    nm_db_ensure($conn);
    $out = [];
    $r = $conn->query("SELECT t.*, n.display_name node_name, n.ip_address node_ip, n.os_icon
                       FROM nm_db_targets t LEFT JOIN nm_nodes n ON n.id=t.node_id ORDER BY t.display_name");
    while ($r && ($x = $r->fetch_assoc())) { unset($x['password_enc']); $out[] = $x; }
    return $out;
}
function nm_db_target($conn, int $id): ?array {
    nm_db_ensure($conn);
    $r = $conn->query("SELECT * FROM nm_db_targets WHERE id=".(int)$id." LIMIT 1");
    return $r ? ($r->fetch_assoc() ?: null) : null;
}
function nm_db_target_save($conn, array $in, ?int $uid = null): array {
    nm_db_ensure($conn);
    $engines = nm_db_engines();
    $engine  = strtolower(trim((string)($in['engine'] ?? 'mysql')));
    if (!isset($engines[$engine])) return ['ok'=>false,'error'=>'Unknown engine'];
    $transport = ($in['transport'] ?? 'direct') === 'ssh' ? 'ssh' : 'direct';
    $name = trim((string)($in['display_name'] ?? ''));
    if ($name === '') return ['ok'=>false,'error'=>'Name required'];
    $node_id = !empty($in['node_id']) ? (int)$in['node_id'] : null;
    if ($transport === 'ssh' && !$node_id) return ['ok'=>false,'error'=>'SSH transport requires a linked node (its SSH credential is used)'];
    $host = trim((string)($in['host'] ?? '127.0.0.1')) ?: '127.0.0.1';
    $port = !empty($in['port']) ? (int)$in['port'] : $engines[$engine]['port'];
    $db   = trim((string)($in['db_name'] ?? '')) ?: null;
    $user = trim((string)($in['username'] ?? '')) ?: null;
    $ssl  = trim((string)($in['ssl_mode'] ?? '')) ?: null;
    $en   = (!isset($in['enabled']) || $in['enabled']) ? 1 : 0;
    $id   = (int)($in['id'] ?? 0);

    // replication role + master link
    $role   = (string)($in['role'] ?? 'standalone');
    if (!in_array($role, ['standalone','master','replica'], true)) $role = 'standalone';
    $replof = ($role === 'replica' && !empty($in['replica_of'])) ? (int)$in['replica_of'] : null;

    // password: keep existing unless a new one is supplied
    $pwEnc = null; $hasPw = array_key_exists('password', $in) && $in['password'] !== '';
    if ($hasPw) $pwEnc = nm_secret_encrypt((string)$in['password']);

    if ($id) {
        $sql = "UPDATE nm_db_targets SET node_id=?,display_name=?,engine=?,transport=?,host=?,port=?,db_name=?,username=?,ssl_mode=?,enabled=?,role=?,replica_of=?"
             . ($hasPw ? ",password_enc=?" : "") . " WHERE id=?";
        $st = $conn->prepare($sql);
        if ($hasPw) $st->bind_param('issssisssisisi', $node_id,$name,$engine,$transport,$host,$port,$db,$user,$ssl,$en,$role,$replof,$pwEnc,$id);
        else        $st->bind_param('issssisssisii',  $node_id,$name,$engine,$transport,$host,$port,$db,$user,$ssl,$en,$role,$replof,$id);
        $st->execute(); $st->close();
        return ['ok'=>true,'id'=>$id];
    }
    $st = $conn->prepare("INSERT INTO nm_db_targets (node_id,display_name,engine,transport,host,port,db_name,username,ssl_mode,enabled,role,replica_of,password_enc,created_by)
                          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
    $st->bind_param('issssisssisisi', $node_id,$name,$engine,$transport,$host,$port,$db,$user,$ssl,$en,$role,$replof,$pwEnc,$uid);
    $st->execute(); $nid = $st->insert_id; $st->close();
    return ['ok'=>true,'id'=>$nid];
}
function nm_db_target_delete($conn, int $id): array {
    nm_db_ensure($conn);
    $conn->query("DELETE FROM nm_db_targets WHERE id=".(int)$id);
    return ['ok'=>true];
}
function nm_db_set_status($conn, int $id, string $status, ?string $err, ?string $ver): void {
    $st = $conn->prepare("UPDATE nm_db_targets SET last_status=?, last_error=?, last_version=?, last_checked=NOW() WHERE id=?");
    $e = $err !== null ? substr($err,0,400) : null; $v = $ver !== null ? substr($ver,0,120) : null;
    $st->bind_param('sssi', $status, $e, $v, $id); $st->execute(); $st->close();
}

// ─────────────────────────────────────────────────────────────────────────────
//  Abstraction layer — DatabaseMonitor (Strategy/Factory)
//  Every method returns a UNIFIED shape; Phase 1 wires probe()/test().
// ─────────────────────────────────────────────────────────────────────────────
abstract class DatabaseMonitor {
    protected $conn; protected array $t; protected ?PDO $_pdo = null;
    public function __construct($conn, array $target) { $this->conn = $conn; $this->t = $target; }

    abstract public function probe(): array;        // {version, uptime_s, connections, max_connections, threads_running}
    abstract public function live(): array;          // {processlist[], locks[], slow[], slow_threshold}
    abstract public function heatmap(): array;        // {tables:[{schema,name,reads,writes,bytes,rows}]}
    abstract public function fingerprintItems(): array;   // map "table.col"|"@idx t.name" => signature (for schema drift)
    abstract public function topQueries(): array;          // {queries:[{query,calls,total_s,avg_ms,rows_examined,no_index}]}
    abstract public function replication(): array;          // {is_replica,io_running,sql_running,seconds_behind,last_error,source_host,gtid_executed,replicas_connected}
    abstract public function tableRows(): array;            // {schema.table => estimated_rows}  (fast, information_schema estimate)
    abstract public function killPid(int $pid): array;
    /** Run a DDL/maintenance statement (used by gated advice-apply). */
    public function run(string $sql): void { $this->exec($sql); }
    /** Exact COUNT(*) for MANY tables. Base = per-table; engines OVERRIDE to batch into one query
     *  (repl-drift verifies dozens of tables — per-table round-trips would hang the compare). */
    public function tableCounts(array $tables): array {
        $out = [];
        foreach ($tables as $t) { try { $out[$t] = $this->tableCount($t); } catch (\Throwable $e) { $out[$t] = null; } }
        return $out;
    }
    abstract public function tableCount(string $table): ?int;
    abstract protected function dsn(): string;
    abstract protected function sshClientCmd(string $sql): string;   // build the native-client one-liner

    protected function lit(string $s): string { return "'" . str_replace("'", "''", $s) . "'"; }

    /** Cached direct PDO handle (with a fast TCP pre-flight so a firewalled host can't hang us). */
    protected function pdo(): PDO {
        if ($this->_pdo) return $this->_pdo;
        $host = (string)$this->t['host']; $port = (int)$this->t['port'];
        $errno = 0; $errstr = '';
        $fp = @fsockopen($host, $port, $errno, $errstr, 4);   // 4s connect ceiling
        if (!$fp) throw new RuntimeException("Cannot reach {$host}:{$port} (" . ($errstr ?: 'connection timed out') . ") — check host/port/firewall, or switch this target to SSH transport.");
        fclose($fp);
        return $this->_pdo = new PDO($this->dsn(), (string)$this->t['username'], $this->pw(),
            [PDO::ATTR_TIMEOUT=>5, PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
    }
    /** Run a SELECT → NUMERIC-indexed rows for BOTH transports (so rowsAs maps by position). */
    protected function query(string $sql): array {
        if (($this->t['transport'] ?? 'direct') === 'ssh') return $this->querySsh($sql);
        return $this->pdo()->query($sql)->fetchAll(PDO::FETCH_NUM) ?: [];
    }
    protected function exec(string $sql): void {
        if (($this->t['transport'] ?? 'direct') === 'ssh') { $this->querySsh($sql); return; }
        $this->pdo()->exec($sql);
    }
    protected function querySsh(string $sql): array {
        $ssh = nm_ssh_resolve($this->conn, (int)$this->t['node_id']);
        if (!$ssh) throw new RuntimeException('No SSH credential resolved for the linked node');
        $r = nm_cm_ssh_fetch($ssh, $this->sshClientCmd($sql), 12);
        if (!$r['ok']) throw new RuntimeException(substr((string)($r['error'] ?? ''),0,200) ?: 'SSH client failed');
        $rows = []; foreach (preg_split('/\r?\n/', trim((string)($r['config'] ?? ''))) as $ln) { if ($ln==='') continue; $rows[] = explode("\t", $ln); }
        return $rows;
    }
    /** Map numeric rows onto named columns (we control the SELECT column order). */
    protected function rowsAs(string $sql, array $cols): array {
        $out = []; foreach ($this->query($sql) as $r) { $v = array_values($r); $row = []; foreach ($cols as $i=>$c) $row[$c] = $v[$i] ?? null; $out[] = $row; }
        return $out;
    }
    protected function scalar(string $sql) { $r = $this->query($sql); if (!$r) return null; $v = array_values($r[0]); return $v[0] ?? null; }
    protected function pw(): string { return nm_secret_decrypt($this->t['password_enc'] ?? ''); }
}

// ── MySQL / MariaDB ──────────────────────────────────────────────────────────
class MySQLMonitor extends DatabaseMonitor {
    protected function dsn(): string {
        return "mysql:host={$this->t['host']};port=".(int)$this->t['port']
             . ($this->t['db_name'] ? ";dbname={$this->t['db_name']}" : "") . ";charset=utf8mb4";
    }
    protected function sshClientCmd(string $sql): string {
        return 'MYSQL_PWD=' . escapeshellarg($this->pw()) . ' mysql'
             . ' -h ' . escapeshellarg($this->t['host']) . ' -P ' . (int)$this->t['port']
             . ' -u ' . escapeshellarg((string)$this->t['username'])
             . ($this->t['db_name'] ? ' -D ' . escapeshellarg($this->t['db_name']) : '')
             . ' --connect-timeout=6 -N -B -e ' . escapeshellarg($sql) . ' 2>&1';
    }
    public function probe(): array {
        // On-disk size (data+index). Scope to the monitored schema if one is set, else whole server.
        $bytes = null; $dbc = null;
        try {
            $where = $this->t['db_name'] ? " WHERE TABLE_SCHEMA=" . $this->qlit($this->t['db_name']) : '';
            $b = $this->scalar("SELECT COALESCE(SUM(DATA_LENGTH+INDEX_LENGTH),0) FROM information_schema.TABLES{$where}");
            if ($b !== null) $bytes = (float)$b;
            $c = $this->scalar("SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME NOT IN ('mysql','information_schema','performance_schema','sys')");
            if ($c !== null) $dbc = (int)$c;
        } catch (\Throwable $e) {}
        return ['ok'=>true,'engine'=>$this->t['engine'],'transport'=>$this->t['transport'],
                'version'=>$this->scalar("SELECT VERSION()"),
                'uptime_s'=>(int)$this->statusVal('Uptime'),
                'connections'=>(int)$this->statusVal('Threads_connected'),
                'max_connections'=>(int)$this->scalar("SELECT @@max_connections"),
                'threads_running'=>(int)$this->statusVal('Threads_running'),
                'db_bytes'=>$bytes,'db_count'=>$dbc,'qps'=>null];
    }
    private function statusVal(string $name) {
        $r = $this->query("SHOW GLOBAL STATUS LIKE " . $this->qlit($name));
        if (!$r) return null; $v = array_values($r[0]); return $v[1] ?? null;   // [Variable_name, Value]
    }
    private function qlit(string $s): string { return "'" . str_replace("'", "''", $s) . "'"; }

    public function live(): array {
        $thr = (int)nm_db_slow_secs($this->conn);
        $pl = $this->rowsAs(
            "SELECT ID, USER, DB, COMMAND, TIME, STATE, LEFT(COALESCE(INFO,''),2000)
             FROM information_schema.PROCESSLIST
             WHERE COMMAND NOT IN ('Sleep','Daemon','Binlog Dump','Binlog Dump GTID')
             ORDER BY TIME DESC LIMIT 200",
            ['pid','user','db','command','secs','state','query']);
        $locks = $this->mysqlLocks();
        $slow = [];
        foreach ($pl as $r) if ((int)$r['secs'] >= $thr && trim((string)$r['query']) !== '') $slow[] = $r;
        return ['ok'=>true,'engine'=>$this->t['engine'],'processlist'=>$pl,'locks'=>$locks,'slow'=>$slow,'slow_threshold'=>$thr];
    }
    private function mysqlLocks(): array {
        // Try the sys-schema view first (MySQL 5.7/8), then perf_schema (MySQL 8). Return [] if neither.
        $tries = [
            ["SELECT waiting_pid, blocking_pid, LEFT(COALESCE(waiting_query,''),1000), LEFT(COALESCE(blocking_query,''),1000)
              FROM sys.innodb_lock_waits", ['waiting_pid','blocking_pid','waiting_query','blocking_query']],
            ["SELECT r.trx_mysql_thread_id, b.trx_mysql_thread_id, LEFT(COALESCE(r.trx_query,''),1000), LEFT(COALESCE(b.trx_query,''),1000)
              FROM performance_schema.data_lock_waits w
              JOIN information_schema.innodb_trx b ON b.trx_id=w.blocking_engine_transaction_id
              JOIN information_schema.innodb_trx r ON r.trx_id=w.requesting_engine_transaction_id",
              ['waiting_pid','blocking_pid','waiting_query','blocking_query']],
        ];
        foreach ($tries as [$sql,$cols]) { try { return $this->rowsAs($sql, $cols); } catch (\Throwable $e) {} }
        return [];
    }
    public function heatmap(): array {
        $io = [];
        try {
            $io = $this->rowsAs(
                "SELECT OBJECT_SCHEMA, OBJECT_NAME, COUNT_READ, COUNT_WRITE
                 FROM performance_schema.table_io_waits_summary_by_table
                 WHERE OBJECT_SCHEMA NOT IN ('mysql','performance_schema','sys','information_schema')
                   AND OBJECT_NAME IS NOT NULL ORDER BY (COUNT_READ+COUNT_WRITE) DESC LIMIT 256",
                ['schema','name','reads','writes']);
        } catch (\Throwable $e) {}
        $sz = [];
        try {
            foreach ($this->rowsAs(
                "SELECT TABLE_SCHEMA, TABLE_NAME, (COALESCE(DATA_LENGTH,0)+COALESCE(INDEX_LENGTH,0)), COALESCE(TABLE_ROWS,0)
                 FROM information_schema.TABLES
                 WHERE TABLE_SCHEMA NOT IN ('mysql','performance_schema','sys','information_schema') AND TABLE_TYPE='BASE TABLE'",
                ['schema','name','bytes','rows']) as $r) $sz[$r['schema'].'.'.$r['name']] = $r;
        } catch (\Throwable $e) {}
        $tables = [];
        foreach ($io as $r) { $k=$r['schema'].'.'.$r['name']; $s=$sz[$k]??null;
            $tables[] = ['schema'=>$r['schema'],'name'=>$r['name'],'reads'=>(float)$r['reads'],'writes'=>(float)$r['writes'],
                         'bytes'=>$s?(float)$s['bytes']:0,'rows'=>$s?(int)$s['rows']:0]; }
        if (!$tables) foreach ($sz as $r) $tables[] = ['schema'=>$r['schema'],'name'=>$r['name'],'reads'=>0,'writes'=>0,'bytes'=>(float)$r['bytes'],'rows'=>(int)$r['rows']];
        return ['ok'=>true,'tables'=>$tables];
    }
    public function killPid(int $pid): array { $this->exec("KILL " . (int)$pid); return ['ok'=>true]; }
    public function fingerprintItems(): array {
        $db = (string)($this->t['db_name'] ?? ''); if ($db === '') return [];   // need a schema scope
        $items = [];
        foreach ($this->rowsAs(
            "SELECT TABLE_NAME, COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_KEY
             FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=" . $this->lit($db) . "
             ORDER BY TABLE_NAME, ORDINAL_POSITION",
            ['t','c','type','nullable','key']) as $r)
            $items[$r['t'].'.'.$r['c']] = $r['type'].' | '.($r['nullable']==='YES'?'NULL':'NOT NULL').($r['key']?(' | '.$r['key']):'');
        foreach ($this->rowsAs(
            "SELECT TABLE_NAME, INDEX_NAME, GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX), MIN(NON_UNIQUE)
             FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=" . $this->lit($db) . "
             GROUP BY TABLE_NAME, INDEX_NAME",
            ['t','idx','cols','nonuniq']) as $r)
            $items['@idx '.$r['t'].'.'.$r['idx']] = $r['cols'].(($r['nonuniq']==='0'||$r['nonuniq']===0)?' (unique)':'');
        return $items;
    }
    public function topQueries(): array {
        // performance_schema digest aggregates = the canonical "what's slow + does it scan" view.
        $db = (string)($this->t['db_name'] ?? '');
        $where = $db !== '' ? "WHERE SCHEMA_NAME=" . $this->lit($db) : "WHERE SCHEMA_NAME IS NOT NULL";
        try {
            $rows = $this->rowsAs(
                "SELECT LEFT(DIGEST_TEXT,500), COUNT_STAR, ROUND(SUM_TIMER_WAIT/1e12,2), ROUND(AVG_TIMER_WAIT/1e9,2),
                        SUM_ROWS_EXAMINED, SUM_ROWS_SENT, SUM_NO_INDEX_USED
                 FROM performance_schema.events_statements_summary_by_digest
                 {$where} AND DIGEST_TEXT IS NOT NULL ORDER BY SUM_TIMER_WAIT DESC LIMIT 40",
                ['query','calls','total_s','avg_ms','rows_examined','rows_sent','no_index']);
            foreach ($rows as &$r) { $r['no_index']=((int)$r['no_index']>0); $r['calls']=(int)$r['calls']; $r['total_s']=(float)$r['total_s']; $r['avg_ms']=(float)$r['avg_ms']; $r['rows_examined']=(int)$r['rows_examined']; $r['rows_sent']=(int)$r['rows_sent']; }
            return ['ok'=>true,'source'=>'performance_schema','queries'=>$rows];
        } catch (\Throwable $e) { return ['ok'=>false,'error'=>'performance_schema digest unavailable: '.$e->getMessage(),'queries'=>[]]; }
    }
    private function parseVertical(string $out): ?array {
        $row = []; foreach (preg_split('/\r?\n/', $out) as $ln) if (preg_match('/^\s*([A-Za-z0-9_]+):\s?(.*)$/', $ln, $m)) $row[$m[1]] = $m[2];
        return $row ?: null;
    }
    /** Run a SHOW … that yields ONE wide row → assoc by column name (works on both transports). */
    private function showVertical(string $sql): ?array {
        if (($this->t['transport'] ?? 'direct') === 'ssh') {
            $ssh = nm_ssh_resolve($this->conn, (int)$this->t['node_id']); if (!$ssh) return null;
            $cmd = 'MYSQL_PWD=' . escapeshellarg($this->pw()) . ' mysql -h ' . escapeshellarg($this->t['host'])
                 . ' -P ' . (int)$this->t['port'] . ' -u ' . escapeshellarg((string)$this->t['username'])
                 . ' --connect-timeout=6 -E -e ' . escapeshellarg($sql) . ' 2>&1';
            $r = nm_cm_ssh_fetch($ssh, $cmd, 12); if (!$r['ok']) return null;
            return $this->parseVertical((string)($r['config'] ?? ''));
        }
        try { $row = $this->pdo()->query($sql)->fetch(PDO::FETCH_ASSOC); return $row ?: null; } catch (\Throwable $e) { return null; }
    }
    public function replication(): array {
        $row = $this->showVertical("SHOW REPLICA STATUS") ?: $this->showVertical("SHOW SLAVE STATUS");
        $g = fn($k) => $row[$k] ?? null;
        $io  = strtolower((string)($g('Replica_IO_Running')  ?? $g('Slave_IO_Running')  ?? '')) === 'yes';
        $sql = strtolower((string)($g('Replica_SQL_Running') ?? $g('Slave_SQL_Running') ?? '')) === 'yes';
        $behind = $g('Seconds_Behind_Source'); if ($behind===null) $behind = $g('Seconds_Behind_Master');
        $behind = ($behind===null || $behind==='NULL' || $behind==='') ? null : (int)$behind;
        $err = trim((string)($g('Last_Error') ?: ($g('Last_SQL_Error') ?: ($g('Last_IO_Error') ?: ''))));
        $replicas = null;
        try { $replicas = count($this->query("SHOW REPLICAS")); }
        catch (\Throwable $e) { try { $replicas = count($this->query("SHOW SLAVE HOSTS")); } catch (\Throwable $e2) {} }
        return ['ok'=>true,'is_replica'=>(bool)$row,'io_running'=>$io,'sql_running'=>$sql,'seconds_behind'=>$behind,
                'last_error'=>$err,'source_host'=>($g('Source_Host') ?? $g('Master_Host')),
                'gtid_executed'=>(string)($g('Executed_Gtid_Set') ?? ''),'replicas_connected'=>$replicas];
    }
    public function tableRows(): array {
        $db = (string)($this->t['db_name'] ?? ''); if ($db === '') return [];
        $out = [];
        foreach ($this->rowsAs(
            "SELECT TABLE_NAME, COALESCE(TABLE_ROWS,0) FROM information_schema.TABLES
             WHERE TABLE_SCHEMA=" . $this->lit($db) . " AND TABLE_TYPE='BASE TABLE'",
            ['t','rows']) as $r) $out[$r['t']] = (int)$r['rows'];
        return $out;
    }
    /** Exact COUNT(*) for ONE table (on-demand only — heavy). */
    public function tableCount(string $table): ?int {
        if (!preg_match('/^[A-Za-z0-9_$]+$/', $table)) return null;
        $db = (string)($this->t['db_name'] ?? '');
        $q = "SELECT COUNT(*) FROM " . ($db!==''?('`'.str_replace('`','',$db).'`.'):'') . "`{$table}`";
        $v = $this->scalar($q); return $v===null?null:(int)$v;
    }
    /** Batched exact COUNT(*): ONE UNION ALL query per 40-table chunk (not N round-trips). */
    public function tableCounts(array $tables): array {
        $db = (string)($this->t['db_name'] ?? '');
        $pre = $db!=='' ? ('`'.str_replace('`','',$db).'`.') : '';
        $valid = array_values(array_filter($tables, fn($t)=>preg_match('/^[A-Za-z0-9_$]+$/', (string)$t)));
        $out = [];
        foreach (array_chunk($valid, 40) as $chunk) {
            $parts = [];
            foreach ($chunk as $t) $parts[] = "SELECT " . $this->lit($t) . " t, COUNT(*) c FROM {$pre}`{$t}`";
            try { foreach ($this->rowsAs(implode(" UNION ALL ", $parts), ['t','c']) as $r) $out[$r['t']] = (int)$r['c']; }
            catch (\Throwable $e) { foreach ($chunk as $t) { try { $out[$t]=$this->tableCount($t); } catch (\Throwable $e2) { $out[$t]=null; } } }
        }
        return $out;
    }
}

// ── PostgreSQL ───────────────────────────────────────────────────────────────
class PostgresMonitor extends DatabaseMonitor {
    protected function dsn(): string {
        return "pgsql:host={$this->t['host']};port=".(int)$this->t['port']
             . ($this->t['db_name'] ? ";dbname={$this->t['db_name']}" : "");
    }
    protected function sshClientCmd(string $sql): string {
        $db = $this->t['db_name'] ?: 'postgres';
        return 'PGCONNECT_TIMEOUT=6 PGPASSWORD=' . escapeshellarg($this->pw())
             . ' psql -h ' . escapeshellarg($this->t['host']) . ' -p ' . (int)$this->t['port']
             . ' -U ' . escapeshellarg((string)$this->t['username']) . ' -d ' . escapeshellarg($db)
             . ' -w -tAF ' . escapeshellarg("\t") . ' -c ' . escapeshellarg($sql) . ' 2>&1';
    }
    public function probe(): array {
        $up = $this->scalar("SELECT EXTRACT(EPOCH FROM (now() - pg_postmaster_start_time()))::bigint");
        // On-disk size of the connected database + count of non-template databases.
        $bytes = null; $dbc = null;
        try {
            $b = $this->scalar("SELECT pg_database_size(current_database())");
            if ($b !== null) $bytes = (float)$b;
            $c = $this->scalar("SELECT count(*) FROM pg_database WHERE datistemplate=false");
            if ($c !== null) $dbc = (int)$c;
        } catch (\Throwable $e) {}
        return ['ok'=>true,'engine'=>$this->t['engine'],'transport'=>$this->t['transport'],
                'version'=>$this->scalar("SELECT version()"),
                'uptime_s'=>$up!==null?(int)$up:null,
                'connections'=>(int)$this->scalar("SELECT count(*) FROM pg_stat_activity"),
                'max_connections'=>(int)$this->scalar("SHOW max_connections"),
                'threads_running'=>(int)$this->scalar("SELECT count(*) FROM pg_stat_activity WHERE state='active'"),
                'db_bytes'=>$bytes,'db_count'=>$dbc,'qps'=>null];
    }
    public function live(): array {
        $thr = (int)nm_db_slow_secs($this->conn);
        $pl = $this->rowsAs(
            "SELECT pid, COALESCE(usename,''), COALESCE(datname,''), COALESCE(state,''),
                    GREATEST(0, EXTRACT(EPOCH FROM (now()-COALESCE(query_start,now())))::int),
                    COALESCE(wait_event_type,''), LEFT(COALESCE(query,''),2000)
             FROM pg_stat_activity
             WHERE state IS NOT NULL AND state <> 'idle' AND pid <> pg_backend_pid()
             ORDER BY query_start NULLS LAST LIMIT 200",
            ['pid','user','db','state','secs','command','query']);
        $locks = [];
        try {
            $locks = $this->rowsAs(
                "SELECT a.pid, bl.pid, LEFT(COALESCE(a.query,''),1000), LEFT(COALESCE(bl.query,''),1000)
                 FROM pg_stat_activity a
                 JOIN LATERAL unnest(pg_blocking_pids(a.pid)) AS b(pid) ON true
                 JOIN pg_stat_activity bl ON bl.pid = b.pid
                 WHERE cardinality(pg_blocking_pids(a.pid)) > 0",
                ['waiting_pid','blocking_pid','waiting_query','blocking_query']);
        } catch (\Throwable $e) {}
        $slow = [];
        foreach ($pl as $r) if ($r['state']==='active' && (int)$r['secs'] >= $thr && trim((string)$r['query'])!=='') $slow[] = $r;
        return ['ok'=>true,'engine'=>$this->t['engine'],'processlist'=>$pl,'locks'=>$locks,'slow'=>$slow,'slow_threshold'=>$thr];
    }
    public function heatmap(): array {
        $tables = [];
        try {
            $tables = $this->rowsAs(
                "SELECT schemaname, relname,
                        (COALESCE(seq_scan,0)+COALESCE(idx_scan,0)),
                        (COALESCE(n_tup_ins,0)+COALESCE(n_tup_upd,0)+COALESCE(n_tup_del,0)),
                        pg_total_relation_size(relid), COALESCE(n_live_tup,0)
                 FROM pg_stat_user_tables
                 ORDER BY (COALESCE(seq_scan,0)+COALESCE(idx_scan,0)+COALESCE(n_tup_ins,0)+COALESCE(n_tup_upd,0)+COALESCE(n_tup_del,0)) DESC
                 LIMIT 256",
                ['schema','name','reads','writes','bytes','rows']);
        } catch (\Throwable $e) {}
        foreach ($tables as &$r) { $r['reads']=(float)$r['reads']; $r['writes']=(float)$r['writes']; $r['bytes']=(float)$r['bytes']; $r['rows']=(int)$r['rows']; }
        return ['ok'=>true,'tables'=>$tables];
    }
    public function killPid(int $pid): array { $this->scalar("SELECT pg_terminate_backend(".(int)$pid.")"); return ['ok'=>true]; }
    public function fingerprintItems(): array {
        $items = [];
        foreach ($this->rowsAs(
            "SELECT table_name, column_name, data_type, is_nullable
             FROM information_schema.columns WHERE table_schema='public'
             ORDER BY table_name, ordinal_position",
            ['t','c','type','nullable']) as $r)
            $items[$r['t'].'.'.$r['c']] = $r['type'].' | '.($r['nullable']==='YES'?'NULL':'NOT NULL');
        foreach ($this->rowsAs(
            "SELECT tablename, indexname, indexdef FROM pg_indexes WHERE schemaname='public'",
            ['t','idx','def']) as $r)
            $items['@idx '.$r['t'].'.'.$r['idx']] = (string)$r['def'];
        return $items;
    }
    public function topQueries(): array {
        // needs the pg_stat_statements extension (CREATE EXTENSION pg_stat_statements)
        try {
            $rows = $this->rowsAs(
                "SELECT LEFT(query,500), calls, ROUND((total_exec_time/1000.0)::numeric,2), ROUND(mean_exec_time::numeric,2), rows, 0, 0
                 FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 40",
                ['query','calls','total_s','avg_ms','rows_examined','rows_sent','no_index']);
            foreach ($rows as &$r) { $r['no_index']=false; $r['calls']=(int)$r['calls']; $r['total_s']=(float)$r['total_s']; $r['avg_ms']=(float)$r['avg_ms']; $r['rows_examined']=(int)$r['rows_examined']; $r['rows_sent']=0; }
            return ['ok'=>true,'source'=>'pg_stat_statements','queries'=>$rows];
        } catch (\Throwable $e) { return ['ok'=>false,'error'=>'pg_stat_statements not enabled (run: CREATE EXTENSION pg_stat_statements;)','queries'=>[]]; }
    }
    public function replication(): array {
        try {
            $inRec = (int)$this->scalar("SELECT pg_is_in_recovery()::int");
            if ($inRec) {
                $lag = $this->scalar("SELECT COALESCE(EXTRACT(EPOCH FROM (now()-pg_last_xact_replay_timestamp()))::int,0)");
                $st  = $this->rowsAs("SELECT COALESCE(status,''), COALESCE(sender_host,'') FROM pg_stat_wal_receiver LIMIT 1", ['status','host']);
                $io  = $st ? ($st[0]['status']==='streaming') : false;
                return ['ok'=>true,'is_replica'=>true,'io_running'=>$io,'sql_running'=>$io,'seconds_behind'=>$lag!==null?(int)$lag:null,
                        'last_error'=>'','source_host'=>$st?$st[0]['host']:null,'gtid_executed'=>'','replicas_connected'=>null];
            }
            $rep = (int)$this->scalar("SELECT count(*) FROM pg_stat_replication");
            return ['ok'=>true,'is_replica'=>false,'io_running'=>false,'sql_running'=>false,'seconds_behind'=>null,
                    'last_error'=>'','source_host'=>null,'gtid_executed'=>'','replicas_connected'=>$rep];
        } catch (\Throwable $e) { return ['ok'=>false,'error'=>$e->getMessage()]; }
    }
    public function tableRows(): array {
        $out = [];
        try { foreach ($this->rowsAs("SELECT relname, COALESCE(n_live_tup,0) FROM pg_stat_user_tables", ['t','rows']) as $r) $out[$r['t']] = (int)$r['rows']; } catch (\Throwable $e) {}
        return $out;
    }
    public function tableCount(string $table): ?int {
        if (!preg_match('/^[A-Za-z0-9_$]+$/', $table)) return null;
        $v = $this->scalar('SELECT COUNT(*) FROM "' . $table . '"'); return $v===null?null:(int)$v;
    }
    public function tableCounts(array $tables): array {
        $valid = array_values(array_filter($tables, fn($t)=>preg_match('/^[A-Za-z0-9_$]+$/', (string)$t)));
        $out = [];
        foreach (array_chunk($valid, 40) as $chunk) {
            $parts = [];
            foreach ($chunk as $t) $parts[] = 'SELECT ' . $this->lit($t) . ' AS t, COUNT(*) AS c FROM "' . $t . '"';
            try { foreach ($this->rowsAs(implode(" UNION ALL ", $parts), ['t','c']) as $r) $out[$r['t']] = (int)$r['c']; }
            catch (\Throwable $e) { foreach ($chunk as $t) { try { $out[$t]=$this->tableCount($t); } catch (\Throwable $e2) { $out[$t]=null; } } }
        }
        return $out;
    }
}

// ── Factory ──────────────────────────────────────────────────────────────────
function nm_db_monitor($conn, array $target): DatabaseMonitor {
    $fam = nm_db_engines()[$target['engine']]['family'] ?? 'mysql';
    return $fam === 'postgres' ? new PostgresMonitor($conn, $target) : new MySQLMonitor($conn, $target);
}

// ── Test a target's connectivity (used by the config tab) ────────────────────
function nm_db_test($conn, int $id): array {
    $t = nm_db_target($conn, $id);
    if (!$t) return ['ok'=>false,'error'=>'Target not found'];
    // guard: direct transport needs the PDO driver present
    if (($t['transport'] ?? 'direct') === 'direct') {
        $caps = nm_db_transport_caps($t['engine']);
        if (!$caps['direct']) return ['ok'=>false,'error'=>$caps['direct_reason']];
    }
    try {
        $mon = nm_db_monitor($conn, $t);
        $p = $mon->probe();
        nm_db_set_status($conn, $id, 'ok', null, (string)($p['version'] ?? ''));
        return ['ok'=>true,'probe'=>$p];
    } catch (\Throwable $e) {
        $msg = $e->getMessage();
        nm_db_set_status($conn, $id, 'error', $msg, null);
        return ['ok'=>false,'error'=>$msg];
    }
}

// ── Schema drift: fingerprint nightly, diff vs last snapshot ─────────────────
function nm_db_schema_interval_h($conn): int {
    $h = 6;
    if ($r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='db_schema_interval_h' LIMIT 1"))
        if ($x = $r->fetch_row()) { $v=(int)$x[0]; if ($v>0) $h=$v; }
    return max(1, min(168, $h));
}
function nm_db_schema_diff(array $prev, array $now): array {
    $changes = [];
    foreach ($now as $k=>$v) {
        if (!array_key_exists($k,$prev)) $changes[] = ['kind'=>'added','item'=>$k,'to'=>$v];
        elseif ($prev[$k] !== $v)        $changes[] = ['kind'=>'changed','item'=>$k,'from'=>$prev[$k],'to'=>$v];
    }
    foreach ($prev as $k=>$v) if (!array_key_exists($k,$now)) $changes[] = ['kind'=>'removed','item'=>$k,'from'=>$v];
    return $changes;
}
/** Capture a schema snapshot if the last one is older than the interval (or $force). Records a drift event on change. */
function nm_db_schema_capture($conn, int $id, bool $force = false): array {
    nm_db_ensure($conn);
    $t = nm_db_target($conn, $id);
    if (!$t || !$t['enabled']) return ['ok'=>false,'skipped'=>'disabled'];
    // throttle
    $last = null;
    if ($r = $conn->query("SELECT id,schema_hash,items_json,captured_at FROM nm_db_schema_snap WHERE target_id=$id ORDER BY id DESC LIMIT 1"))
        $last = $r->fetch_assoc() ?: null;
    if (!$force && $last) {
        $ageH = (time() - strtotime($last['captured_at'])) / 3600.0;
        if ($ageH < nm_db_schema_interval_h($conn)) return ['ok'=>true,'skipped'=>'throttled'];
    }
    if (($t['transport'] ?? 'direct') === 'direct') { $caps = nm_db_transport_caps($t['engine']); if (!$caps['direct']) return ['ok'=>false,'error'=>$caps['direct_reason']]; }
    try {
        $items = nm_db_monitor($conn, $t)->fingerprintItems();
    } catch (\Throwable $e) { return ['ok'=>false,'error'=>$e->getMessage()]; }
    if (!$items) return ['ok'=>true,'skipped'=>'no-schema-scope'];   // e.g. MySQL target without a db_name
    ksort($items);
    $hash = sha1(json_encode($items));
    if ($last && $last['schema_hash'] === $hash) return ['ok'=>true,'changed'=>false];
    // store new snapshot
    $cnt = count($items); $json = json_encode($items);
    $st = $conn->prepare("INSERT INTO nm_db_schema_snap (target_id,schema_hash,item_count,items_json) VALUES (?,?,?,?)");
    $st->bind_param('isis', $id, $hash, $cnt, $json); $st->execute(); $st->close();
    if (!$last) return ['ok'=>true,'changed'=>false,'baseline'=>true];   // first capture = baseline, no drift
    // diff + drift event
    $prev = json_decode((string)$last['items_json'], true) ?: [];
    $changes = nm_db_schema_diff($prev, $items);
    if (!$changes) return ['ok'=>true,'changed'=>false];
    $a=$r2=0;$c=0; foreach ($changes as $ch){ if($ch['kind']==='added')$a++; elseif($ch['kind']==='removed')$r2++; else $c++; }
    $summary = trim(($a?"+$a ":'').($r2?"-$r2 ":'').($c?"~$c":'')) . ' (' . count($changes) . ' change' . (count($changes)>1?'s':'') . ')';
    $cj = json_encode($changes);
    $st = $conn->prepare("INSERT INTO nm_db_schema_drift (target_id,summary,changes_json) VALUES (?,?,?)");
    $st->bind_param('iss', $id, $summary, $cj); $st->execute(); $st->close();
    return ['ok'=>true,'changed'=>true,'summary'=>$summary,'changes'=>count($changes)];
}
function nm_db_schema_get($conn, int $id): array {
    nm_db_ensure($conn);
    $snap = null;
    if ($r = $conn->query("SELECT captured_at,schema_hash,item_count FROM nm_db_schema_snap WHERE target_id=$id ORDER BY id DESC LIMIT 1")) $snap = $r->fetch_assoc() ?: null;
    $drifts = [];
    if ($r = $conn->query("SELECT id,detected_at,summary,changes_json,acknowledged_at,acknowledged_by FROM nm_db_schema_drift WHERE target_id=$id ORDER BY id DESC LIMIT 20"))
        while ($x=$r->fetch_assoc()) { $x['changes']=json_decode((string)$x['changes_json'],true)?:[]; unset($x['changes_json']); $drifts[]=$x; }
    return ['ok'=>true,'snapshot'=>$snap,'drifts'=>$drifts];
}
/** Accept the current schema: mark this target's outstanding drift events as approved so they stop
 *  raising incidents. Returns the number of drift events accepted. */
function nm_db_schema_accept($conn, int $id, string $by = ''): int {
    nm_db_ensure($conn);
    $st = $conn->prepare("UPDATE nm_db_schema_drift SET acknowledged_at=NOW(), acknowledged_by=? WHERE target_id=? AND acknowledged_at IS NULL");
    $st->bind_param('si', $by, $id); $st->execute(); $n = $st->affected_rows; $st->close();
    return max(0, (int)$n);
}

// ── Advice (Index Archaeologist + Solution Center) ──────────────────────────
function nm_db_advice_list($conn, int $target, ?string $status = null): array {
    nm_db_ensure($conn);
    $w = "target_id=" . (int)$target . ($status ? " AND status='" . $conn->real_escape_string($status) . "'" : "");
    $out = [];
    $r = $conn->query("SELECT * FROM nm_db_advice WHERE $w ORDER BY FIELD(status,'proposed','applied','dismissed','failed'), FIELD(risk,'high','medium','low'), id DESC LIMIT 100");
    while ($r && ($x=$r->fetch_assoc())) $out[] = $x;
    return $out;
}
/** Insert/refresh an advice item (used by the n8n callback). De-dupes on (target,fingerprint). */
function nm_db_advice_add($conn, int $target, array $a): array {
    nm_db_ensure($conn);
    $kind = in_array(($a['kind']??'index'), ['index','maintenance','kill','config','other'], true) ? $a['kind'] : 'other';
    $risk = in_array(($a['risk']??'low'), ['low','medium','high'], true) ? $a['risk'] : 'low';
    $title=substr(trim((string)($a['title']??'Recommendation')),0,255);
    $rat  =(string)($a['rationale']??''); $ddl=(string)($a['ddl']??'');
    $ben  =substr((string)($a['benefit']??''),0,160); $src=substr((string)($a['source']??'ai'),0,12);
    $fp   =substr((string)($a['fingerprint'] ?? ($kind.':'.md5($ddl.$title))),0,120);
    $st=$conn->prepare("INSERT INTO nm_db_advice (target_id,kind,title,rationale,ddl,risk,benefit,source,fingerprint,status)
                        VALUES (?,?,?,?,?,?,?,?,?,'proposed')
                        ON DUPLICATE KEY UPDATE title=VALUES(title),rationale=VALUES(rationale),ddl=VALUES(ddl),risk=VALUES(risk),benefit=VALUES(benefit),
                        status=IF(status IN ('applied','dismissed'),status,'proposed')");
    $st->bind_param('issssssss',$target,$kind,$title,$rat,$ddl,$risk,$ben,$src,$fp); $st->execute(); $st->close();
    return ['ok'=>true];
}
function nm_db_advice_set_status($conn, int $id, string $status, ?string $result=null): void {
    $st=$conn->prepare("UPDATE nm_db_advice SET status=?, result=COALESCE(?,result) WHERE id=?");
    $st->bind_param('ssi',$status,$result,$id); $st->execute(); $st->close();
}
// SAFETY: only these statement shapes may ever be executed by "apply". DDL is never
// taken verbatim from the AI without this whitelist — no DROP/ALTER/DELETE/UPDATE/etc.
function nm_db_advice_allowed_sql(string $kind, string $sql): bool {
    $s = ltrim($sql);
    if ($kind === 'index')       return (bool)preg_match('/^CREATE\s+(UNIQUE\s+)?INDEX\s+/i', $s) && !preg_match('/;\s*\S/', $s);
    if ($kind === 'maintenance') return (bool)preg_match('/^(ANALYZE|OPTIMIZE\s+TABLE|VACUUM(\s+ANALYZE)?|REINDEX)\s/i', $s) && !preg_match('/;\s*\S/', $s);
    return false;   // config/kill/other are NOT auto-runnable as raw SQL
}
/** Apply an advice item (gated by the caller's RBAC). Returns ok/err. */
function nm_db_apply_advice($conn, int $id, ?int $uid=null): array {
    $r = $conn->query("SELECT * FROM nm_db_advice WHERE id=".(int)$id." LIMIT 1");
    $a = $r ? $r->fetch_assoc() : null;
    if (!$a) return ['ok'=>false,'error'=>'Advice not found'];
    if ($a['status']==='applied') return ['ok'=>false,'error'=>'Already applied'];
    $t = nm_db_target($conn, (int)$a['target_id']);
    if (!$t) return ['ok'=>false,'error'=>'Target gone'];
    if (!in_array($a['kind'], ['index','maintenance'], true))
        return ['ok'=>false,'error'=>'This recommendation must be applied by hand (only index/maintenance are auto-runnable).'];
    if (!nm_db_advice_allowed_sql($a['kind'], (string)$a['ddl']))
        return ['ok'=>false,'error'=>'Refused: the statement is not a safe '.$a['kind'].' operation.'];
    try {
        nm_db_monitor($conn, $t)->run((string)$a['ddl']);
        $st=$conn->prepare("UPDATE nm_db_advice SET status='applied', result='OK', applied_at=NOW(), applied_by=? WHERE id=?");
        $st->bind_param('ii',$uid,$id); $st->execute(); $st->close();
        return ['ok'=>true];
    } catch (\Throwable $e) {
        nm_db_advice_set_status($conn,$id,'failed',substr($e->getMessage(),0,300));
        return ['ok'=>false,'error'=>$e->getMessage()];
    }
}

// ── Replication monitor ──────────────────────────────────────────────────────
function nm_db_repl_lag($conn): array {
    $warn=30; $crit=300;
    if ($r=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='db_repl_lag_warn' LIMIT 1")) if($x=$r->fetch_row()){ $v=(int)$x[0]; if($v>0)$warn=$v; }
    if ($r=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='db_repl_lag_crit' LIMIT 1")) if($x=$r->fetch_row()){ $v=(int)$x[0]; if($v>0)$crit=$v; }
    return [$warn,$crit];
}
/** Capture a replica's SHOW REPLICA STATUS into nm_db_repl (called by the poller for role=replica). */
function nm_db_repl_capture($conn, int $id): array {
    $t = nm_db_target($conn, $id);
    if (!$t || ($t['role'] ?? 'standalone') !== 'replica') return ['ok'=>false,'skipped'=>'not-replica'];
    if (($t['transport'] ?? 'direct') === 'direct') { $c=nm_db_transport_caps($t['engine']); if(!$c['direct']) return ['ok'=>false,'error'=>$c['direct_reason']]; }
    try {
        $rep = nm_db_monitor($conn, $t)->replication();
        if (empty($rep['ok'])) return $rep;
        $io=$rep['io_running']?1:0; $sql=$rep['sql_running']?1:0; $sb=$rep['seconds_behind'];
        $err=substr((string)($rep['last_error']??''),0,400); $src=substr((string)($rep['source_host']??''),0,190);
        $st=$conn->prepare("INSERT INTO nm_db_repl (target_id,io_running,sql_running,seconds_behind,last_error,source_host) VALUES (?,?,?,?,?,?)");
        $st->bind_param('iiiiss',$id,$io,$sql,$sb,$err,$src); $st->execute(); $st->close();
        return ['ok'=>true,'io'=>$io,'sql'=>$sql,'behind'=>$sb];
    } catch (\Throwable $e) { return ['ok'=>false,'error'=>$e->getMessage()]; }
}
/** Live replication status for the UI: the replica's state + (if linked) its master + GTID gap. */
function nm_db_repl_status($conn, int $id): array {
    $t = nm_db_target($conn, $id); if (!$t) return ['ok'=>false,'error'=>'Target not found'];
    if (($t['transport'] ?? 'direct') === 'direct') { $c=nm_db_transport_caps($t['engine']); if(!$c['direct']) return ['ok'=>false,'error'=>$c['direct_reason']]; }
    [$warn,$crit] = nm_db_repl_lag($conn);
    try {
        $self = nm_db_monitor($conn, $t)->replication();
        $master = null; $gtidGap = null;
        $mid = (int)($t['replica_of'] ?? 0);
        if ($mid) { $mt = nm_db_target($conn, $mid);
            if ($mt && (($mt['transport']??'direct')!=='direct' || nm_db_transport_caps($mt['engine'])['direct'])) {
                try { $master = nm_db_monitor($conn,$mt)->replication(); $master['name']=$mt['display_name']; } catch (\Throwable $e) { $master=['ok'=>false,'error'=>$e->getMessage()]; }
            }
        }
        return ['ok'=>true,'role'=>$t['role']??'standalone','replica_of'=>$mid?:null,'self'=>$self,'master'=>$master,
                'lag_warn'=>$warn,'lag_crit'=>$crit,'name'=>$t['display_name']];
    } catch (\Throwable $e) { return ['ok'=>false,'error'=>$e->getMessage()]; }
}
/** Per-table row drift master↔replica. Estimate for all tables; exact COUNT(*) for one table on demand. */
function nm_db_repl_drift($conn, int $replicaId, ?string $exactTable = null): array {
    $rep = nm_db_target($conn, $replicaId); if (!$rep) return ['ok'=>false,'error'=>'Replica not found'];
    $mid = (int)($rep['replica_of'] ?? 0); $mas = $mid ? nm_db_target($conn, $mid) : null;
    if (!$mas) return ['ok'=>false,'error'=>'No master linked — set "Replica of" in the database config.'];
    foreach ([$rep,$mas] as $t) if (($t['transport']??'direct')==='direct') { $c=nm_db_transport_caps($t['engine']); if(!$c['direct']) return ['ok'=>false,'error'=>$c['direct_reason']]; }
    try {
        $mMon = nm_db_monitor($conn,$mas); $rMon = nm_db_monitor($conn,$rep);
        if ($exactTable !== null) {
            $mc=$mMon->tableCount($exactTable); $rc=$rMon->tableCount($exactTable);
            return ['ok'=>true,'exact'=>true,'table'=>$exactTable,'master_rows'=>$mc,'replica_rows'=>$rc,'delta'=>($mc!==null&&$rc!==null)?($mc-$rc):null];
        }
        $m=$mMon->tableRows(); $r=$rMon->tableRows();
        $names=array_unique(array_merge(array_keys($m),array_keys($r))); sort($names);
        // InnoDB information_schema row counts are ESTIMATES and are unreliable at EVERY size (they
        // faked drift like COMMTYPE 3→0 when both hold 3, and ±44 on 1k-row tables that actually match).
        // So verify every table that LOOKS like it drifts with an exact COUNT(*) — cheapest first, within
        // a total row budget + count cap so one monster table can't stall the compare. Only tables that
        // don't fit the budget fall back to the estimate (+ the manual "exact" button).
        $rows=[];
        foreach ($names as $tn) $rows[$tn]=['table'=>$tn,'master_rows'=>$m[$tn]??null,'replica_rows'=>$r[$tn]??null,'exact'=>false];
        $PER_TABLE_MAX = 3000000;   // never auto-COUNT(*) an individually huge table
        $BUDGET        = 8000000;   // total estimated rows we'll COUNT(*) in one compare
        $AUTO_CAP      = 250;       // and never more than this many tables
        $cand=[];
        foreach ($rows as $tn=>$row) {
            $mr=$row['master_rows']; $rr=$row['replica_rows'];
            if ($mr===null || $rr===null || (int)$mr !== (int)$rr) $cand[$tn]=max((int)$mr,(int)$rr);  // looks like drift
        }
        asort($cand);   // cheapest (smallest estimate) first
        $spent=0; $toCount=[];
        foreach ($cand as $tn=>$estSize) {
            if (count($toCount) >= $AUTO_CAP) break;
            if ($estSize > $PER_TABLE_MAX || $spent + $estSize > $BUDGET) continue;  // too big / over budget — keep estimate
            $toCount[] = $tn; $spent += max(1, $estSize);
        }
        $autoDone = 0;
        if ($toCount) {
            // ONE batched UNION ALL query per side (not a round-trip per table → no more hanging compare)
            $mc = $mMon->tableCounts($toCount);
            $rc = $rMon->tableCounts($toCount);
            foreach ($toCount as $tn) {
                if (($mc[$tn] ?? null) !== null) $rows[$tn]['master_rows'] = $mc[$tn];
                if (($rc[$tn] ?? null) !== null) $rows[$tn]['replica_rows'] = $rc[$tn];
                $rows[$tn]['exact'] = (($mc[$tn] ?? null) !== null && ($rc[$tn] ?? null) !== null);
                if ($rows[$tn]['exact']) $autoDone++;
            }
        }
        $tables=[]; $drift=0; $estLeft=0;
        foreach ($rows as $row) {
            $mr=$row['master_rows']; $rr=$row['replica_rows']; $miss=($mr===null||$rr===null);
            $d=($mr!==null&&$rr!==null)?($mr-$rr):null; if($miss||($d!==null&&$d!==0)) $drift++;
            if(!$row['exact'] && $d!==null && $d!==0) $estLeft++;   // still-estimated tables that show a delta
            $tables[]=['table'=>$row['table'],'master_rows'=>$mr,'replica_rows'=>$rr,'delta'=>$d,'missing'=>$miss,'exact'=>$row['exact']];
        }
        $note = "{$autoDone} table(s) verified with exact COUNT(*) (✓).";
        if ($estLeft) $note .= " {$estLeft} large table(s) still show storage-engine ESTIMATES — hit “exact” to confirm.";
        return ['ok'=>true,'exact'=>false,'tables'=>$tables,'drift_count'=>$drift,'auto_exact'=>$autoDone,
                'master'=>$mas['display_name'],'replica'=>$rep['display_name'],'note'=>$note];
    } catch (\Throwable $e) { return ['ok'=>false,'error'=>$e->getMessage()]; }
}

// ── Poller (cron_dbmon.php → curl→localhost, web-context so secrets decrypt) ──
function nm_db_poll_all($conn): array {
    nm_db_ensure($conn);
    $out = [];
    foreach (nm_db_targets($conn) as $t) {
        $id = (int)$t['id'];
        if (!$t['enabled']) { $out[$id]='disabled'; continue; }
        $full = nm_db_target($conn, $id);            // with password_enc
        if (!$full) { $out[$id]='gone'; continue; }
        if (($full['transport'] ?? 'direct') === 'direct') {
            $caps = nm_db_transport_caps($full['engine']);
            if (!$caps['direct']) { nm_db_set_status($conn,$id,'error',$caps['direct_reason'],null); $out[$id]='no-driver'; continue; }
        }
        try {
            $mon  = nm_db_monitor($conn, $full);
            $p    = $mon->probe();
            $live = $mon->live();
            $blocked = is_array($live['locks'] ?? null) ? count($live['locks']) : 0;
            $slow    = is_array($live['slow']  ?? null) ? count($live['slow'])  : 0;
            $c=(int)($p['connections']??0); $m=(int)($p['max_connections']??0); $tr=(int)($p['threads_running']??0); $up=(int)($p['uptime_s']??0);
            $st = $conn->prepare("INSERT INTO nm_db_samples (target_id,connections,max_connections,threads_running,uptime_s,blocked,slow) VALUES (?,?,?,?,?,?,?)");
            $st->bind_param('iiiiiii', $id,$c,$m,$tr,$up,$blocked,$slow); $st->execute(); $st->close();
            nm_db_set_status($conn,$id,'ok',null,(string)($p['version']??''));
            $out[$id] = "ok (c=$c blk=$blocked slow=$slow)";
        } catch (\Throwable $e) {
            nm_db_set_status($conn,$id,'error',$e->getMessage(),null);
            $out[$id] = 'error: ' . substr($e->getMessage(),0,80);
        }
    }
    return $out;
}
function nm_db_prune($conn, int $days = 14): void {
    nm_db_ensure($conn);
    $d = max(1,$days);
    $conn->query("DELETE FROM nm_db_samples WHERE sampled_at < (NOW() - INTERVAL {$d} DAY)");
    $conn->query("DELETE FROM nm_db_repl    WHERE sampled_at < (NOW() - INTERVAL {$d} DAY)");
}

} // end function_exists guard
