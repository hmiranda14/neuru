<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU readiness probe. Returns 200 + JSON when the platform is fully up:
//   Apache serving + database reachable + the schema imported (core tables present).
// Used by the containers.php deploy progress banner (and by monitoring) to know when a
// freshly-deployed NEURU (Docker / MikroTik container) has finished initializing.
// No auth on purpose — it exposes ONLY liveness booleans, never data.
// ─────────────────────────────────────────────────────────────────────────────
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

$out = ['ok'=>false,'apache'=>true,'db'=>false,'schema'=>false,'version'=>null,'stage'=>'starting'];
$out['version'] = @trim((string)@file_get_contents(__DIR__.'/VERSION')) ?: null;

try {
    // connect via the same generated config; if it's not there yet, we're still initializing
    if (!is_file(__DIR__.'/connection.php')) { $out['stage']='no-config'; echo json_encode($out); exit; }
    $host='127.0.0.1'; $user='sisuser'; $pass='sispass'; $db='netmon';
    // read the real params from connection.php without executing its side effects
    $src = @file_get_contents(__DIR__.'/connection.php');
    if ($src) {
        if (preg_match('/\$host\s*=\s*\'([^\']*)\'/',$src,$m))     $host=$m[1];
        if (preg_match('/\$dbname\s*=\s*\'([^\']*)\'/',$src,$m))   $db=$m[1];
        if (preg_match('/\$username\s*=\s*\'([^\']*)\'/',$src,$m)) $user=$m[1];
        if (preg_match('/\$password\s*=\s*\'([^\']*)\'/',$src,$m)) $pass=$m[1];
    }
    mysqli_report(MYSQLI_REPORT_OFF);
    $c = @new mysqli($host,$user,$pass,$db);
    if ($c && !$c->connect_error) {
        $out['db']=true; $out['stage']='db-up';
        $r = @$c->query("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='".$c->real_escape_string($db)."'");
        $n = ($r && ($x=$r->fetch_row())) ? (int)$x[0] : 0;
        if ($n >= 50) { $out['schema']=true; $out['tables']=$n; $out['stage']='ready'; $out['ok']=true; }
        else { $out['tables']=$n; $out['stage']='importing-schema'; }
        $c->close();
    } else { $out['stage']='starting-database'; }
} catch (\Throwable $e) { $out['stage']='starting'; }

http_response_code($out['ok'] ? 200 : 503);
echo json_encode($out);
