<?php
// NEURU-in-a-Box — federation slave enrolment (optional). Called on first boot ONLY when
// this NEURU was DEPLOYED FROM a parent NEURU (which passed its master URL + token). A
// standalone install never calls this. Registers this instance as a Federation slave of the
// parent so the router/edge NEURU reports up into the deploying NEURU's distributed NOC.
//   argv: <master_url> <master_token> <slave_name>
// Best-effort: logs + exits 0 on any failure so it never blocks the boot.
$master = rtrim((string)($argv[1] ?? ''), '/');
$token  = (string)($argv[2] ?? '');
$name   = (string)($argv[3] ?? gethostname());
if ($master === '' || $token === '') { fwrite(STDERR, "federate: missing master/token\n"); exit(0); }

// local identity for the master to reach back
$ip = trim((string)@shell_exec("ip -o -4 addr show 2>/dev/null | awk '{print \$4}' | grep -vE '^127|^172.1[78]' | head -1"));
$ip = explode('/', $ip)[0] ?: '';

$payload = json_encode(['name'=>$name, 'ip'=>$ip, 'role'=>'slave', 'kind'=>'neuru-box',
                        'version'=>@trim((string)@file_get_contents(__DIR__.'/../../VERSION'))]);

$ch = curl_init($master.'/federation.php?api=slave_enroll');
curl_setopt_array($ch, [
    CURLOPT_POST=>true, CURLOPT_POSTFIELDS=>$payload, CURLOPT_RETURNTRANSFER=>true, CURLOPT_TIMEOUT=>20,
    CURLOPT_SSL_VERIFYPEER=>false, CURLOPT_SSL_VERIFYHOST=>0,
    CURLOPT_HTTPHEADER=>['Content-Type: application/json', 'X-Neuru-Fed-Token: '.$token],
]);
$res = curl_exec($ch); $code = curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
echo date('c')." federate → master=$master code=$code res=".substr((string)$res,0,200)."\n";

// Also record locally so this instance knows its master (best-effort; the app's own
// federation tables self-heal on first page load).
try {
    require __DIR__.'/../../connection.php';
    @$conn->query("INSERT INTO nm_settings(setting_key,setting_val) VALUES('federation_master_url','".$conn->real_escape_string($master)."') ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)");
    @$conn->query("INSERT INTO nm_settings(setting_key,setting_val) VALUES('federation_role','slave') ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)");
} catch (\Throwable $e) {}
exit(0);
