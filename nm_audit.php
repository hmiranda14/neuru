<?php
// ─────────────────────────────────────────────────────────────────────────────
// NetMon — unified audit logging. One structured row per security-relevant event
// in nm_audit_log. Never throws; auditing must never break the app.
//
//   nm_audit($conn, 'node.update', [
//       'target_type' => 'node', 'target_id' => 5,
//       'status'      => 'ok',            // ok | denied | failure | error
//       'details'     => ['field'=>'snmp_community'],   // array → JSON, or string
//   ]);
// ─────────────────────────────────────────────────────────────────────────────

if (!function_exists('nm_audit')) {
    function nm_audit($conn, string $action, array $o = []): void {
        if (!($conn instanceof mysqli)) return;

        $username = $o['username']    ?? ($_SESSION['username'] ?? null);
        $role     = $o['role']        ?? ($_SESSION['role']     ?? null);
        $ttype    = $o['target_type'] ?? null;
        $tid      = isset($o['target_id']) ? (string)$o['target_id'] : null;
        $status   = $o['status']      ?? 'ok';
        $details  = $o['details']     ?? null;
        if (is_array($details)) {
            $details = json_encode($details, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        }
        if (is_string($details) && strlen($details) > 4000) {
            $details = substr($details, 0, 4000) . '…';
        }

        $method = $_SERVER['REQUEST_METHOD'] ?? null;
        $uri    = isset($_SERVER['REQUEST_URI'])     ? substr($_SERVER['REQUEST_URI'], 0, 255)     : null;
        $ip     = $_SERVER['REMOTE_ADDR'] ?? null;
        $ua     = isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 255) : null;

        try {
            $st = $conn->prepare(
                "INSERT INTO nm_audit_log
                 (username, role, action, target_type, target_id, status, details, method, uri, ip, user_agent)
                 VALUES (?,?,?,?,?,?,?,?,?,?,?)"
            );
            if ($st) {
                $st->bind_param('sssssssssss',
                    $username, $role, $action, $ttype, $tid, $status, $details, $method, $uri, $ip, $ua);
                $st->execute();
                $st->close();
            }
        } catch (\Throwable $e) {
            // swallow — auditing must never interrupt a request
        }
    }
}
