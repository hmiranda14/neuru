<?php
session_start();
include("connection.php");
require_once __DIR__ . '/nm_audit.php';

function logUserAction($conn, $username, $actionType, $details = '') {
    if (!$conn) return;
    $ip    = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    $stmt  = $conn->prepare("INSERT INTO user_action_log (username,action_type,action_details,ip_address,user_agent) VALUES (?,?,?,?,?)");
    if ($stmt) {
        $stmt->bind_param("sssss", $username, $actionType, $details, $ip, $agent);
        $stmt->execute();
        $stmt->close();
    }
}

if (isset($_SESSION['username'])) {
    logUserAction($conn, $_SESSION['username'], 'logout', 'User logged out');
    nm_audit($conn, 'auth.logout', ['target_type' => 'user', 'target_id' => $_SESSION['UID'] ?? null]);
}

session_unset();
session_destroy();
header("Location: index.php");
exit;
?>
