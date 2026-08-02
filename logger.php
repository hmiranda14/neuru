<?php
function log_user_action($conn, $action_type, $action_details = null) {
    if (!isset($_SESSION['username'])) return;

    $username = $_SESSION['username'];
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';

    $stmt = $conn->prepare("INSERT INTO user_action_log (username,action_type,action_details,ip_address,user_agent) VALUES (?,?,?,?,?)");
    $stmt->bind_param("sssss", $username, $action_type, $action_details, $ip, $ua);
    $stmt->execute();
}

function log_query_action($conn, $query, $page = '') {
    $safe_query = substr($query, 0, 1000);
    $details = "Query on $page: $safe_query";
    log_user_action($conn, 'query_exec', $details);
}

function logActivity($conn, $operation, $table, $record_id, $description) {
    if (!isset($_SESSION['username'])) return;

    $username  = $_SESSION['username'];
    $ip        = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $timestamp = date('Y-m-d H:i:s');

    try {
        $stmt = $conn->prepare("INSERT INTO activity_log (username,operation,table_name,record_id,description,ip_address,timestamp) VALUES (?,?,?,?,?,?,?)");
        if ($stmt) {
            $stmt->bind_param("sssisss", $username, $operation, $table, $record_id, $description, $ip, $timestamp);
            $stmt->execute();
            $stmt->close();
        }
    } catch (Exception $e) {
        // silently ignore
    }
}
?>
