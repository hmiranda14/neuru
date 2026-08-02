<?php
$host     = '__DB_HOST__';
$dbname   = '__DB_NAME__';
$username = '__DB_USER__';
$password = '__DB_PASS__';

$conn = new mysqli($host, $username, $password, $dbname);
if ($conn->connect_error) {
    die('Database connection failed: ' . $conn->connect_error);
}
$conn->set_charset('utf8mb4');
