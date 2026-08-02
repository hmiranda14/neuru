<?php
$host2     = '__DB_HOST__';
$dbname2   = '__DB_NAME__';
$username2 = '__DB_USER__';
$password2 = '__DB_PASS__';

$conn2 = new mysqli($host2, $username2, $password2, $dbname2);
if ($conn2->connect_error) {
    die('User DB connection failed: ' . $conn2->connect_error);
}
$conn2->set_charset('utf8mb4');
