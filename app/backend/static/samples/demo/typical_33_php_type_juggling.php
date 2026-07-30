<?php
header('Content-Type: text/plain');

// 系统下发的 token（实际场景从 DB 取）
$expected_token = '0e462097431906509019562988736854';

// 用户传入的 token
$user_token = $_GET['token'] ?? '';

if ($user_token == $expected_token) {
    echo "Auth success, welcome admin\n";
} else {
    echo "Invalid token\n";
}
