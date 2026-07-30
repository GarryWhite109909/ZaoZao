<?php
// 反射型 XSS：用户输入直接 echo
$name = $_GET['name'] ?? '';
echo "<html><body><h1>Welcome, " . $name . "!</h1></body></html>";
