<?php
$pdo = new PDO('sqlite::memory:');
$user = $_GET['user'];
$sql = <<<SQL
SELECT * FROM profiles
WHERE username = '$user'
SQL; // vuln@6
$pdo->query($sql);
