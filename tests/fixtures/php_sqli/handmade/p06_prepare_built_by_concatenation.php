<?php
$pdo = new PDO('sqlite::memory:');
$stmt = $pdo->prepare("SELECT * FROM users WHERE email = '" . $_POST['email'] . "'"); // vuln
$stmt->execute();
