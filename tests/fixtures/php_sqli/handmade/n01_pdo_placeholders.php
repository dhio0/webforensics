<?php
$pdo = new PDO('sqlite::memory:');
$stmt = $pdo->prepare('SELECT * FROM products WHERE id = ?');
$stmt->execute([$_GET['id']]);
