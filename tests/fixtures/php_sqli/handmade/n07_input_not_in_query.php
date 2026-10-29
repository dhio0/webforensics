<?php
$pdo = new PDO('sqlite::memory:');
$rows = $pdo->query('SELECT * FROM products ORDER BY id')->fetchAll();
echo htmlspecialchars($_GET['q'] ?? '', ENT_QUOTES, 'UTF-8');
