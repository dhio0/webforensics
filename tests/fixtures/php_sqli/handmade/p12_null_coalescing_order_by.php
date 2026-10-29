<?php
$pdo = new PDO('sqlite::memory:');
$sort = $_GET['sort'] ?? 'id';
$rows = $pdo->query("SELECT * FROM products ORDER BY $sort")->fetchAll(); // vuln
