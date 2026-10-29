<?php
$pdo = new PDO('sqlite::memory:');
$page = (int) ($_GET['page'] ?? 1);
$pdo->query('SELECT * FROM posts LIMIT 10 OFFSET ' . ($page * 10));
