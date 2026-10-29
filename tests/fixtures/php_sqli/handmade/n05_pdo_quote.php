<?php
$pdo = new PDO('sqlite::memory:');
$pdo->query('SELECT * FROM users WHERE name = ' . $pdo->quote($_GET['name']));
