<?php
$pdo = new PDO('mysql:host=db;dbname=shop', 'app', 'secret');
$rows = $pdo->query("SELECT * FROM products WHERE id = " . $_GET['id'])->fetchAll(); // vuln
