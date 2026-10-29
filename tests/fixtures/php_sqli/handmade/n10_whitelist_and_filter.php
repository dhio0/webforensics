<?php
$pdo = new PDO('sqlite::memory:');
$sort = $_GET['sort'] ?? 'id';
if (!in_array($sort, ['id', 'name', 'price'], true)) {
    exit('bad sort');
}
$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
$pdo->query("SELECT * FROM products WHERE id = $id ORDER BY $sort");
