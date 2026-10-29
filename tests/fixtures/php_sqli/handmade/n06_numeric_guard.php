<?php
$pdo = new PDO('sqlite::memory:');
$id = $_GET['id'];
if (!ctype_digit($id)) {
    http_response_code(400);
    exit;
}
$pdo->query("SELECT * FROM products WHERE id = $id");
