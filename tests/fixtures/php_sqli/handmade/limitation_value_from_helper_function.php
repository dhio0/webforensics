<?php
// limitation: calls are not followed, so input returned by a helper is not seen.
function param($key) { return $_GET[$key]; }
$pdo = new PDO('sqlite::memory:');
$pdo->query("SELECT * FROM products WHERE id = " . param('id')); // vuln
