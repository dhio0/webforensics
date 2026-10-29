<?php
$pdo = new PDO('sqlite::memory:');
foreach ($_POST as $column => $value) {
    $pdo->exec("UPDATE settings SET $column = '$value'"); // vuln
}
