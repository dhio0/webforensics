<?php
$pdo = new PDO('sqlite::memory:');
$sql = "SELECT * FROM orders WHERE 1 = 1";
if (isset($_GET['customer'])) {
    $sql .= " AND customer = '" . $_GET['customer'] . "'"; // vuln
}
$pdo->query($sql);
