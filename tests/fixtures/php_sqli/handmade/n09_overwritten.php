<?php
$pdo = new PDO('sqlite::memory:');
$limit = $_GET['limit'];
$limit = 20;
$pdo->query("SELECT * FROM posts LIMIT $limit");
