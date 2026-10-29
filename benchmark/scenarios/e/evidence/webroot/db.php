<?php
$dsn = sprintf(
    'mysql:host=%s;dbname=%s;charset=utf8mb4',
    getenv('DB_HOST'),
    getenv('DB_NAME')
);
$pdo = new PDO($dsn, getenv('DB_USER'), getenv('DB_PASSWORD'));
