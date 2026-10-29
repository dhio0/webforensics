<?php
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit;
}

$page = (int)($_POST['page'] ?? 1);
$path = __DIR__ . '/cache/page-' . max(1, $page) . '.php';
$html = "<!doctype html>\n<html><body><p>Cached community comments</p></body></html>\n";
if (file_put_contents($path, $html) === false) {
    http_response_code(500);
    exit;
}
echo 'Comment accepted';
