<?php
$mysqli = new mysqli('db', 'app', 'secret', 'shop');
$login = trim($_POST['login']);
$res = $mysqli->query("SELECT id FROM users WHERE login = '$login'"); // vuln
