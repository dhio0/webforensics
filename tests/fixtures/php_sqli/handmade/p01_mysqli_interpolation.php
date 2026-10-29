<?php
$conn = mysqli_connect('db', 'app', 'secret', 'shop');
$name = $_POST['name'];
$sql = "SELECT * FROM users WHERE name = '$name'"; // vuln
$result = mysqli_query($conn, $sql);
