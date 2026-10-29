<?php
$conn = mysqli_connect('db', 'app', 'secret', 'shop');
$name = mysqli_real_escape_string($conn, $_POST['name']);
mysqli_query($conn, "SELECT * FROM users WHERE name = '$name'");
