<?php
$conn = mysqli_connect('db', 'app', 'secret', 'shop');
$stmt = mysqli_prepare($conn, 'SELECT * FROM users WHERE email = ?');
mysqli_stmt_bind_param($stmt, 's', $_POST['email']);
mysqli_stmt_execute($stmt);
