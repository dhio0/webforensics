<?php
$conn = mysqli_connect('db', 'app', 'secret', 'shop');
$id = mysqli_real_escape_string($conn, $_GET['id']);
mysqli_query($conn, "SELECT * FROM posts WHERE id = $id"); // vuln
