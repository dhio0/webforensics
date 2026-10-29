<?php
$conn = mysqli_connect('db', 'app', 'secret', 'shop');
$id = intval($_GET['id']);
mysqli_query($conn, "SELECT * FROM posts WHERE id = $id");
