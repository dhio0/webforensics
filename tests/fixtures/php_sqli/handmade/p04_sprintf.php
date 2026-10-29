<?php
$conn = mysqli_connect('db', 'app', 'secret', 'shop');
$query = sprintf("DELETE FROM carts WHERE id = %s",
    $_REQUEST['cart']); // vuln
mysqli_query($conn, $query);
