<?php
global $wpdb;
$search = $_GET['s'];
$posts = $wpdb->get_results("SELECT * FROM wp_posts WHERE post_title LIKE '%" . $search . "%'"); // vuln
