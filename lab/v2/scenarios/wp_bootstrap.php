<?php
declare(strict_types=1);

$bootstrap_complete = false;
register_shutdown_function(function () use (&$bootstrap_complete): void {
    if (!$bootstrap_complete) {
        fwrite(STDERR, "WordPress bootstrap did not complete\n");
        exit(1);
    }
});

define('WP_INSTALLING', true);
require '/var/www/html/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/upgrade.php';

if (!is_blog_installed()) {
    wp_install(
        'Benchmark v2 pilot',
        getenv('BENCH_ADMIN_USER') ?: 'benchadmin',
        getenv('BENCH_ADMIN_EMAIL') ?: 'benchadmin@example.invalid',
        true,
        '',
        getenv('BENCH_ADMIN_PASSWORD') ?: ''
    );
}

require_once ABSPATH . 'wp-admin/includes/plugin.php';
$result = activate_plugin('wp-file-manager/file_folder_manager.php');
if (is_wp_error($result)) {
    fwrite(STDERR, $result->get_error_message() . "\n");
    exit(1);
}
$bootstrap_complete = true;
echo "wordpress_installed_and_plugin_activated\n";
