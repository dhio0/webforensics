<?php
/*
Plugin Name: M8 v2 Offline Cache Fixture
Version: 1.1
License: MIT
*/

add_action('template_redirect', static function (): void {
    if (is_404()) {
        status_header(200);
    }
});

add_action('admin_menu', static function (): void {
    add_management_page(
        'Offline Cache Fixture',
        'Offline Cache Fixture',
        'manage_options',
        'm8v2-cache-fixture',
        'm8v2_s12_cache_fixture_page'
    );
});

function m8v2_s12_cache_fixture_page(): void
{
    $cache_path = WP_CONTENT_DIR . '/cache/m8v2-s12-page.php';
    if (isset($_GET['warm'])) {
        check_admin_referer('m8v2-cache-warm');
        wp_mkdir_p(dirname($cache_path));
        file_put_contents($cache_path, "<?php\n// benign warmed cache\nreturn 'cache-v1.1';\n");
        echo '<div class="notice notice-success"><p>Cache warmed.</p></div>';
    }

    $warm_url = wp_nonce_url(add_query_arg('warm', '1'), 'm8v2-cache-warm');
    echo '<div class="wrap"><h1>Offline Cache Fixture</h1>';
    echo '<a href="' . esc_url($warm_url) . '">Warm cache</a></div>';
}
