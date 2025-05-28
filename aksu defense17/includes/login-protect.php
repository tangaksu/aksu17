<?php
if (!defined('ABSPATH')) exit;

// 登录入口安全防护功能
function aksu_login_protect() {
    $enabled = get_option('wpss_fw_loginprotect_status', 1);
    $http_code = intval(get_option('wpss_fw_loginprotect_code', 403));
    $custom_slug = get_option('wpss_custom_login_slug', 'my-login');
    $extra_param = get_option('wpss_login_extra_param', '');
    $extra_value = get_option('wpss_login_extra_value', '');

    if (!$enabled) return;

    if (isset($_SERVER['SCRIPT_NAME']) && basename($_SERVER['SCRIPT_NAME']) === 'wp-login.php') {
        // 检查自定义slug
        $matched_slug = false;
        if ($custom_slug && isset($_GET[$custom_slug])) $matched_slug = true;
        if (!$matched_slug) aksu_login_deny($http_code);

        // 检查附加参数
        if ($extra_param && $extra_value) {
            if (!isset($_GET[$extra_param]) || trim($_GET[$extra_param]) !== $extra_value) {
                aksu_login_deny($http_code);
            }
        }
    }
}

function aksu_login_deny($code = 403) {
    status_header($code);
    wp_die(
        '<h1>非法访问</h1><p>当前登录入口已被安全保护，请使用正确的登录方式访问。</p>',
        '安全防护'
    );
    exit;
}

add_action('init', 'aksu_login_protect', 1);