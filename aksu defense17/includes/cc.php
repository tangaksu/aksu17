<?php
// aksu defense - CC攻击防护模块
if (!defined('ABSPATH')) exit;

if (!function_exists('aksu_cc_defend')) {
    function aksu_cc_defend() {
        // ====== 全局白名单豁免 ======
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $white = get_option('wpss_ip_whitelist', '');
        $white_arr = array_filter(array_map('trim', preg_split('/[\n,]+/', $white)));
        foreach ($white_arr as $w) {
            if (function_exists('aksu_ip_match') && aksu_ip_match($ip, $w)) {
                return; // 命中白名单，直接放行
            }
        }
        // ===========================

        // 新增：自定义白名单IP（如需可自行添加公网IP）
        $whitelist = ['127.0.0.1']; // 本地测试IP，可按需添加

        if (in_array($ip, $whitelist)) return;

        // 管理员豁免：已登录且为管理员账号直接放行
        if (function_exists('is_user_logged_in') && function_exists('current_user_can')) {
            if (is_user_logged_in() && current_user_can('manage_options')) return;
        }

        // ---- 后台页面豁免CC防护 ----
        if (
            (isset($_SERVER['REQUEST_URI']) && strpos($_SERVER['REQUEST_URI'], '/wp-admin/') === 0)
            || (isset($_SERVER['REQUEST_URI']) && strpos($_SERVER['REQUEST_URI'], '/wp-login.php') !== false)
        ) {
            return;
        }
        // ---- 结束 ----

        if (!get_option('wpss_fw_cc_status', 1)) return;

        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $referer = $_SERVER['HTTP_REFERER'] ?? '';
        $host = $_SERVER['HTTP_HOST'] ?? '';
        $req_uri = $_SERVER['REQUEST_URI'] ?? '';
        // 优化：key仅用IP，避免站群/多域名交叉影响
        $key = 'aksu_cc_' . md5($ip);

        // 配置参数
        $limit = intval(get_option('wpss_cc_limit', 60));     // 单位周期最大请求数
        $period = intval(get_option('wpss_cc_period', 60));   // 统计周期(秒)
        $blocktime = intval(get_option('wpss_cc_blocktime', 1800)); // 封禁时长(秒)

        // 大数据增强：常见CC攻击特征拦截
        $dangerous_ua_patterns = [
            '/curl/i', '/wget/i', '/python-requests/i', '/httpclient/i', '/scrapy/i', '/go-http-client/i', '/lwp::simple/i', '/okhttp/i'
        ];
        $dangerous_uri_patterns = [
            '/(admin|login|wp-login|xmlrpc)\.php/i', // 针对敏感页面的爆破
            '/\?id=\d+/i', '/\?p=\d+/i', // 带有参数的爆破
        ];

        // 1. 检查危险UA特征
        foreach ($dangerous_ua_patterns as $pattern) {
            if (preg_match($pattern, $ua)) {
                if (function_exists('wpss_log')) wpss_log('cc', "可疑UA特征CC拦截: $ip $ua");
                aksu_defense_die('CC攻击检测，疑似恶意请求', null, [], 'cc');
            }
        }

        // 2. 检查危险URI特征
        foreach ($dangerous_uri_patterns as $pattern) {
            if (preg_match($pattern, $req_uri)) {
                if (function_exists('wpss_log')) wpss_log('cc', "敏感URI特征CC拦截: $ip $req_uri");
                aksu_defense_die('CC攻击检测，疑似爆破', null, [], 'cc');
            }
        }

        // 3. CC限速统计
        $now = time();
        $cc_data = get_transient($key);
        if (!$cc_data || !is_array($cc_data)) {
            $cc_data = ['count' => 1, 'start' => $now, 'block' => 0];
        } else {
            // 检查是否已在封禁期
            if (!empty($cc_data['block']) && $cc_data['block'] > $now) {
                if (function_exists('wpss_log')) wpss_log('cc', "CC限制封禁期内拦截: $ip");
                aksu_defense_die('疑似CC攻击，已临时封禁', null, [], 'cc');
            }

            // 统计周期内计数
            if (($now - $cc_data['start']) <= $period) {
                $cc_data['count']++;
                if ($cc_data['count'] > $limit) {
                    // 触发封禁
                    $cc_data['block'] = $now + $blocktime;
                    set_transient($key, $cc_data, $blocktime);
                    if (function_exists('wpss_log')) wpss_log('cc', "CC超限封禁: $ip");
                    aksu_defense_die('您操作过于频繁，请稍后再试', null, [], 'cc');
                }
            } else {
                // 新周期
                $cc_data = ['count' => 1, 'start' => $now, 'block' => 0];
            }
        }
        // 保存数据
        set_transient($key, $cc_data, max($period, $blocktime));
    }
}