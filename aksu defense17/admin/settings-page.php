<?php
if (!defined('ABSPATH')) exit;

// 插件基础设置页面（含IP黑白名单、自定义登录设置）
function aksu_settings_page() {
    if (isset($_POST['wpss_settings_save']) && check_admin_referer('wpss_settings')) {
        update_option('wpss_admin_email', sanitize_email($_POST['wpss_admin_email']));
        update_option('wpss_ip_whitelist', trim($_POST['wpss_ip_whitelist']));
        update_option('wpss_ip_blacklist', trim($_POST['wpss_ip_blacklist']));
        update_option('wpss_custom_login_slug', sanitize_text_field($_POST['wpss_custom_login_slug']));
        update_option('wpss_login_extra_param', sanitize_text_field($_POST['wpss_login_extra_param']));
        update_option('wpss_login_extra_value', sanitize_text_field($_POST['wpss_login_extra_value']));
        echo '<div class="updated"><p>基础设置已保存。</p></div>';
    }
    $white = get_option('wpss_ip_whitelist', '');
    $black = get_option('wpss_ip_blacklist', '');
    $custom_login_slug = get_option('wpss_custom_login_slug', 'my-login');
    $login_extra_param = get_option('wpss_login_extra_param', '');
    $login_extra_value = get_option('wpss_login_extra_value', '');
    ?>
    <div class="wrap">
        <h1>插件设置</h1>
        <form method="post">
            <?php wp_nonce_field('wpss_settings'); ?>
            <table class="form-table">
                <tr>
                    <th scope="row"><label for="wpss_admin_email">安全通知邮箱</label></th>
                    <td>
                        <input type="email" name="wpss_admin_email" id="wpss_admin_email" value="<?php echo esc_attr(get_option('wpss_admin_email', get_option('admin_email'))); ?>" size="40">
                        <p class="description">当有重要拦截或操作时，将邮件通知此邮箱。</p>
                    </td>
                </tr>
                <tr>
                    <th>IP白名单</th>
                    <td>
                        <textarea name="wpss_ip_whitelist" rows="5" cols="60" placeholder="每行填写一个IP或通配符"><?php echo esc_textarea($white); ?></textarea>
                        <p class="description">支持如 192.168.1.1 或 192.168.*.*，支持IPV6。白名单IP将永不拦截。</p>
                    </td>
                </tr>
                <tr>
                    <th>IP黑名单</th>
                    <td>
                        <textarea name="wpss_ip_blacklist" rows="5" cols="60" placeholder="每行填写一个IP或通配符"><?php echo esc_textarea($black); ?></textarea>
                        <p class="description">支持如 1.2.3.4、10.10.*.*、2001:db8::1等。命中黑名单将直接拒绝访问。</p>
                    </td>
                </tr>
                <!-- 新增：自定义登录路径与参数验证设置 -->
                <tr>
                    <th>自定义登录地址</th>
                    <td>
                        <input type="text" name="wpss_custom_login_slug" id="wpss_custom_login_slug" value="<?php echo esc_attr($custom_login_slug); ?>" style="width:220px;" placeholder="如 my-login">
                        <p class="description">将 WordPress 登录地址从 /wp-login.php 改为 /?your-slug（如 /?my-login）。建议使用字母、数字、短横线组合。</p>
                        <span style="color:#888;">启用后，原有 <code>/wp-login.php</code> 登录入口会被保护，只允许通过此自定义路径访问登录页面。</span>
                        <br><span style="color:#888;">如需响应码、全局开关等请移步“防火墙规则”设置。</span>
                    </td>
                </tr>
                <tr>
                    <th>登录附加参数验证</th>
                    <td>
                        <input type="text" name="wpss_login_extra_param" id="wpss_login_extra_param" value="<?php echo esc_attr($login_extra_param); ?>" style="width:120px;" placeholder="参数名，如 token">
                        <input type="text" name="wpss_login_extra_value" id="wpss_login_extra_value" value="<?php echo esc_attr($login_extra_value); ?>" style="width:120px;" placeholder="参数值">
                        <p class="description">开启后，登录页面只有带此参数（如 <code>?my-login&token=xxxx</code>）才允许访问。留空则不启用。</p>
                    </td>
                </tr>
                <!-- 新增结束 -->
            </table>
            <p><button type="submit" class="button button-primary" name="wpss_settings_save">保存设置</button></p>
        </form>
    </div>
    <?php
}
