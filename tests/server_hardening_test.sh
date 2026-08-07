#!/usr/bin/env bash

# shellcheck disable=SC1090,SC1091,SC2030,SC2031,SC2034,SC2016,SC2317

set -u

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PACKAGE_DIR="$ROOT_DIR/服务器加固"
SCRIPT="$PACKAGE_DIR/server_hardening.sh"
MODULE_DIR="$PACKAGE_DIR/lib"
TESTS_RUN=0
TESTS_FAILED=0

fail() {
    printf '失败: %s\n' "$1" >&2
    return 1
}

assert_eq() {
    local expected="$1"
    local actual="$2"
    local message="$3"
    [[ "$expected" == "$actual" ]] || fail "${message}（期望=${expected} 实际=${actual}）"
}

assert_contains() {
    local haystack="$1"
    local needle="$2"
    local message="$3"
    [[ "$haystack" == *"$needle"* ]] || fail "${message}（缺少: ${needle}）"
}

assert_not_contains() {
    local haystack="$1"
    local needle="$2"
    local message="$3"
    [[ "$haystack" != *"$needle"* ]] || fail "${message}（不应出现: ${needle}）"
}

run_test() {
    local name="$1"
    shift
    TESTS_RUN=$((TESTS_RUN + 1))
    if "$@"; then
        printf '通过 %d - %s\n' "$TESTS_RUN" "$name"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        printf '未通过 %d - %s\n' "$TESTS_RUN" "$name"
    fi
}

load_script() {
    if declare -F generate_password >/dev/null 2>&1; then
        return 0
    fi
    [[ -f "$SCRIPT" ]] || fail "找不到脚本 $SCRIPT"
    # shellcheck source=../服务器加固/server_hardening.sh
    source "$SCRIPT"
}

sh_invocation_reports_bash_requirement() {
    local output status
    set +e
    output=$(sh "$SCRIPT" 2>&1)
    status=$?
    set -e
    [[ $status -ne 0 ]] || { fail "sh 误用应返回非零状态"; return 1; }
    assert_contains "$output" '本脚本需要 Bash' "sh 误用说明解释器要求" || return 1
    assert_contains "$output" '不能使用 sh' "sh 误用输出明确中文提示" || return 1
    assert_contains "$output" 'sudo bash server_hardening.sh' "sh 误用输出正确命令"
}

password_defaults_and_classes_are_enforced() {
    load_script || return 1
    local password
    password=$(generate_password) || return 1
    assert_eq 8 "${#password}" "默认密码长度" || return 1
    [[ "$password" =~ [A-Z] ]] || fail "缺少大写字母" || return 1
    [[ "$password" =~ [a-z] ]] || fail "缺少小写字母" || return 1
    [[ "$password" =~ [0-9] ]] || fail "缺少数字" || return 1
    [[ "$password" =~ [^[:alnum:]] ]] || fail "缺少符号"
}

password_length_boundaries_are_enforced() {
    load_script || return 1
    local password
    password=$(generate_password 8) || return 1
    assert_eq 8 "${#password}" "最小密码长度" || return 1
    password=$(generate_password 128) || return 1
    assert_eq 128 "${#password}" "最大密码长度" || return 1
    if generate_password 7 >/dev/null 2>&1; then
        fail "7 位密码应该失败"
        return 1
    fi
    if generate_password 129 >/dev/null 2>&1; then
        fail "129 位密码应该失败"
        return 1
    fi
}

supported_platforms_are_detected() {
    load_script || return 1
    local tmp version distro file
    tmp=$(mktemp -d)
    for version in 18.04 20.04 22.04 24.04; do
        file="$tmp/ubuntu-$version"
        printf 'ID=ubuntu\nVERSION_ID="%s"\n' "$version" > "$file"
        assert_eq debian "$(platform_family_from_os_release "$file")" "Ubuntu $version 发行版家族" || return 1
    done
    for version in 10 11 12; do
        file="$tmp/debian-$version"
        printf 'ID=debian\nVERSION_ID="%s"\n' "$version" > "$file"
        assert_eq debian "$(platform_family_from_os_release "$file")" "Debian $version 发行版家族" || return 1
    done
    printf 'ID=centos\nVERSION_ID="7"\n' > "$tmp/centos"
    for distro in rhel rocky almalinux; do
        for version in 8.10 9.4; do
            file="$tmp/$distro-$version"
            printf 'ID=%s\nVERSION_ID="%s"\n' "$distro" "$version" > "$file"
            assert_eq rhel8plus "$(platform_family_from_os_release "$file")" "$distro $version 发行版家族" || return 1
        done
    done
    printf 'ID=arch\nVERSION_ID="2026"\n' > "$tmp/arch"
    assert_eq rhel7 "$(platform_family_from_os_release "$tmp/centos")" "CentOS 7 发行版家族" || return 1
    if platform_family_from_os_release "$tmp/arch" >/dev/null 2>&1; then
        fail "不支持的发行版应该失败"
        return 1
    fi
    # PAM layout matches a verified family, so these classify as derived and
    # need --allow-unverified-platform rather than being rejected outright.
    local expected_family
    for distro in 'ubuntu:25.04:debian' 'debian:13:debian' 'centos:8:rhel8plus' \
        'rhel:10:rhel8plus' 'rocky:10:rhel8plus' 'almalinux:10:rhel8plus' \
        'fedora:40:rhel8plus' 'amzn:2023:rhel8plus' 'amzn:2:rhel7' 'ol:9.6:rhel8plus'; do
        file="$tmp/derived-${distro//:/-}"
        expected_family=${distro##*:}
        printf 'ID=%s\nVERSION_ID="%s"\n' "${distro%%:*}" "$(cut -d: -f2 <<<"$distro")" > "$file"
        assert_eq "$expected_family" "$(platform_classification_family "$file")" \
            "$distro 候选家族" || { rm -rf "$tmp"; return 1; }
        assert_eq derived "$(platform_classification_tier "$file")" \
            "$distro 应标记为未实测" || { rm -rf "$tmp"; return 1; }
    done
    # Vendor-managed or non-PAM stacks stay rejected: an ID_LIKE match is not
    # evidence that the PAM layout can be safely taken over.
    for distro in 'openEuler:22.03' 'kylin:V10' 'uos:20' 'sles:15.6' 'alpine:3.22' \
        'ubuntu:27.04' 'debian:14' 'rhel:11' 'fedora:45'; do
        file="$tmp/reject-${distro//:/-}"
        printf 'ID=%s\nVERSION_ID="%s"\n' "${distro%%:*}" "${distro#*:}" > "$file"
        assert_eq unsupported "$(platform_classification_tier "$file")" \
            "$distro 应被拒绝" || { rm -rf "$tmp"; return 1; }
        if platform_family_from_os_release "$file" >/dev/null 2>&1; then
            fail "不支持的 $distro 应被拒绝"
            rm -rf "$tmp"
            return 1
        fi
    done
    rm -rf "$tmp"
}

ssh_block_supports_root_and_admin_login_modes() {
    load_script || return 1
    local output
    output=$(render_ssh_managed_block disabled password-only 600) || return 1
    assert_contains "$output" 'PermitRootLogin no' "禁止 root 登录" || return 1
    assert_contains "$output" 'ClientAliveInterval 300' "SSH 空闲间隔" || return 1
    assert_contains "$output" 'ClientAliveCountMax 2' "SSH 空闲次数" || return 1
    assert_contains "$output" 'PasswordAuthentication no' "普通用户不开放 SSH 密码认证" || return 1
    assert_contains "$output" 'Match User opsadmin,auditadmin,secadmin' "仅三员账户允许初始密码登录" || return 1
    assert_contains "$output" 'PasswordAuthentication yes' "三员账户 SSH 密码认证" || return 1
    assert_contains "$output" 'PubkeyAuthentication no' "仅密码模式禁用公钥认证" || return 1
    assert_contains "$output" 'Match all' "恢复 SSH 全局上下文" || return 1
    output=$(render_ssh_managed_block key-only key-only 600) || return 1
    assert_contains "$output" 'PermitRootLogin prohibit-password' "root 仅允许密钥登录" || return 1
    assert_contains "$output" 'AuthenticationMethods publickey' "三员仅密钥登录" || return 1
    output=$(render_ssh_managed_block password-and-key password-and-key 600) || return 1
    assert_contains "$output" 'PermitRootLogin yes' "root 支持密码与密钥" || return 1
    assert_contains "$output" 'Match User root' "root 双模式独立覆盖密码认证" || return 1
    assert_not_contains "$output" 'AuthenticationMethods any' "双模式不生成 Ubuntu sshd 拒绝的 any 指令" || return 1
    if render_ssh_managed_block invalid password-only 600 >/dev/null 2>&1; then
        fail "无效 root SSH 模式应被拒绝"
        return 1
    fi
}

sshd_match_blocks_are_validated_for_managed_accounts() {
    load_script || return 1
    local tmp log config content
    tmp=$(mktemp -d)
    log="$tmp/sshd.log"
    config="$tmp/sshd_config"
    : > "$config"
    cat > "$tmp/sshd" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$SSHD_LOG"
EOF
    chmod +x "$tmp/sshd"
    SSHD_LOG="$log"
    export SSHD_LOG
    PATH="$tmp:$PATH"
    validate_sshd_config "$config" || { rm -rf "$tmp"; return 1; }
    content=$(<"$log")
    assert_contains "$content" "-t -f $config" "SSH 全局语法校验" || { rm -rf "$tmp"; return 1; }
    assert_contains "$content" "-T -f $config -C user=root,host=localhost,addr=127.0.0.1" "root Match 配置展开校验" || { rm -rf "$tmp"; return 1; }
    assert_contains "$content" "-T -f $config -C user=opsadmin,host=localhost,addr=127.0.0.1" "opsadmin Match 配置展开校验" || { rm -rf "$tmp"; return 1; }
    assert_contains "$content" "-T -f $config -C user=auditadmin,host=localhost,addr=127.0.0.1" "auditadmin Match 配置展开校验" || { rm -rf "$tmp"; return 1; }
    assert_contains "$content" "-T -f $config -C user=secadmin,host=localhost,addr=127.0.0.1" "secadmin Match 配置展开校验" || { rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

matching_effective_ssh_policy_is_not_rewritten() {
    load_script || return 1
    local tmp config before after output
    tmp=$(mktemp -d)
    config="$tmp/sshd_config"
    printf 'Port 22\n' > "$config"
    cat > "$tmp/sshd" <<'EOF'
#!/usr/bin/env bash
password=no
case "$*" in
    *user=opsadmin,*|*user=auditadmin,*|*user=secadmin,*) password=yes ;;
esac
cat <<OUT
permitrootlogin no
passwordauthentication $password
pubkeyauthentication yes
authenticationmethods any
clientaliveinterval 300
clientalivecountmax 2
permitemptypasswords no
usepam yes
OUT
EOF
    chmod +x "$tmp/sshd"
    reset_options
    ROOT_LOGIN=disabled
    ADMIN_LOGIN='password-and-key'
    SSH_IDLE_TIMEOUT=600
    NON_INTERACTIVE=1
    CONFLICT_ACTION=fail
    PATH="$tmp:$PATH"
    touch -t 202001010000 "$config"
    before=$(stat -c '%Y' "$config" 2>/dev/null || stat -f '%m' "$config")
    output=$(apply_ssh_policy "$config" 2>&1) || { rm -rf "$tmp"; return 1; }
    after=$(stat -c '%Y' "$config" 2>/dev/null || stat -f '%m' "$config")
    assert_eq "$before" "$after" "SSH 生效策略一致时保持配置 mtime" || { rm -rf "$tmp"; return 1; }
    assert_contains "$output" 'SSH 最终生效策略' "SSH 一致项输出说明" || { rm -rf "$tmp"; return 1; }
    assert_contains "$output" 'root 登录方式: 禁止登录' "读取 root 最终生效值" || { rm -rf "$tmp"; return 1; }
    assert_contains "$output" 'opsadmin 登录方式: 密码或密钥登录' "读取三员最终生效值" || { rm -rf "$tmp"; return 1; }
    assert_contains "$output" 'SSH 无响应超时: 600 秒' "换算 SSH 无响应超时" || { rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

ssh_idle_timeout_values_are_explained() {
    load_script || return 1
    assert_eq '未启用（ClientAliveInterval=0，ClientAliveCountMax=3）' \
        "$(ssh_idle_timeout_summary 0:3)" "ClientAliveInterval 为 0 表示未启用" || return 1
    assert_eq '600 秒（ClientAliveInterval=300，ClientAliveCountMax=2）' \
        "$(ssh_idle_timeout_summary 300:2)" "SSH 超时换算为实际秒数"
}

managed_block_replacement_is_idempotent() {
    load_script || return 1
    local tmp content before_mtime after_mtime output
    tmp=$(mktemp)
    reset_options
    NON_INTERACTIVE=1
    CONFLICT_ACTION=overwrite
    printf 'Port 22\n# keep me\n' > "$tmp"
    replace_managed_block "$tmp" '# BEGIN SERVER-HARDENING SSH' '# END SERVER-HARDENING SSH' 'PermitRootLogin no' top || return 1
    touch -t 202001010000 "$tmp"
    before_mtime=$(stat -c '%Y' "$tmp" 2>/dev/null || stat -f '%m' "$tmp")
    output=$(replace_managed_block "$tmp" '# BEGIN SERVER-HARDENING SSH' '# END SERVER-HARDENING SSH' 'PermitRootLogin no' top 2>&1) || return 1
    after_mtime=$(stat -c '%Y' "$tmp" 2>/dev/null || stat -f '%m' "$tmp")
    assert_eq "$before_mtime" "$after_mtime" "一致受管理块保持 mtime" || return 1
    assert_contains "$output" '已存在，跳过' "一致受管理块提示当前值" || return 1
    replace_managed_block "$tmp" '# BEGIN SERVER-HARDENING SSH' '# END SERVER-HARDENING SSH' 'PermitRootLogin prohibit-password' top || return 1
    content=$(<"$tmp")
    assert_eq 1 "$(grep -c '^# BEGIN SERVER-HARDENING SSH$' "$tmp")" "只保留一个受管理块" || return 1
    assert_contains "$content" 'PermitRootLogin prohibit-password' "最新受管理内容" || return 1
    assert_not_contains "$content" 'PermitRootLogin no' "旧受管理内容已移除" || return 1
    assert_contains "$content" '# keep me' "非受管理内容保留" || return 1
    rm -f "$tmp"
}

matching_managed_artifact_is_not_rewritten() {
    load_script || return 1
    local tmp root path before_mtime after_mtime output
    tmp=$(mktemp -d)
    root="$tmp/root"
    path="$root/etc/sudoers.d/server-hardening-roles"
    mkdir -p "$(dirname "$path")"
    printf 'managed artifact\n' > "$path"
    chmod 0440 "$path"
    SYSTEM_ROOT="$root"
    reset_options
    SYSTEM_ROOT="$root"
    NON_INTERACTIVE=1
    CONFLICT_ACTION=fail
    touch -t 202001010000 "$path"
    before_mtime=$(stat -c '%Y' "$path" 2>/dev/null || stat -f '%m' "$path")
    output=$(write_managed_artifact "$path" 0440 'managed artifact' 2>&1) || { rm -rf "$tmp"; return 1; }
    after_mtime=$(stat -c '%Y' "$path" 2>/dev/null || stat -f '%m' "$path")
    assert_eq "$before_mtime" "$after_mtime" "一致角色文件保持 mtime" || { rm -rf "$tmp"; return 1; }
    assert_contains "$output" '已存在，跳过' "一致角色文件提示跳过" || { rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

malformed_managed_block_is_rejected() {
    load_script || return 1
    local tmp before
    tmp=$(mktemp)
    printf 'Port 22\n# BEGIN SERVER-HARDENING SSH\nPermitRootLogin no\n' > "$tmp"
    before=$(<"$tmp")
    if replace_managed_block "$tmp" '# BEGIN SERVER-HARDENING SSH' '# END SERVER-HARDENING SSH' 'PermitRootLogin yes' top 2>/dev/null; then
        rm -f "$tmp"
        fail "残缺的受管理块应该失败"
        return 1
    fi
    assert_eq "$before" "$(<"$tmp")" "残缺块文件应保持不变" || { rm -f "$tmp"; return 1; }
    rm -f "$tmp"
}

non_interactive_options_are_validated() {
    load_script || return 1
    if (reset_options; NON_INTERACTIVE=1; validate_options) >/dev/null 2>&1; then
        fail "缺少非交互参数应该失败"
        return 1
    fi
    (reset_options
        NON_INTERACTIVE=1
        ROOT_LOGIN=disabled
        ADMIN_LOGIN='password-only'
        ROOT_PASSWORD_ACTION=keep
        PASSWORD_AGING=enable
        PASS_MAX_DAYS=30
        PASS_MIN_DAYS=1
        PASS_WARN_AGE=7
        PASS_MAX_DAYS_SET=1
        PASS_MIN_DAYS_SET=1
        PASS_WARN_AGE_SET=1
        PASSWORD_QUALITY=disable
        LOCKOUT=disable
        APPLY_AGING_EXISTING=yes
        APPLY_AGING_EXISTING_SET=1
        validate_options
    ) >/dev/null 2>&1 || {
        fail "完整的非交互参数应该通过校验"
        return 1
    }
    if (reset_options
        NON_INTERACTIVE=1
        ROOT_LOGIN=invalid
        ADMIN_LOGIN='password-only'
        ROOT_PASSWORD_ACTION=keep
        PASSWORD_AGING=enable
        PASS_MAX_DAYS=30
        PASS_MIN_DAYS=1
        PASS_WARN_AGE=7
        PASS_MAX_DAYS_SET=1
        PASS_MIN_DAYS_SET=1
        PASS_WARN_AGE_SET=1
        PASSWORD_QUALITY=disable
        LOCKOUT=disable
        APPLY_AGING_EXISTING=yes
        APPLY_AGING_EXISTING_SET=1
        validate_options
    ) >/dev/null 2>&1; then
        fail "无效 root SSH 模式应被拒绝"
        return 1
    fi
}

numbered_menu_returns_value_and_prints_chinese_labels() {
    load_script || return 1
    local tmp value output
    tmp=$(mktemp)
    value=$(printf '9\n2\n' | ask_menu 'root 密码处理' keep \
        keep '保持现有 root 密码' \
        custom '手工输入新 root 密码' \
        generate '自动生成 root 强密码' 2>"$tmp") || { rm -f "$tmp"; return 1; }
    output=$(<"$tmp")
    assert_eq custom "$value" "数字选项返回内部值" || { rm -f "$tmp"; return 1; }
    assert_contains "$output" '1) 保持现有 root 密码' "打印第一个中文选项" || { rm -f "$tmp"; return 1; }
    assert_contains "$output" '2) 手工输入新 root 密码' "打印第二个中文选项" || { rm -f "$tmp"; return 1; }
    assert_contains "$output" '请输入序号' "提示使用数字选择" || { rm -f "$tmp"; return 1; }
    assert_contains "$output" '无效选择' "超出菜单范围时要求重新输入" || { rm -f "$tmp"; return 1; }
    : > "$tmp"
    value=$(printf '999\n30\n' | ask_number '密码最长使用天数' 30 1 90 2>"$tmp") || { rm -f "$tmp"; return 1; }
    assert_eq 30 "$value" "数值超出范围后可重新输入" || { rm -f "$tmp"; return 1; }
    assert_contains "$(<"$tmp")" '请输入 1-90 的整数' "数值越界输出明确范围" || { rm -f "$tmp"; return 1; }
    rm -f "$tmp"
}

identical_conflict_value_is_skipped_with_current_value() {
    load_script || return 1
    local tmp output
    tmp=$(mktemp)
    reset_options
    NON_INTERACTIVE=1
    CONFLICT_ACTION=fail
    resolve_conflict password.max_days '密码最长有效期' '30 天' '30 天' '调整密码周期' > "$tmp" 2>&1 || { rm -f "$tmp"; return 1; }
    output=$(<"$tmp")
    assert_eq skip "$CONFLICT_DECISION" "一致项决策为跳过" || { rm -f "$tmp"; return 1; }
    assert_contains "$output" '已存在，跳过' "一致项跳过提示" || { rm -f "$tmp"; return 1; }
    assert_contains "$output" '值: 30 天' "一致项显示当前值" || { rm -f "$tmp"; return 1; }
    rm -f "$tmp"
}

interactive_conflict_retries_and_keeps_current_value() {
    load_script || return 1
    local output
    output=$(printf '9\n2\n' | (
        reset_options
        NON_INTERACTIVE=0
        resolve_conflict password.max_days '密码最长有效期' '90 天' '30 天' '调整密码周期'
        printf 'decision=%s partial=%s\n' "$CONFLICT_DECISION" "$PARTIAL_HARDENING"
    ) 2>&1) || return 1
    assert_contains "$output" '当前值:' "冲突显示当前值标题" || return 1
    assert_contains "$output" '目标值:' "冲突显示目标值标题" || return 1
    assert_contains "$output" '值: 90 天' "冲突显示当前值内容" || return 1
    assert_contains "$output" '值: 30 天' "冲突显示目标值内容" || return 1
    assert_contains "$output" '无效选择' "无效序号重试" || return 1
    assert_contains "$output" 'decision=skip partial=1' "保留当前值标记部分应用"
}

non_interactive_conflict_actions_are_enforced() {
    load_script || return 1
    local output
    output=$(
        reset_options
        NON_INTERACTIVE=1
        CONFLICT_ACTION=overwrite
        resolve_conflict ssh.admin_login '三员 SSH 登录方式' '仅密钥' '密码和密钥' '调整 SSH 认证方式'
        printf 'decision=%s changed=%s\n' "$CONFLICT_DECISION" "$SYSTEM_CHANGE_REQUIRED"
    ) 2>&1 || return 1
    assert_contains "$output" 'decision=apply changed=1' "非交互 overwrite 标记需要系统变更" || return 1
    output=$(
        reset_options
        NON_INTERACTIVE=1
        CONFLICT_ACTION=skip
        resolve_conflict ssh.admin_login '三员 SSH 登录方式' '仅密钥' '密码和密钥' '调整 SSH 认证方式'
        printf 'decision=%s partial=%s\n' "$CONFLICT_DECISION" "$PARTIAL_HARDENING"
    ) 2>&1 || return 1
    assert_contains "$output" 'decision=skip partial=1' "非交互 skip 保留" || return 1
    if (
        reset_options
        NON_INTERACTIVE=1
        CONFLICT_ACTION=fail
        resolve_conflict ssh.admin_login '三员 SSH 登录方式' '仅密钥' '密码和密钥' '调整 SSH 认证方式'
    ) >/dev/null 2>&1; then
        fail "非交互 fail 应拒绝冲突"
        return 1
    fi
}

identical_values_do_not_mark_system_changes() {
    load_script || return 1
    reset_options
    NON_INTERACTIVE=1
    CONFLICT_ACTION=fail
    resolve_conflict account.opsadmin.shell '账户 opsadmin 的登录 Shell' /bin/bash /bin/bash '修改登录 Shell' >/dev/null || return 1
    assert_eq 0 "$SYSTEM_CHANGE_REQUIRED" "一致值不标记系统变更"
}

no_change_transaction_skips_ssh_confirmation() {
    load_script || return 1
    local tmp output
    tmp=$(mktemp -d)
    mkdir -p "$tmp/transaction"
    printf 'id=fixture\nstatus=preparing\nssh_service=sshd\n' > "$tmp/transaction/metadata"
    output=$(
        TRANSACTION_DIR="$tmp/transaction"
        TRANSACTION_ID=fixture
        CHANGE_STARTED=1
        PARTIAL_HARDENING=0
        ROOT_PASSWORD_VALUE='temporary-test-value'
        disarm_automatic_rollback() { :; }
        finish_no_change_transaction
    ) 2>&1 || { rm -rf "$tmp"; return 1; }
    assert_contains "$output" '无需重载 SSH，也无需新建会话确认' "无变更时明确跳过确认" || { rm -rf "$tmp"; return 1; }
    assert_not_contains "$output" '请新建 SSH 会话' "无变更时不要求新会话" || { rm -rf "$tmp"; return 1; }
    assert_contains "$(<"$tmp/transaction/metadata")" 'status=no-changes' "无变更事务状态" || { rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

transaction_decisions_are_flushed_and_sanitized() {
    load_script || return 1
    local tmp mode content
    tmp=$(mktemp -d)
    reset_options
    BACKUP_ROOT="$tmp/backups"
    SSH_SERVICE=sshd
    NON_INTERACTIVE=1
    CONFLICT_ACTION=overwrite
    record_decision password.fixture 'TemporaryP@ss1' '$6$salt$secret-shadow-hash' apply test
    record_decision ssh.fixture 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakePublicKeyBody fixture' 'fingerprint=SHA256:safe' apply test
    create_transaction
    [[ -f "$TRANSACTION_DIR/decisions.tsv" ]] || { fail "事务应创建 decisions.tsv"; rm -rf "$tmp"; return 1; }
    mode=$(stat -c '%a' "$TRANSACTION_DIR/decisions.tsv" 2>/dev/null || stat -f '%Lp' "$TRANSACTION_DIR/decisions.tsv")
    assert_eq 600 "$mode" "决策日志权限" || { rm -rf "$tmp"; return 1; }
    content=$(<"$TRANSACTION_DIR/decisions.tsv")
    assert_contains "$content" '[REDACTED]' "敏感决策值已屏蔽" || { rm -rf "$tmp"; return 1; }
    assert_not_contains "$content" 'TemporaryP@ss1' "决策日志不含明文密码" || { rm -rf "$tmp"; return 1; }
    assert_not_contains "$content" 'secret-shadow-hash' "决策日志不含 shadow 哈希" || { rm -rf "$tmp"; return 1; }
    assert_not_contains "$content" 'AAAAC3Nza' "决策日志不含公钥主体" || { rm -rf "$tmp"; return 1; }
    record_decision later.fixture current target skip test
    assert_contains "$(<"$TRANSACTION_DIR/decisions.tsv")" 'later.fixture' "事务创建后的决策直接追加" || { rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

credential_bundle_contains_generated_credentials() {
    load_script || return 1
    local tmp bundle content output dir_mode file_mode owner
    tmp=$(mktemp -d)
    reset_options
    SYSTEM_ROOT="$tmp/system"
    TRANSACTION_ID=20260805T120000Z-a1b2c3d4
    mkdir -p "$SYSTEM_ROOT/opt"
    record_account_credential opsadmin 'OpsP@ss1'
    record_root_password_credential 'RootP@ss1'
    record_ssh_key_credential opsadmin \
        'ssh-ed25519 AAAAC3NzaFixture server-hardening:opsadmin:fixture' \
        $'-----BEGIN OPENSSH PRIVATE KEY-----\nprivate-fixture\n-----END OPENSSH PRIVATE KEY-----'
    output=$(write_credential_bundle 2>&1) || { rm -rf "$tmp"; return 1; }
    bundle="$SYSTEM_ROOT/opt/server-hardening/credentials.txt"
    [[ -f "$bundle" ]] || { fail "应创建固定凭据汇总文件"; rm -rf "$tmp"; return 1; }
    dir_mode=$(stat -c '%a' "$(dirname "$bundle")" 2>/dev/null || stat -f '%Lp' "$(dirname "$bundle")")
    file_mode=$(stat -c '%a' "$bundle" 2>/dev/null || stat -f '%Lp' "$bundle")
    assert_eq 700 "$dir_mode" "凭据目录权限" || { rm -rf "$tmp"; return 1; }
    assert_eq 600 "$file_mode" "凭据文件权限" || { rm -rf "$tmp"; return 1; }
    if (( EUID == 0 )); then
        owner=$(file_owner_value "$bundle") || { rm -rf "$tmp"; return 1; }
        assert_eq 0:0 "$owner" "凭据文件属主" || { rm -rf "$tmp"; return 1; }
    fi
    content=$(<"$bundle")
    assert_contains "$content" 'username=opsadmin' "凭据文件包含用户名" || { rm -rf "$tmp"; return 1; }
    assert_contains "$content" 'password=OpsP@ss1' "凭据文件包含账户密码" || { rm -rf "$tmp"; return 1; }
    assert_contains "$content" 'password=RootP@ss1' "凭据文件包含 root 密码" || { rm -rf "$tmp"; return 1; }
    assert_contains "$content" 'public_key=ssh-ed25519 AAAAC3NzaFixture' "凭据文件包含公钥" || { rm -rf "$tmp"; return 1; }
    assert_contains "$content" '-----BEGIN OPENSSH PRIVATE KEY-----' "凭据文件包含原始私钥" || { rm -rf "$tmp"; return 1; }
    assert_not_contains "$output" 'OpsP@ss1' "普通输出不泄露账户密码" || { rm -rf "$tmp"; return 1; }
    assert_not_contains "$output" 'private-fixture' "普通输出不泄露私钥" || { rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

credential_bundle_is_unchanged_without_new_values() {
    load_script || return 1
    local tmp bundle before_mtime before_checksum output
    tmp=$(mktemp -d)
    reset_options
    SYSTEM_ROOT="$tmp/system"
    TRANSACTION_ID=20260805T120000Z-a1b2c3d4
    bundle="$SYSTEM_ROOT/opt/server-hardening/credentials.txt"
    mkdir -p "$(dirname "$bundle")"
    printf 'existing credentials\n' > "$bundle"
    chmod 0600 "$bundle"
    touch -t 202001010000 "$bundle"
    before_mtime=$(stat -c '%Y' "$bundle" 2>/dev/null || stat -f '%m' "$bundle")
    before_checksum=$(cksum "$bundle")
    output=$(write_credential_bundle 2>&1) || { rm -rf "$tmp"; return 1; }
    assert_eq "$before_mtime" "$(stat -c '%Y' "$bundle" 2>/dev/null || stat -f '%m' "$bundle")" "无新增凭据时保持 mtime" || { rm -rf "$tmp"; return 1; }
    assert_eq "$before_checksum" "$(cksum "$bundle")" "无新增凭据时保持内容" || { rm -rf "$tmp"; return 1; }
    assert_contains "$output" '本次无新增凭据，文件未修改' "无新增凭据提示" || { rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

credential_bundle_write_failure_preserves_existing_file() {
    load_script || return 1
    local tmp bundle before
    tmp=$(mktemp -d)
    reset_options
    SYSTEM_ROOT="$tmp/system"
    TRANSACTION_ID=20260805T120000Z-a1b2c3d4
    bundle="$SYSTEM_ROOT/opt/server-hardening/credentials.txt"
    mkdir -p "$(dirname "$bundle")" "$tmp/bin"
    printf 'existing credentials\n' > "$bundle"
    before=$(<"$bundle")
    record_account_credential opsadmin 'OpsP@ss1'
    cat > "$tmp/bin/mv" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
    chmod +x "$tmp/bin/mv"
    if PATH="$tmp/bin:$PATH" write_credential_bundle >/dev/null 2>&1; then
        rm -rf "$tmp"
        fail "原子替换失败时应返回失败"
        return 1
    fi
    assert_eq "$before" "$(<"$bundle")" "写入失败时保留旧凭据文件" || { rm -rf "$tmp"; return 1; }
    [[ -z $(find "$(dirname "$bundle")" -name '.credentials.*' -print -quit) ]] || { fail "写入失败后应删除临时文件"; rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

credential_bundle_rejects_symlink_paths() {
    load_script || return 1
    local tmp
    tmp=$(mktemp -d)
    reset_options
    SYSTEM_ROOT="$tmp/system"
    TRANSACTION_ID=20260805T120000Z-a1b2c3d4
    mkdir -p "$SYSTEM_ROOT/opt" "$tmp/redirect"
    ln -s "$tmp/redirect" "$SYSTEM_ROOT/opt/server-hardening"
    record_account_credential opsadmin 'OpsP@ss1'
    if write_credential_bundle >/dev/null 2>&1; then
        rm -rf "$tmp"
        fail "凭据目录为符号链接时必须拒绝写入"
        return 1
    fi
    [[ ! -e "$tmp/redirect/credentials.txt" ]] || { fail "不得通过符号链接写入凭据"; rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

dry_run_does_not_create_decision_log() {
    load_script || return 1
    local tmp
    tmp=$(mktemp -d)
    reset_options
    BACKUP_ROOT="$tmp/backups"
    DRY_RUN=1
    record_decision dry.fixture current target skip test
    create_transaction
    [[ ! -e "$BACKUP_ROOT" ]] || { fail "dry-run 不应创建事务或决策日志"; rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

partial_result_message_does_not_claim_full_application() {
    load_script || return 1
    local output
    TRANSACTION_ID=fixture-transaction
    PARTIAL_HARDENING=1
    output=$(show_apply_result 2>&1) || return 1
    assert_contains "$output" '部分策略未应用' "跳过冲突项时输出部分应用" || return 1
    assert_not_contains "$output" '加固已完整应用' "部分应用不得声称完整成功"
}

account_state_readers_return_sanitized_values() {
    load_script || return 1
    local tmp aging
    tmp=$(mktemp -d)
    cat > "$tmp/passwd" <<'EOF'
opsadmin:x:1001:1001:Ops:/home/opsadmin:/bin/zsh
EOF
    cat > "$tmp/shadow" <<'EOF'
opsadmin:$6$salt$secret-hash:0:1:30:7:::
EOF
    PASSWD_FILE="$tmp/passwd"
    SHADOW_FILE="$tmp/shadow"
    assert_eq /bin/zsh "$(account_shell_value opsadmin)" "账户 Shell 当前值" || { rm -rf "$tmp"; return 1; }
    aging=$(account_aging_value opsadmin) || { rm -rf "$tmp"; return 1; }
    assert_eq 'min=1,max=30,warn=7,must-change=yes,password=set' "$aging" "账户密码周期摘要" || { rm -rf "$tmp"; return 1; }
    assert_not_contains "$aging" 'secret-hash' "密码摘要不泄露 shadow 哈希" || { rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

managed_block_and_file_mode_are_readable() {
    load_script || return 1
    local tmp file
    tmp=$(mktemp -d)
    file="$tmp/config"
    printf 'before\n# BEGIN X\nkey=value\n# END X\nafter\n' > "$file"
    chmod 0640 "$file"
    assert_eq 'key=value' "$(managed_block_content "$file" '# BEGIN X' '# END X')" "读取受管块当前内容" || { rm -rf "$tmp"; return 1; }
    assert_eq 640 "$(file_mode_value "$file")" "读取文件权限" || { rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

file_and_managed_key_summaries_hide_content() {
    load_script || return 1
    local tmp file key summary public_key_body
    tmp=$(mktemp -d)
    file="$tmp/artifact"
    printf 'sensitive managed content\n' > "$file"
    chmod 0640 "$file"
    summary=$(file_state_summary "$file" 0600) || { rm -rf "$tmp"; return 1; }
    assert_contains "$summary" 'mode=640,expected-mode=600' "文件摘要包含当前和目标权限" || { rm -rf "$tmp"; return 1; }
    assert_contains "$summary" 'sha256=' "文件摘要包含内容摘要" || { rm -rf "$tmp"; return 1; }
    assert_not_contains "$summary" 'sensitive managed content' "文件摘要不打印正文" || { rm -rf "$tmp"; return 1; }

    mkdir -p "$tmp/home/opsadmin/.ssh"
    key="$tmp/id_ed25519"
    ssh-keygen -q -t ed25519 -N '' -C 'server-hardening:opsadmin:fixture' -f "$key" || { rm -rf "$tmp"; return 1; }
    cp "$key.pub" "$tmp/home/opsadmin/.ssh/authorized_keys"
    printf 'opsadmin:x:1001:1001:Ops:%s:/bin/bash\n' "$tmp/home/opsadmin" > "$tmp/passwd"
    PASSWD_FILE="$tmp/passwd"
    SYSTEM_ROOT=/
    summary=$(managed_authorized_key_fingerprint opsadmin) || { rm -rf "$tmp"; return 1; }
    public_key_body=$(awk '{print $2}' "$key.pub")
    assert_contains "$summary" 'type=ssh-ed25519' "密钥摘要包含类型" || { rm -rf "$tmp"; return 1; }
    assert_contains "$summary" 'fingerprint=SHA256:' "密钥摘要包含指纹" || { rm -rf "$tmp"; return 1; }
    assert_not_contains "$summary" "$public_key_body" "密钥摘要不打印公钥主体" || { rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

existing_policy_values_are_read_and_skipped() {
    load_script || return 1
    local tmp login_defs pwquality faillock before after output
    tmp=$(mktemp -d)
    login_defs="$tmp/login.defs"
    pwquality="$tmp/pwquality.conf"
    faillock="$tmp/faillock.conf"
    printf 'PASS_MAX_DAYS 30\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\n' > "$login_defs"
    printf 'minlen = 8\ndcredit = -1\nucredit = -1\nlcredit = -1\nocredit = -1\nmaxrepeat = 3\nenforce_for_root\n' > "$pwquality"
    printf 'deny = 5\nunlock_time = 900\n' > "$faillock"
    touch -t 202001010000 "$login_defs" "$pwquality" "$faillock"
    reset_options
    NON_INTERACTIVE=1
    CONFLICT_ACTION=fail
    PASSWORD_QUALITY=enable
    MIN_CONFIGURED_PASSWORD_LENGTH=8
    LOCKOUT=enable
    LOCKOUT_DENY=5
    UNLOCK_TIME=900
    before=$(for file in "$login_defs" "$pwquality" "$faillock"; do stat -c '%Y' "$file" 2>/dev/null || stat -f '%m' "$file"; done)
    output=$(
        apply_login_defs_policy "$login_defs"
        apply_pwquality_policy "$pwquality"
        apply_faillock_file_policy "$faillock" yes
    ) 2>&1 || { rm -rf "$tmp"; return 1; }
    after=$(for file in "$login_defs" "$pwquality" "$faillock"; do stat -c '%Y' "$file" 2>/dev/null || stat -f '%m' "$file"; done)
    assert_eq "$before" "$after" "已有策略值一致时保持文件 mtime" || { rm -rf "$tmp"; return 1; }
    assert_contains "$output" '最长有效期: 30 天' "读取 login.defs 当前值" || { rm -rf "$tmp"; return 1; }
    assert_contains "$output" '最小密码长度: 8 位' "读取 pwquality 当前值" || { rm -rf "$tmp"; return 1; }
    assert_contains "$output" '连续失败次数: 5 次' "读取 faillock 当前值" || { rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

missing_policy_files_are_created_without_conflict() {
    load_script || return 1
    local tmp pwquality faillock output content
    tmp=$(mktemp -d)
    pwquality="$tmp/security/pwquality.conf"
    faillock="$tmp/security/faillock.conf"
    output="$tmp/output.log"
    reset_options
    NON_INTERACTIVE=1
    CONFLICT_ACTION=fail
    PASSWORD_QUALITY=enable
    MIN_CONFIGURED_PASSWORD_LENGTH=8
    LOCKOUT_DENY=5
    UNLOCK_TIME=900
    SYSTEM_CHANGE_REQUIRED=0

    {
        apply_pwquality_policy "$pwquality"
        apply_faillock_file_policy "$faillock" yes
    } > "$output" 2>&1 || { rm -rf "$tmp"; return 1; }

    [[ -s "$pwquality" ]] || { rm -rf "$tmp"; fail "缺失的 pwquality.conf 应创建完整配置"; return 1; }
    [[ -s "$faillock" ]] || { rm -rf "$tmp"; fail "缺失的 faillock.conf 应创建完整配置"; return 1; }
    content=$(<"$pwquality")
    assert_contains "$content" "$PWQUALITY_BLOCK_BEGIN" "pwquality 受管理块起始标记" || { rm -rf "$tmp"; return 1; }
    assert_contains "$content" 'minlen = 8' "pwquality 目标内容" || { rm -rf "$tmp"; return 1; }
    content=$(<"$faillock")
    assert_contains "$content" "$FAILLOCK_BLOCK_BEGIN" "faillock 受管理块起始标记" || { rm -rf "$tmp"; return 1; }
    assert_contains "$content" 'deny = 5' "faillock 目标内容" || { rm -rf "$tmp"; return 1; }
    assert_not_contains "$(<"$output")" '配置冲突' "首次创建配置不进入冲突处理" || { rm -rf "$tmp"; return 1; }
    assert_eq 1 "$SYSTEM_CHANGE_REQUIRED" "首次创建策略文件标记系统变更" || { rm -rf "$tmp"; return 1; }

    rm -f "$pwquality" "$faillock"
    DRY_RUN=1
    SYSTEM_CHANGE_REQUIRED=0
    apply_pwquality_policy "$pwquality" >/dev/null 2>&1 || { rm -rf "$tmp"; return 1; }
    apply_faillock_file_policy "$faillock" yes >/dev/null 2>&1 || { rm -rf "$tmp"; return 1; }
    [[ ! -e "$pwquality" && ! -e "$faillock" ]] || { rm -rf "$tmp"; fail "dry-run 不应创建策略文件"; return 1; }
    assert_eq 0 "$SYSTEM_CHANGE_REQUIRED" "dry-run 不标记实际系统变更" || { rm -rf "$tmp"; return 1; }
    reset_options
    rm -rf "$tmp"
}

state_details_are_rendered_with_readable_labels() {
    load_script || return 1
    local output
    output=$(
        print_state_details account.opsadmin.aging 'min=1,max=30,warn=7,must-change=yes,password=set'
        print_state_details account.opsadmin.group.wheel 'member=yes'
        print_state_details ssh-key.opsadmin 'path=/home/opsadmin/.ssh/authorized_keys,type=ssh-ed25519,fingerprint=SHA256:fixture'
        print_state_details artifact./etc/example 'mode=640,expected-mode=600,owner=0:0,sha256=fixture'
        print_state_details password.lockout 'deny=5,unlock-time=900'
        print_state_details password.quality 'minlen=8,dcredit=-1,ucredit=-1,lcredit=-1,ocredit=-1,maxrepeat=3,enforce-root=yes'
    ) || return 1
    assert_contains "$output" '最长有效期: 30 天' "账户周期使用中文字段" || return 1
    assert_contains "$output" '首次登录必须修改密码: 是' "首次改密状态可读" || return 1
    assert_contains "$output" '成员状态: 已加入' "组成员状态可读" || return 1
    assert_contains "$output" '密钥类型: Ed25519' "SSH 密钥类型可读" || return 1
    assert_contains "$output" '权限: 0640' "文件权限可读" || return 1
    assert_contains "$output" '属主: root:root' "文件属主可读" || return 1
    assert_contains "$output" '锁定时间: 900 秒' "失败锁定参数可读" || return 1
    assert_contains "$output" '数字要求: 至少 1 个' "密码复杂度 credit 转换为直接说明" || return 1
    assert_not_contains "$output" 'must-change=' "不输出账户内部摘要" || return 1
    assert_not_contains "$output" 'member=' "不输出组内部摘要" || return 1
    assert_not_contains "$output" 'expected-mode=' "不输出文件内部摘要"
}

managed_accounts_are_created_without_resetting_existing_passwords() {
    load_script || return 1
    local tmp log content opsadmin_password
    tmp=$(mktemp -d)
    log="$tmp/commands.log"
    mkdir -p "$tmp/bin" "$tmp/etc"
    cat > "$tmp/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/bash
auditadmin:x:1001:27:Audit Administrator:/home/auditadmin:/bin/bash
ordinary:x:1002:1002:Ordinary User:/home/ordinary:/bin/bash
EOF
    cat > "$tmp/etc/group" <<'EOF'
sudo:x:27:auditadmin
wheel:x:10:
adm:x:4:
systemd-journal:x:190:
EOF
    cat > "$tmp/etc/shadow" <<'EOF'
auditadmin:$6$salt$hash:20000:1:30:7:::
ordinary:$6$salt$hash:20000:1:30:7:::
EOF
    cat > "$tmp/bin/command-stub" <<'EOF'
#!/usr/bin/env bash
name=${0##*/}
if [[ "$name" == chpasswd ]]; then
    while IFS= read -r line; do printf 'chpasswd %s\n' "$line" >> "$COMMAND_LOG"; done
else
    printf '%s %s\n' "$name" "$*" >> "$COMMAND_LOG"
fi
EOF
    chmod +x "$tmp/bin/command-stub"
    local command
    for command in groupadd useradd usermod gpasswd chpasswd chage; do ln -s "$tmp/bin/command-stub" "$tmp/bin/$command"; done
    SYSTEM_ROOT="$tmp"
    PLATFORM_FAMILY=debian
    PASSWD_FILE="$tmp/etc/passwd"
    GROUP_FILE="$tmp/etc/group"
    SHADOW_FILE="$tmp/etc/shadow"
    NON_INTERACTIVE=1
    CONFLICT_ACTION=overwrite
    COMMAND_LOG="$log"
    export COMMAND_LOG
    PATH="$tmp/bin:$PATH"
    reset_managed_account_state
    apply_managed_accounts
    content=$(<"$log")
    assert_contains "$content" 'useradd -m -s /bin/bash -c 运维管理员 opsadmin' "创建运维管理员" || { rm -rf "$tmp"; return 1; }
    assert_contains "$content" 'useradd -m -s /bin/bash -c 安全管理员 secadmin' "创建安全管理员" || { rm -rf "$tmp"; return 1; }
    assert_not_contains "$content" 'useradd -m -s /bin/bash -c 审计管理员 auditadmin' "已有审计管理员不重建" || { rm -rf "$tmp"; return 1; }
    assert_contains "$content" 'chpasswd opsadmin:' "为新建运维管理员设置随机密码" || { rm -rf "$tmp"; return 1; }
    opsadmin_password=$(sed -n 's/^chpasswd opsadmin://p' "$log" | head -1)
    assert_eq 8 "${#opsadmin_password}" "三员临时密码长度" || { rm -rf "$tmp"; return 1; }
    assert_contains "$content" 'chpasswd secadmin:' "为新建安全管理员设置随机密码" || { rm -rf "$tmp"; return 1; }
    assert_not_contains "$content" 'chpasswd auditadmin:' "已有账户密码不重置" || { rm -rf "$tmp"; return 1; }
    assert_contains "$content" 'chage -d 0 -M 30 -m 1 -W 7 opsadmin' "新建账户首次登录强制改密" || { rm -rf "$tmp"; return 1; }
    assert_not_contains "$content" 'chage -M 30 -m 1 -W 7 auditadmin' "已有账户密码周期一致时跳过" || { rm -rf "$tmp"; return 1; }
    assert_not_contains "$content" 'chage -d 0 -M 30 -m 1 -W 7 auditadmin' "已有账户不强制重新首次改密" || { rm -rf "$tmp"; return 1; }
    assert_contains "$content" 'usermod -a -G sudo opsadmin' "运维管理员加入 sudo 组" || { rm -rf "$tmp"; return 1; }
    assert_contains "$content" 'usermod -a -G adm auditadmin' "审计管理员加入日志只读组" || { rm -rf "$tmp"; return 1; }
    assert_contains "$content" 'groupadd auditadmin' "为受限管理员创建非管理主组" || { rm -rf "$tmp"; return 1; }
    assert_contains "$content" 'usermod -g auditadmin auditadmin' "审计管理员不得以 sudo 为主组" || { rm -rf "$tmp"; return 1; }
    assert_contains "$content" 'gpasswd -d auditadmin sudo' "审计管理员移出完整 sudo 组" || { rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

matching_managed_accounts_do_not_run_mutation_commands() {
    load_script || return 1
    local tmp log output
    tmp=$(mktemp -d)
    log="$tmp/commands.log"
    mkdir -p "$tmp/bin" "$tmp/etc"
    cat > "$tmp/etc/passwd" <<'EOF'
opsadmin:x:1001:1001:Ops:/home/opsadmin:/bin/bash
auditadmin:x:1002:1002:Audit:/home/auditadmin:/bin/bash
secadmin:x:1003:1003:Security:/home/secadmin:/bin/bash
EOF
    cat > "$tmp/etc/group" <<'EOF'
sudo:x:27:opsadmin
wheel:x:10:
adm:x:4:auditadmin
systemd-journal:x:190:auditadmin
opsadmin:x:1001:
auditadmin:x:1002:
secadmin:x:1003:
EOF
    cat > "$tmp/etc/shadow" <<'EOF'
opsadmin:$6$salt$hash:20000:1:30:7:::
auditadmin:$6$salt$hash:20000:1:30:7:::
secadmin:$6$salt$hash:20000:1:30:7:::
EOF
    cat > "$tmp/bin/command-stub" <<'EOF'
#!/usr/bin/env bash
printf '%s %s\n' "${0##*/}" "$*" >> "$COMMAND_LOG"
EOF
    chmod +x "$tmp/bin/command-stub"
    local command
    for command in groupadd useradd usermod gpasswd chpasswd chage; do ln -s "$tmp/bin/command-stub" "$tmp/bin/$command"; done
    reset_options
    SYSTEM_ROOT="$tmp"
    PLATFORM_FAMILY=debian
    PASSWD_FILE="$tmp/etc/passwd"
    GROUP_FILE="$tmp/etc/group"
    SHADOW_FILE="$tmp/etc/shadow"
    COMMAND_LOG="$log"
    export COMMAND_LOG
    PATH="$tmp/bin:$PATH"
    NON_INTERACTIVE=1
    CONFLICT_ACTION=fail
    output=$(apply_managed_accounts 2>&1) || { rm -rf "$tmp"; return 1; }
    [[ ! -s "$log" ]] || { fail "一致三员账户不应执行修改命令"; rm -rf "$tmp"; return 1; }
    assert_contains "$output" '已存在，跳过' "一致账户属性提示跳过" || { rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

backup_and_restore_preserve_sensitive_files() {
    load_script || return 1
    local tmp original exported_key
    tmp=$(mktemp -d)
    mkdir -p "$tmp/etc/ssh" "$tmp/backups"
    printf 'Port 22\nPermitRootLogin yes\n' > "$tmp/etc/ssh/sshd_config"
    printf 'root:$6$oldhash:20000:0:99999:7:::\n' > "$tmp/etc/shadow"
    original=$(<"$tmp/etc/ssh/sshd_config")
    SYSTEM_ROOT="$tmp"
    BACKUP_ROOT="$tmp/backups"
    TRANSACTION_DIR="$tmp/backups/20260803T120000Z-a1b2c3d4"
    TRANSACTION_ID=20260803T120000Z-a1b2c3d4
    SSH_SERVICE=sshd
    mkdir -p "$TRANSACTION_DIR/archives"
    : > "$TRANSACTION_DIR/manifest.tsv"
    exported_key="$tmp/server-hardening-opsadmin-20260803T120000Z-a1b2c3d4-ed25519"
    printf 'private\n' > "$exported_key"
    printf '%s\n' "$exported_key" > "$TRANSACTION_DIR/exported-keys.list"
    printf 'id=%s\ncreated_epoch=1\nstatus=preparing\nssh_service=sshd\n' "$TRANSACTION_ID" > "$TRANSACTION_DIR/metadata"
    backup_target /etc/ssh/sshd_config no
    backup_target /etc/shadow yes
    printf 'corrupt\n' > "$tmp/etc/ssh/sshd_config"
    printf 'root:$6$newhash:20000:0:99999:7:::\n' > "$tmp/etc/shadow"
    restore_transaction_dir "$TRANSACTION_DIR"
    assert_eq "$original" "$(<"$tmp/etc/ssh/sshd_config")" "备份恢复 SSH 配置内容" || { rm -rf "$tmp"; return 1; }
    assert_contains "$(<"$tmp/etc/shadow")" '$6$oldhash' "shadow 哈希已恢复" || { rm -rf "$tmp"; return 1; }
    [[ ! -e "$exported_key" ]] || { rm -rf "$tmp"; fail "手动回滚应删除已导出私钥"; return 1; }
    rm -rf "$tmp"
}

restore_skips_selinux_relabel_for_removed_targets() {
    load_script || return 1
    local tmp id log
    tmp=$(mktemp -d)
    id=20260803T120000Z-a1b2c3d4
    log="$tmp/restorecon.log"
    mkdir -p "$tmp/bin" "$tmp/transaction/archives"
    printf '1\tno\tno\t/etc/security/faillock.conf\n' > "$tmp/transaction/manifest.tsv"
    printf 'id=%s\ncreated_epoch=1\nstatus=preparing\nssh_service=sshd\n' "$id" > "$tmp/transaction/metadata"
    cat > "$tmp/bin/restorecon" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$RESTORECON_LOG"
exit 1
EOF
    chmod +x "$tmp/bin/restorecon"
    RESTORECON_LOG="$log"
    export RESTORECON_LOG
    if ! (SYSTEM_ROOT="$tmp" PATH="$tmp/bin:$PATH" restore_transaction_dir "$tmp/transaction"); then
        rm -rf "$tmp"
        fail "删除原本不存在的目标时不应因 restorecon 失败"
        return 1
    fi
    [[ ! -e "$log" ]] || { rm -rf "$tmp"; fail "不存在的目标不应调用 restorecon"; return 1; }
    rm -rf "$tmp"
}

debian_pam_blocks_are_managed() {
    load_script || return 1
    local tmp content
    tmp=$(mktemp -d)
    mkdir -p "$tmp/etc/pam.d" "$tmp/lib/security" "$tmp/etc/security"
    touch "$tmp/lib/security/pam_faillock.so" "$tmp/lib/security/pam_pwquality.so"
    printf 'auth [success=1 default=ignore] pam_unix.so nullok\nauth requisite pam_deny.so\nauth required pam_permit.so\n' > "$tmp/etc/pam.d/common-auth"
    printf 'auth [success=1 default=ignore] pam_sss.so\n' >> "$tmp/etc/pam.d/common-auth"
    printf 'account [success=1 new_authtok_reqd=done default=ignore] pam_unix.so\naccount requisite pam_deny.so\naccount required pam_permit.so\n' > "$tmp/etc/pam.d/common-account"
    printf 'password [success=1 default=ignore] pam_unix.so obscure\npassword requisite pam_deny.so\npassword required pam_permit.so\n' > "$tmp/etc/pam.d/common-password"
    SYSTEM_ROOT="$tmp"
    PLATFORM_FAMILY=debian
    LOCKOUT=enable
    LOCKOUT_DENY=5
    UNLOCK_TIME=900
    PASSWORD_QUALITY=enable
    NON_INTERACTIVE=1
    CONFLICT_ACTION=overwrite
    prepare_debian_pam
    apply_debian_pam
    content=$(<"$tmp/etc/pam.d/common-auth")
    assert_contains "$content" 'pam_faillock.so preauth' "faillock 预认证模块" || { rm -rf "$tmp"; return 1; }
    assert_contains "$content" '[success=2 default=ignore] pam_unix.so' "pam_unix 成功跳转计数已调整" || { rm -rf "$tmp"; return 1; }
    assert_contains "$content" '[success=1 default=ignore] pam_sss.so' "非 pam_unix 控制流保持不变" || { rm -rf "$tmp"; return 1; }
    [[ $(grep -n 'pam_faillock.so preauth' "$tmp/etc/pam.d/common-auth" | cut -d: -f1) -lt $(grep -n 'pam_unix.so' "$tmp/etc/pam.d/common-auth" | cut -d: -f1) ]] || { rm -rf "$tmp"; fail "faillock 预认证应在 pam_unix 前"; return 1; }
    [[ $(grep -n 'pam_faillock.so authfail' "$tmp/etc/pam.d/common-auth" | cut -d: -f1) -gt $(grep -n 'pam_unix.so' "$tmp/etc/pam.d/common-auth" | cut -d: -f1) ]] || { rm -rf "$tmp"; fail "faillock 失败记录应在 pam_unix 后"; return 1; }
    assert_contains "$(<"$tmp/etc/pam.d/common-password")" 'pam_pwquality.so retry=3' "pwquality PAM 配置行" || { rm -rf "$tmp"; return 1; }
    apply_debian_pam
    assert_eq 1 "$(grep -c '^# BEGIN SERVER-HARDENING AUTH LOCKOUT$' "$tmp/etc/pam.d/common-auth")" "PAM 锁定配置幂等" || { rm -rf "$tmp"; return 1; }
    LOCKOUT=disable
    prepare_debian_pam
    apply_debian_pam
    assert_contains "$(<"$tmp/etc/pam.d/common-auth")" '[success=1 default=ignore] pam_unix.so' "pam_unix 成功跳转计数已恢复" || { rm -rf "$tmp"; return 1; }
    assert_eq 0 "$(grep -c '^# BEGIN SERVER-HARDENING AUTH LOCKOUT$' "$tmp/etc/pam.d/common-auth" || true)" "锁定受管理块已移除" || { rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

existing_pwquality_line_is_reused() {
    load_script || return 1
    local tmp
    tmp=$(mktemp -d)
    mkdir -p "$tmp/etc/pam.d" "$tmp/lib/security"
    touch "$tmp/lib/security/pam_faillock.so" "$tmp/lib/security/pam_pwquality.so"
    printf 'auth [success=1 default=ignore] pam_unix.so nullok\nauth requisite pam_deny.so\nauth required pam_permit.so\n' > "$tmp/etc/pam.d/common-auth"
    printf 'account [success=1 new_authtok_reqd=done default=ignore] pam_unix.so\naccount requisite pam_deny.so\naccount required pam_permit.so\n' > "$tmp/etc/pam.d/common-account"
    printf 'password requisite pam_pwquality.so retry=3\npassword [success=1 default=ignore] pam_unix.so obscure\npassword requisite pam_deny.so\npassword required pam_permit.so\n' > "$tmp/etc/pam.d/common-password"
    SYSTEM_ROOT="$tmp"
    LOCKOUT=disable
    PASSWORD_QUALITY=enable
    PAM_PWQUALITY_LINE_NEEDED=0
    NON_INTERACTIVE=1
    CONFLICT_ACTION=overwrite
    prepare_debian_pam
    apply_debian_pam
    assert_eq 1 "$(grep -c 'pam_pwquality.so' "$tmp/etc/pam.d/common-password")" "复用已有 pwquality 配置行" || { rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

rhel_lockout_uses_platform_commands() {
    load_script || return 1
    local tmp log
    tmp=$(mktemp -d)
    log="$tmp/commands.log"
    mkdir -p "$tmp/bin" "$tmp/etc/pam.d" "$tmp/etc/security"
    printf 'auth required pam_unix.so\n' > "$tmp/etc/pam.d/system-auth-ac"
    printf 'auth required pam_unix.so\n' > "$tmp/etc/pam.d/password-auth-ac"
    ln -s system-auth-ac "$tmp/etc/pam.d/system-auth"
    ln -s password-auth-ac "$tmp/etc/pam.d/password-auth"
    cat > "$tmp/bin/authselect" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == check ]]; then exit 0; fi
if [[ "$1" == current ]]; then
    printf 'Profile ID: sssd\n'
    [[ ${AUTHSELECT_WITH_FAILLOCK:-0} == 1 ]] && printf 'Enabled features:\n- with-faillock\n'
    exit 0
fi
printf 'authselect %s\n' "$*" >> "$COMMAND_LOG"
EOF
    cat > "$tmp/bin/authconfig" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == --test ]]; then printf 'pam_faillock is disabled\n'; exit 0; fi
printf 'authconfig %s\n' "$*" >> "$COMMAND_LOG"
EOF
    chmod +x "$tmp/bin/authselect" "$tmp/bin/authconfig"
    SYSTEM_ROOT="$tmp"
    LOCKOUT=enable
    PASSWORD_QUALITY=disable
    LOCKOUT_DENY=5
    UNLOCK_TIME=900
    COMMAND_LOG="$log"
    export COMMAND_LOG
    PATH="$tmp/bin:$PATH"
    PLATFORM_FAMILY=rhel8plus
    prepare_rhel_pam
    apply_rhel_pam
    assert_contains "$(<"$log")" 'authselect enable-feature with-faillock' "RHEL 8 启用 faillock 特性" || { rm -rf "$tmp"; return 1; }
    [[ -f "$tmp/var/lib/server-hardening/authselect-faillock.enabled" ]] || { rm -rf "$tmp"; fail "RHEL 8 所有权标记缺失"; return 1; }
    : > "$log"
    PLATFORM_FAMILY=rhel7
    prepare_rhel_pam
    apply_rhel_pam
    assert_contains "$(<"$log")" 'authconfig --enablefaillock --faillockargs=deny=5 unlock_time=900 --update' "CentOS 7 authconfig 参数" || { rm -rf "$tmp"; return 1; }
    [[ -f "$tmp/var/lib/server-hardening/authconfig-faillock.enabled" ]] || { rm -rf "$tmp"; fail "CentOS 7 所有权标记缺失"; return 1; }
    LOCKOUT=disable
    PAM_LOCKOUT_WAS_MANAGED=0
    prepare_rhel_pam
    apply_rhel_pam
    assert_contains "$(<"$log")" 'authconfig --disablefaillock --update' "CentOS 7 仅禁用脚本自己管理的 faillock" || { rm -rf "$tmp"; return 1; }
    [[ ! -e "$tmp/var/lib/server-hardening/authconfig-faillock.enabled" ]] || { rm -rf "$tmp"; fail "CentOS 7 禁用后所有权标记应被移除"; return 1; }
    rm -rf "$tmp"
}

rollback_script_is_self_contained() {
    load_script || return 1
    local tmp content
    tmp=$(mktemp -d)
    TRANSACTION_DIR="$tmp/transaction"
    TRANSACTION_ID=20260803T120000Z-a1b2c3d4
    mkdir -p "$TRANSACTION_DIR/archives"
    printf 'id=%s\ncreated_epoch=1\nstatus=preparing\nssh_service=sshd\n' "$TRANSACTION_ID" > "$TRANSACTION_DIR/metadata"
    : > "$TRANSACTION_DIR/manifest.tsv"
    generate_rollback_script
    content=$(<"$TRANSACTION_DIR/rollback.sh")
    assert_contains "$content" 'tar_extract "$DIR/archives/$index.tar" "$staging"' "回滚脚本使用备份归档" || { rm -rf "$tmp"; return 1; }
    assert_not_contains "$content" 'exec "$0" --rollback' "回滚脚本不依赖主脚本" || { rm -rf "$tmp"; return 1; }
    assert_contains "$content" 'flock -x 8' "回滚脚本共享全局锁" || { rm -rf "$tmp"; return 1; }
    assert_contains "$content" '[[ -e "$system_path" || -L "$system_path" ]]' "自动回滚仅对存在的目标恢复 SELinux 上下文" || { rm -rf "$tmp"; return 1; }
    assert_contains "$content" 'exported-keys.list' "自动回滚删除已导出私钥" || { rm -rf "$tmp"; return 1; }
    [[ -x "$TRANSACTION_DIR/rollback.sh" ]] || { rm -rf "$tmp"; fail "回滚脚本应可执行"; return 1; }
    rm -rf "$tmp"
}

service_detection_requires_exact_unit() {
    load_script || return 1
    local tmp
    tmp=$(mktemp -d)
    mkdir -p "$tmp/bin" "$tmp/etc"
    printf 'ID=rocky\nVERSION_ID="9"\n' > "$tmp/etc/os-release"
    cat > "$tmp/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" == *'ssh.service'* && "$*" != *'sshd.service'* ]]; then exit 0; fi
if [[ "$*" == *'sshd.service'* ]]; then printf 'sshd.service enabled\n'; exit 0; fi
exit 0
EOF
    chmod +x "$tmp/bin/systemctl"
    for command in sshd ssh-keygen tar flock sudo; do ln -s "$tmp/bin/systemctl" "$tmp/bin/$command"; done
    SYSTEM_ROOT="$tmp"
    OS_RELEASE_FILE="$tmp/etc/os-release"
    PATH="$tmp/bin:$PATH"
    detect_platform
    assert_eq sshd "$SSH_SERVICE" "精确单元检测应选择 sshd" || { rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

platform_prefers_native_ssh_service_name() {
    load_script || return 1
    local tmp
    tmp=$(mktemp -d)
    mkdir -p "$tmp/bin" "$tmp/etc"
    cat > "$tmp/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == list-unit-files ]]; then
    printf 'ssh.service enabled\nsshd.service enabled\n'
fi
exit 0
EOF
    chmod +x "$tmp/bin/systemctl"
    local command
    for command in sshd tar flock; do ln -s "$tmp/bin/systemctl" "$tmp/bin/$command"; done
    PATH="$tmp/bin:$PATH"
    SYSTEM_ROOT="$tmp"
    OS_RELEASE_FILE="$tmp/etc/os-release"
    printf 'ID=ubuntu\nVERSION_ID="22.04"\n' > "$OS_RELEASE_FILE"
    detect_platform
    assert_eq ssh "$SSH_SERVICE" "Ubuntu 应优先 ssh.service" || { rm -rf "$tmp"; return 1; }
    printf 'ID=debian\nVERSION_ID="12"\n' > "$OS_RELEASE_FILE"
    detect_platform
    assert_eq ssh "$SSH_SERVICE" "Debian 应优先 ssh.service" || { rm -rf "$tmp"; return 1; }
    printf 'ID=centos\nVERSION_ID="7"\n' > "$OS_RELEASE_FILE"
    detect_platform
    assert_eq sshd "$SSH_SERVICE" "CentOS 7 应优先 sshd.service" || { rm -rf "$tmp"; return 1; }
    printf 'ID=rocky\nVERSION_ID="9.4"\n' > "$OS_RELEASE_FILE"
    detect_platform
    assert_eq sshd "$SSH_SERVICE" "Rocky 9 应优先 sshd.service" || { rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

platform_uses_native_package_manager() {
    load_script || return 1
    local tmp log
    tmp=$(mktemp -d)
    log="$tmp/packages.log"
    mkdir -p "$tmp/bin"
    cat > "$tmp/bin/package-stub" <<'EOF'
#!/usr/bin/env bash
printf '%s %s\n' "${0##*/}" "$*" >> "$PACKAGE_LOG"
EOF
    chmod +x "$tmp/bin/package-stub"
    local command
    for command in apt-get yum dnf; do ln -s "$tmp/bin/package-stub" "$tmp/bin/$command"; done
    PACKAGE_LOG="$log"
    export PACKAGE_LOG
    PATH="$tmp/bin:$PATH"
    DRY_RUN=0
    INSTALL_PACKAGES=1
    NON_INTERACTIVE=1
    PLATFORM_FAMILY=debian
    install_package libpam-pwquality
    assert_contains "$(<"$log")" 'apt-get update' "Ubuntu/Debian 使用 apt-get update" || { rm -rf "$tmp"; return 1; }
    assert_contains "$(<"$log")" 'apt-get install -y libpam-pwquality' "Ubuntu/Debian 使用 apt-get install" || { rm -rf "$tmp"; return 1; }
    : > "$log"
    PLATFORM_FAMILY=rhel7
    install_package authconfig
    assert_contains "$(<"$log")" 'yum install -y authconfig' "CentOS 7 使用 yum" || { rm -rf "$tmp"; return 1; }
    : > "$log"
    PLATFORM_FAMILY=rhel8plus
    install_package authselect
    assert_contains "$(<"$log")" 'dnf install -y authselect' "RHEL 8/9 优先使用 dnf" || { rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

platform_matrix_completes_full_dry_run() {
    load_script || return 1
    local tmp distro version family service lockout_module output
    while IFS='|' read -r distro version family service lockout_module; do
        tmp=$(mktemp -d)
        mkdir -p "$tmp/etc/pam.d" "$tmp/etc/ssh" "$tmp/etc/security" "$tmp/bin" "$tmp/lib/security"
        printf 'ID=%s\nVERSION_ID="%s"\n' "$distro" "$version" > "$tmp/etc/os-release"
        printf 'Port 22\n' > "$tmp/etc/ssh/sshd_config"
        printf 'UID_MIN 1000\n' > "$tmp/etc/login.defs"
        touch "$tmp/lib/security/pam_pwquality.so"
        touch "$tmp/lib/security/$lockout_module"
        case "$family" in
            debian)
                printf 'auth [success=1 default=ignore] pam_unix.so nullok\nauth requisite pam_deny.so\nauth required pam_permit.so\n' > "$tmp/etc/pam.d/common-auth"
                printf 'account [success=1 new_authtok_reqd=done default=ignore] pam_unix.so\naccount requisite pam_deny.so\naccount required pam_permit.so\n' > "$tmp/etc/pam.d/common-account"
                printf 'password [success=1 default=ignore] pam_unix.so obscure\npassword requisite pam_deny.so\npassword required pam_permit.so\n' > "$tmp/etc/pam.d/common-password"
                ;;
            rhel7)
                printf 'auth required pam_unix.so\npassword requisite pam_pwquality.so retry=3\npassword sufficient pam_unix.so\n' > "$tmp/etc/pam.d/system-auth-ac"
                printf 'auth required pam_unix.so\npassword requisite pam_pwquality.so retry=3\npassword sufficient pam_unix.so\n' > "$tmp/etc/pam.d/password-auth-ac"
                ln -s system-auth-ac "$tmp/etc/pam.d/system-auth"
                ln -s password-auth-ac "$tmp/etc/pam.d/password-auth"
                ;;
            rhel8plus)
                printf 'auth required pam_unix.so\npassword requisite pam_pwquality.so retry=3\npassword sufficient pam_unix.so\n' > "$tmp/etc/pam.d/system-auth"
                printf 'auth required pam_unix.so\npassword requisite pam_pwquality.so retry=3\npassword sufficient pam_unix.so\n' > "$tmp/etc/pam.d/password-auth"
                ;;
        esac
        cat > "$tmp/bin/systemctl" <<EOF
#!/usr/bin/env bash
if [[ "\$1" == list-unit-files && "\$*" == *'$service.service'* ]]; then
    printf '%s.service enabled\n' '$service'
fi
exit 0
EOF
        cat > "$tmp/bin/authselect" <<'EOF'
#!/usr/bin/env bash
[[ "${1:-}" == check ]] && exit 0
[[ "${1:-}" == current ]] && { printf 'Profile ID: sssd\n'; exit 0; }
exit 0
EOF
        cat > "$tmp/bin/authconfig" <<'EOF'
#!/usr/bin/env bash
[[ "${1:-}" == --test ]] && { printf 'pam_faillock is disabled\n'; exit 0; }
exit 0
EOF
        chmod +x "$tmp/bin/systemctl" "$tmp/bin/authselect" "$tmp/bin/authconfig"
        local command
        for command in sshd tar flock sudo groupadd useradd usermod gpasswd chpasswd chage visudo; do
            ln -s "$tmp/bin/systemctl" "$tmp/bin/$command"
        done
        output=$(SYSTEM_ROOT="$tmp" PATH="$tmp/bin:$PATH" bash "$SCRIPT" --non-interactive --dry-run \
            --root-login disabled --admin-login password-only --root-password-action keep \
            --password-aging enable --pass-max-days 30 --pass-min-days 1 --pass-warn-age 7 \
            --apply-aging-to-existing-users yes --password-quality enable --min-password-length 8 \
            --lockout enable --deny 5 --unlock-time 900) || {
            rm -rf "$tmp"
            fail "$distro $version 完整 dry-run 失败"
            return 1
        }
        assert_contains "$output" "平台: $distro $version ($family)" "$distro $version 平台输出" || { rm -rf "$tmp"; return 1; }
        assert_contains "$output" 'PermitRootLogin no' "$distro $version SSH 配置" || { rm -rf "$tmp"; return 1; }
        assert_contains "$output" 'minlen = 8' "$distro $version 密码复杂度" || { rm -rf "$tmp"; return 1; }
        assert_contains "$output" 'deny=5 unlock_time=900' "$distro $version 登录失败锁定" || { rm -rf "$tmp"; return 1; }
        rm -rf "$tmp"
    done <<'EOF'
ubuntu|18.04|debian|ssh|pam_tally2.so
ubuntu|20.04|debian|ssh|pam_tally2.so
ubuntu|22.04|debian|ssh|pam_faillock.so
ubuntu|24.04|debian|ssh|pam_faillock.so
debian|10|debian|ssh|pam_tally2.so
debian|11|debian|ssh|pam_faillock.so
debian|12|debian|ssh|pam_faillock.so
centos|7|rhel7|sshd|pam_faillock.so
rhel|8.10|rhel8plus|sshd|pam_faillock.so
rhel|9.4|rhel8plus|sshd|pam_faillock.so
rocky|8.10|rhel8plus|sshd|pam_faillock.so
rocky|9.4|rhel8plus|sshd|pam_faillock.so
almalinux|8.10|rhel8plus|sshd|pam_faillock.so
almalinux|9.4|rhel8plus|sshd|pam_faillock.so
EOF
}

pending_transaction_blocks_new_apply() {
    load_script || return 1
    local tmp id
    tmp=$(mktemp -d)
    id=20260803T120000Z-a1b2c3d4
    mkdir -p "$tmp/$id"
    printf 'id=%s\ncreated_epoch=1\nstatus=pending-confirmation\nssh_service=sshd\n' "$id" > "$tmp/$id/metadata"
    BACKUP_ROOT="$tmp"
    if (assert_no_pending_transaction) >/dev/null 2>&1; then
        rm -rf "$tmp"
        fail "待确认事务应阻止新加固"
        return 1
    fi
    rm -rf "$tmp"
}

confirm_works_when_sudo_removes_ssh_environment() {
    load_script || return 1
    local tmp id output
    tmp=$(mktemp -d)
    id=20260805T031535Z-f9d6cfab
    mkdir -p "$tmp/$id"
    printf 'id=%s\ncreated_epoch=1\nstatus=pending-confirmation\nssh_service=sshd\napplied_epoch=100\n' "$id" > "$tmp/$id/metadata"
    output=$(
        unset SSH_CONNECTION SSH_CLIENT SSH_TTY
        BACKUP_ROOT="$tmp"
        CONFIRM_TRANSACTION="$id"
        ssh_tty_session_start_epoch() { printf '200\n'; }
        disarm_automatic_rollback() { :; }
        confirm_transaction
    ) 2>&1 || { rm -rf "$tmp"; return 1; }
    assert_contains "$output" '已确认' "sudo 清理 SSH 环境后仍可确认" || { rm -rf "$tmp"; return 1; }
    assert_contains "$(<"$tmp/$id/metadata")" 'status=confirmed' "事务状态更新为已确认" || { rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

password_aging_updates_existing_users() {
    load_script || return 1
    local tmp log uid
    tmp=$(mktemp -d)
    log="$tmp/chage.log"
    uid=1000
    mkdir -p "$tmp/etc" "$tmp/bin"
    ln -s /bin/bash "$tmp/bin/bash"
    printf 'UID_MIN 500\n' > "$tmp/etc/login.defs"
    printf 'admin:x:%s:1000:Admin:/home/admin:/bin/bash\n' "$uid" > "$tmp/etc/passwd"
    printf 'admin:$6$salt$hash:20000:0:90:14:::\n' > "$tmp/etc/shadow"
    printf '/bin/bash\n' > "$tmp/etc/shells"
    cat > "$tmp/chage" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$CHAGE_LOG"
EOF
    chmod +x "$tmp/chage"
    SYSTEM_ROOT="$tmp"
    PASSWD_FILE="$tmp/etc/passwd"
    SHADOW_FILE="$tmp/etc/shadow"
    SHELLS_FILE="$tmp/etc/shells"
    CHAGE_LOG="$log"
    export CHAGE_LOG
    PATH="$tmp:$PATH"
    hash -r
    ROOT_PASSWORD_ACTION=keep
    PASSWORD_AGING=enable
    APPLY_AGING_EXISTING=yes
    PASS_MAX_DAYS=30
    PASS_MIN_DAYS=1
    PASS_WARN_AGE=7
    NON_INTERACTIVE=1
    CONFLICT_ACTION=overwrite
    apply_account_policies
    assert_contains "$(<"$log")" '-M 30 -m 1 -W 7 admin' "普通用户密码最长 30 天" || { rm -rf "$tmp"; return 1; }
    : > "$log"
    printf 'admin:$6$salt$hash:20000:1:30:7:::\n' > "$tmp/etc/shadow"
    CONFLICT_ACTION=fail
    apply_account_policies || { rm -rf "$tmp"; return 1; }
    [[ ! -s "$log" ]] || { fail "普通用户密码周期一致时不应调用 chage"; rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

unmanaged_debian_lockout_is_rejected() {
    load_script || return 1
    local tmp
    tmp=$(mktemp -d)
    mkdir -p "$tmp/etc/pam.d" "$tmp/lib/security"
    touch "$tmp/lib/security/pam_faillock.so"
    printf 'auth required pam_faillock.so preauth\nauth [success=1 default=ignore] pam_unix.so\nauth requisite pam_deny.so\nauth required pam_permit.so\n' > "$tmp/etc/pam.d/common-auth"
    printf 'account [success=1 new_authtok_reqd=done default=ignore] pam_unix.so\naccount requisite pam_deny.so\naccount required pam_permit.so\n' > "$tmp/etc/pam.d/common-account"
    printf 'password [success=1 default=ignore] pam_unix.so\npassword requisite pam_deny.so\npassword required pam_permit.so\n' > "$tmp/etc/pam.d/common-password"
    SYSTEM_ROOT="$tmp"
    LOCKOUT=enable
    PASSWORD_QUALITY=disable
    if (prepare_debian_pam) >/dev/null 2>&1; then
        rm -rf "$tmp"
        fail "非脚本管理的 faillock 应被拒绝"
        return 1
    fi
    rm -rf "$tmp"
}

persistent_rollback_timer_is_armed() {
    load_script || return 1
    local tmp service timer metadata
    tmp=$(mktemp -d)
    mkdir -p "$tmp/bin" "$tmp/transaction/archives"
    : > "$tmp/transaction/manifest.tsv"
    printf 'id=20260803T120000Z-a1b2c3d4\ncreated_epoch=1\nstatus=preparing\nssh_service=sshd\n' > "$tmp/transaction/metadata"
    cat > "$tmp/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$SYSTEMCTL_LOG"
exit 0
EOF
    chmod +x "$tmp/bin/systemctl"
    SYSTEM_ROOT="$tmp"
    TRANSACTION_DIR="$tmp/transaction"
    TRANSACTION_ID=20260803T120000Z-a1b2c3d4
    ROLLBACK_TIMEOUT=300
    ROLLBACK_DUE_TIMESTAMP_OVERRIDE='2026-08-03 12:05:00 UTC'
    SYSTEMCTL_LOG="$tmp/systemctl.log"
    export SYSTEMCTL_LOG
    PATH="$tmp/bin:$PATH"
    arm_automatic_rollback
    service="$tmp/etc/systemd/system/server-hardening-rollback-$TRANSACTION_ID.service"
    timer="$tmp/etc/systemd/system/server-hardening-rollback-$TRANSACTION_ID.timer"
    metadata=$(<"$TRANSACTION_DIR/metadata")
    assert_contains "$(<"$service")" 'Type=simple' "CentOS 7 systemd 219 支持回滚服务的失败重启" || { rm -rf "$tmp"; return 1; }
    assert_not_contains "$(<"$service")" 'Type=oneshot' "避免 CentOS 7 拒绝 oneshot 与 Restart 组合" || { rm -rf "$tmp"; return 1; }
    assert_contains "$(<"$service")" "ExecStart=/bin/bash $TRANSACTION_DIR/rollback.sh" "服务使用 bash，兼容 noexec 挂载" || { rm -rf "$tmp"; return 1; }
    assert_contains "$(<"$timer")" 'Persistent=true' "回滚 timer 支持重启后持久化" || { rm -rf "$tmp"; return 1; }
    assert_not_contains "$(<"$timer")" ' UTC' "CentOS 7 systemd 219 的 OnCalendar 不接受时区后缀" || { rm -rf "$tmp"; return 1; }
    assert_contains "$metadata" "timer_unit=server-hardening-rollback-$TRANSACTION_ID.timer" "事务保存 timer 元数据" || { rm -rf "$tmp"; return 1; }
    assert_contains "$(<"$tmp/systemctl.log")" "start server-hardening-rollback-$TRANSACTION_ID.timer" "timer 已启动" || { rm -rf "$tmp"; return 1; }
    reset_rollback_deadline_after_apply "$TRANSACTION_DIR"
    metadata=$(<"$TRANSACTION_DIR/metadata")
    assert_contains "$metadata" 'applied_epoch=' "SSH 重载后记录 applied_epoch" || { rm -rf "$tmp"; return 1; }
    assert_contains "$(<"$tmp/systemctl.log")" "restart server-hardening-rollback-$TRANSACTION_ID.timer" "应用成功后重新计时" || { rm -rf "$tmp"; return 1; }
    disarm_automatic_rollback "$TRANSACTION_DIR"
    [[ ! -e "$service" && ! -e "$timer" ]] || { rm -rf "$tmp"; fail "取消回滚应移除 unit 文件"; return 1; }
    rm -rf "$tmp"
}

rhel_pwquality_layout_is_validated() {
    load_script || return 1
    local tmp
    tmp=$(mktemp -d)
    mkdir -p "$tmp/bin" "$tmp/etc/pam.d" "$tmp/lib/security"
    touch "$tmp/lib/security/pam_pwquality.so"
    printf 'password requisite pam_pwquality.so retry=3\npassword sufficient pam_unix.so sha512 shadow\n' > "$tmp/etc/pam.d/system-auth"
    printf 'password sufficient pam_unix.so\n' > "$tmp/etc/pam.d/password-auth"
    cat > "$tmp/bin/authselect" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    chmod +x "$tmp/bin/authselect"
    SYSTEM_ROOT="$tmp"
    PATH="$tmp/bin:$PATH"
    PLATFORM_FAMILY=rhel8plus
    PASSWORD_QUALITY=enable
    LOCKOUT=disable
    PWQUALITY_WOULD_INSTALL=0
    prepare_rhel_pam
    printf 'password requisite pam_pwquality.so minlen=8\npassword sufficient pam_unix.so\n' > "$tmp/etc/pam.d/system-auth"
    if (prepare_rhel_pam) >/dev/null 2>&1; then
        rm -rf "$tmp"
        fail "RHEL 行内 pwquality 策略应该被拒绝"
        return 1
    fi
    rm -rf "$tmp"
}

role_sudoers_enforce_separation_of_duties() {
    load_script || return 1
    local output
    output=$(render_role_sudoers) || return 1
    assert_contains "$output" 'opsadmin ALL=(ALL:ALL) ALL' "运维管理员拥有完整 sudo" || return 1
    assert_contains "$output" '/usr/local/sbin/server-hardening-audit-read system' "审计管理员仅调用固定只读查询" || return 1
    assert_contains "$output" '/usr/bin/sudoedit /etc/ssh/sshd_config' "安全管理员可编辑指定 SSH 配置" || return 1
    assert_contains "$output" '/usr/bin/systemctl reload ssh.service' "安全管理员仅重载指定 SSH 服务" || return 1
    assert_not_contains "$output" 'auditadmin ALL=(ALL' "审计管理员不得获得完整 sudo" || return 1
    assert_not_contains "$output" 'secadmin ALL=(ALL:ALL) ALL' "安全管理员不得获得无限制 sudo" || return 1
    assert_not_contains "$output" '/bin/bash' "受限角色不得调用通用 Shell" || return 1
}

audit_helper_uses_fixed_readonly_commands() {
    load_script || return 1
    local output
    output=$(render_audit_helper) || return 1
    assert_contains "$output" '#!/bin/bash' "审计辅助命令使用固定解释器" || return 1
    assert_contains "$output" '/usr/bin/journalctl --no-pager' "日志查询使用绝对路径" || return 1
    assert_contains "$output" '/usr/bin/systemctl list-units' "服务查询仅使用只读子命令" || return 1
    assert_not_contains "$output" '/usr/bin/env bash' "禁止通过 PATH 选择解释器" || return 1
    assert_not_contains "$output" 'eval ' "审计辅助命令禁止 eval" || return 1
    assert_not_contains "$output" '"$@"' "审计辅助命令禁止透传任意参数" || return 1
}

sudoers_dropin_must_be_included_by_main_policy() {
    load_script || return 1
    local tmp
    tmp=$(mktemp)
    printf '#includedir /etc/sudoers.d\n' > "$tmp"
    SUDOERS_FILE="$tmp" sudoers_dropin_is_enabled || { rm -f "$tmp"; fail "应识别 #includedir"; return 1; }
    printf '@includedir /etc/sudoers.d\n' > "$tmp"
    SUDOERS_FILE="$tmp" sudoers_dropin_is_enabled || { rm -f "$tmp"; fail "应识别 @includedir"; return 1; }
    printf 'root ALL=(ALL:ALL) ALL\n' > "$tmp"
    if SUDOERS_FILE="$tmp" sudoers_dropin_is_enabled; then
        rm -f "$tmp"
        fail "未引用 sudoers.d 时应失败"
        return 1
    fi
    rm -f "$tmp"
}

managed_account_artifacts_are_transactional() {
    load_script || return 1
    local output
    PLATFORM_FAMILY=debian
    ROOT_PASSWORD_ACTION=keep
    ROOT_LOGIN='key-only'
    ADMIN_LOGIN='key-only'
    APPLY_AGING_EXISTING=yes
    output=$(transaction_target_list) || return 1
    assert_contains "$output" '/etc/passwd' "备份账户数据库" || return 1
    assert_contains "$output" '/etc/group' "备份组数据库" || return 1
    assert_contains "$output" '/etc/shadow' "备份密码哈希" || return 1
    assert_contains "$output" '/etc/gshadow' "备份组密码数据库" || return 1
    assert_contains "$output" '/etc/subuid' "备份 useradd 可能修改的 subuid" || return 1
    assert_contains "$output" '/etc/subgid' "备份 useradd 可能修改的 subgid" || return 1
    assert_contains "$output" '/etc/sudoers.d/server-hardening-roles' "备份角色 sudoers" || return 1
    assert_contains "$output" '/usr/local/sbin/server-hardening-audit-read' "备份审计辅助命令" || return 1
    assert_contains "$output" '/opt/server-hardening/credentials.txt' "备份 root 专用凭据汇总文件" || return 1
    assert_contains "$output" '/home/opsadmin' "新建运维家目录可回滚" || return 1
    assert_contains "$output" '/home/auditadmin' "新建审计家目录可回滚" || return 1
    assert_contains "$output" '/home/secadmin' "新建安全家目录可回滚" || return 1
    assert_contains "$output" '/root/.ssh' "root 密钥登录的 authorized_keys 可回滚" || return 1
}

independent_ssh_keys_are_exported_to_invocation_directory() {
    load_script || return 1
    local tmp uid gid id user private public mode
    tmp=$(mktemp -d)
    uid=$(id -u)
    gid=$(id -g)
    id=20260804T120000Z-a1b2c3d4
    mkdir -p "$tmp/system/etc" "$tmp/system/root" "$tmp/system/home/opsadmin" \
        "$tmp/system/home/auditadmin" "$tmp/system/home/secadmin" "$tmp/transaction" "$tmp/export"
    cat > "$tmp/system/etc/passwd" <<EOF
root:x:0:0:root:/root:/bin/bash
opsadmin:x:$uid:$gid:Ops:/home/opsadmin:/bin/bash
auditadmin:x:$uid:$gid:Audit:/home/auditadmin:/bin/bash
secadmin:x:$uid:$gid:Security:/home/secadmin:/bin/bash
EOF
    SYSTEM_ROOT="$tmp/system"
    PASSWD_FILE="$tmp/system/etc/passwd"
    TRANSACTION_DIR="$tmp/transaction"
    TRANSACTION_ID="$id"
    KEY_EXPORT_DIR="$tmp/export"
    KEY_EXPORT_UID="$uid"
    KEY_EXPORT_GID="$gid"
    ROOT_LOGIN='key-only'
    ADMIN_LOGIN='password-and-key'
    hash -r
    reset_managed_ssh_key_state
    CREDENTIAL_SECTIONS=()
    provision_managed_ssh_keys
    assert_contains "$(<"$TRANSACTION_DIR/exported-keys.list")" "$tmp/export/server-hardening-root-$id-ed25519" "事务记录已导出私钥路径" || { rm -rf "$tmp"; return 1; }
    for user in root opsadmin auditadmin secadmin; do
        private="$tmp/export/server-hardening-$user-$id-ed25519"
        public="$private.pub"
        [[ -s "$private" && -s "$public" ]] || { rm -rf "$tmp"; fail "$user 密钥未导出到当前目录"; return 1; }
        mode=$(stat -c '%a' "$private" 2>/dev/null || stat -f '%Lp' "$private")
        assert_eq 600 "$mode" "$user 私钥权限" || { rm -rf "$tmp"; return 1; }
        assert_contains "$(<"$tmp/system$(awk -F: -v user="$user" '$1 == user {print $6}' "$PASSWD_FILE")/.ssh/authorized_keys")" 'ssh-ed25519 ' "$user 公钥已安装" || { rm -rf "$tmp"; return 1; }
    done
    write_credential_bundle || { rm -rf "$tmp"; return 1; }
    assert_eq 4 "$(grep -c '^\[ssh-key\]$' "$tmp/system/opt/server-hardening/credentials.txt")" "四个账户密钥写入固定凭据文件" || { rm -rf "$tmp"; return 1; }
    assert_eq 4 "$(grep -c '^-----BEGIN OPENSSH PRIVATE KEY-----$' "$tmp/system/opt/server-hardening/credentials.txt")" "固定凭据文件包含四个私钥" || { rm -rf "$tmp"; return 1; }
    cleanup_exported_ssh_keys
    [[ ! -e "$tmp/export/server-hardening-root-$id-ed25519" ]] || { rm -rf "$tmp"; fail "失败清理应删除已导出私钥"; return 1; }
    rm -rf "$tmp"
}

existing_managed_ssh_key_is_reused() {
    load_script || return 1
    local tmp uid gid key output
    tmp=$(mktemp -d)
    uid=$(id -u)
    gid=$(id -g)
    mkdir -p "$tmp/system/etc" "$tmp/system/home/opsadmin/.ssh" "$tmp/transaction" "$tmp/export"
    printf 'opsadmin:x:%s:%s:Ops:/home/opsadmin:/bin/bash\n' "$uid" "$gid" > "$tmp/system/etc/passwd"
    key="$tmp/existing"
    ssh-keygen -q -t ed25519 -N '' -C 'server-hardening:opsadmin:existing' -f "$key" || { rm -rf "$tmp"; return 1; }
    cp "$key.pub" "$tmp/system/home/opsadmin/.ssh/authorized_keys"
    reset_options
    SYSTEM_ROOT="$tmp/system"
    PASSWD_FILE="$tmp/system/etc/passwd"
    TRANSACTION_DIR="$tmp/transaction"
    TRANSACTION_ID=20260804T120000Z-a1b2c3d4
    KEY_EXPORT_DIR="$tmp/export"
    KEY_EXPORT_UID="$uid"
    KEY_EXPORT_GID="$gid"
    ROOT_LOGIN=disabled
    ADMIN_LOGIN='key-only'
    NON_INTERACTIVE=1
    CONFLICT_ACTION=fail
    output=$(provision_ssh_key_for_account opsadmin 2>&1) || { rm -rf "$tmp"; return 1; }
    assert_contains "$output" '密钥指纹: SHA256:' "已有 SSH 密钥显示指纹" || { rm -rf "$tmp"; return 1; }
    [[ -z $(find "$tmp/export" -type f -print -quit) ]] || { fail "已有受管密钥不应重新生成私钥"; rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

dry_run_without_policy_options_enters_interactive_mode() {
    load_script || return 1
    reset_options
    DRY_RUN=1
    POLICY_OPTIONS_SET=0
    should_run_interactive_wizard || fail "单独 --dry-run 应进入交互式预演" || return 1
    NON_INTERACTIVE=1
    if should_run_interactive_wizard; then
        fail "--non-interactive --dry-run 不应进入交互向导"
        return 1
    fi
}

execution_plan_prints_detailed_feature_descriptions() {
    load_script || return 1
    local output
    reset_options
    ROOT_LOGIN=disabled
    ADMIN_LOGIN='password-only'
    PASSWORD_AGING=enable
    PASS_MAX_DAYS=30
    APPLY_AGING_EXISTING=yes
    output=$(show_execution_plan) || return 1
    assert_contains "$output" 'opsadmin' "说明运维管理员权限" || return 1
    assert_contains "$output" 'auditadmin' "说明审计管理员权限" || return 1
    assert_contains "$output" 'secadmin' "说明安全管理员权限" || return 1
    assert_contains "$output" '30 天' "说明密码有效期" || return 1
    assert_contains "$output" 'root:' "说明 root SSH 登录模式" || return 1
    assert_contains "$output" '自动回滚' "说明 SSH 失联保护" || return 1
}

dry_run_preserves_fixture() {
    local tmp before output
    tmp=$(mktemp -d)
    mkdir -p "$tmp/etc/pam.d" "$tmp/etc/ssh" "$tmp/bin"
    printf 'ID=ubuntu\nVERSION_ID="22.04"\n' > "$tmp/etc/os-release"
    printf 'auth [success=1 default=ignore] pam_unix.so nullok\nauth requisite pam_deny.so\nauth required pam_permit.so\n' > "$tmp/etc/pam.d/common-auth"
    printf 'account [success=1 new_authtok_reqd=done default=ignore] pam_unix.so\naccount requisite pam_deny.so\naccount required pam_permit.so\n' > "$tmp/etc/pam.d/common-account"
    printf 'password [success=1 default=ignore] pam_unix.so obscure\npassword requisite pam_deny.so\npassword required pam_permit.so\n' > "$tmp/etc/pam.d/common-password"
    printf 'Port 22\n' > "$tmp/etc/ssh/sshd_config"
    cat > "$tmp/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == list-unit-files ]]; then
    case "$*" in
        *ssh.service*) printf 'ssh.service enabled\n' ;;
        *sshd.service*) printf 'sshd.service enabled\n' ;;
    esac
fi
exit 0
EOF
    cp "$tmp/bin/systemctl" "$tmp/bin/systemd-run"
    cp "$tmp/bin/systemctl" "$tmp/bin/sshd"
    cp "$tmp/bin/systemctl" "$tmp/bin/flock"
    for command in systemd-run sshd flock sudo groupadd useradd usermod gpasswd chpasswd chage visudo; do
        cp "$tmp/bin/systemctl" "$tmp/bin/$command"
    done
    chmod +x "$tmp/bin/"*
    before=$(find "$tmp/etc" -type f -exec cksum {} \; | sort)
    output=$(SYSTEM_ROOT="$tmp" PATH="$tmp/bin:$PATH" bash "$SCRIPT" --non-interactive --dry-run \
        --root-login disabled --admin-login password-only --root-password-action keep \
        --password-aging enable --pass-max-days 30 --pass-min-days 1 --pass-warn-age 7 \
        --apply-aging-to-existing-users yes \
        --password-quality disable --lockout disable) || {
        rm -rf "$tmp"
        fail "临时根 dry-run 应通过"
        return 1
    }
    assert_contains "$output" '[dry-run]' "dry-run 输出标记" || { rm -rf "$tmp"; return 1; }
    assert_eq "$before" "$(find "$tmp/etc" -type f -exec cksum {} \; | sort)" "dry-run 不应修改文件" || { rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

operator_prompts_do_not_consume_loop_stdin() {
    load_script || return 1
    # These loops call resolve_conflict, which prompts on stdin. Their data
    # stream must use another descriptor, or the prompt reads usernames as
    # answers and then fails on EOF, aborting and rolling back the transaction.
    if awk '/^apply_managed_accounts\(\) \{/,/^\}/' "$MODULE_DIR/accounts.sh" \
        | grep -qE 'done[[:space:]]*<[[:space:]]*<\('; then
        fail 'apply_managed_accounts 的用户名流必须使用独立描述符'
        return 1
    fi
    if awk '/^apply_account_policies\(\) \{/,/^\}/' "$MODULE_DIR/hardening.sh" \
        | grep -qE 'done[[:space:]]*<[[:space:]]*<\('; then
        fail 'apply_account_policies 的用户名流必须使用独立描述符'
        return 1
    fi
    # A prompt nested in such a loop must still receive the operator's answer.
    local decision
    decision=$(printf '2\n' | bash -c "
        source '$MODULE_DIR/core.sh' 2>/dev/null
        source '$MODULE_DIR/cli.sh' 2>/dev/null
        source '$MODULE_DIR/state.sh' 2>/dev/null
        reset_options 2>/dev/null
        CONFLICT_ACTION=''
        DECISION_LOG_READY=0
        while IFS= read -r user <&3; do
            resolve_conflict \"aging.\$user\" \"账户 \$user\" a b impact >/dev/null 2>&1 || exit 1
        done 3< <(printf 'alice\n')
        printf '%s' \"\$CONFLICT_DECISION\"") \
        || { fail '嵌套循环中的冲突提示应读到操作者输入'; return 1; }
    assert_eq skip "$decision" '嵌套提示读取操作者选择' || return 1
}

modular_layout_is_complete_and_entry_is_short() {
    local module lines count
    lines=$(wc -l < "$SCRIPT" | tr -d ' ')
    (( lines <= 200 )) || { fail "入口脚本超过 200 行（实际=${lines}）"; return 1; }
    for module in core cli state accounts artifacts ssh pam transaction hardening sysinfo; do
        [[ -r "$MODULE_DIR/$module.sh" ]] || { fail "缺少模块: $MODULE_DIR/$module.sh"; return 1; }
    done
    count=$(find "$MODULE_DIR" -maxdepth 1 -type f -name '*.sh' | wc -l | tr -d ' ')
    assert_eq 10 "$count" "模块数量" || return 1
    assert_eq 'server_hardening.sh 2.0.0' "$(bash "$SCRIPT" --version)" "模块化版本号"
}

missing_module_fails_before_execution() {
    local tmp output status
    tmp=$(mktemp -d)
    mkdir -p "$tmp/package" "$tmp/other"
    cp "$SCRIPT" "$tmp/package/server_hardening.sh"
    cp -R "$MODULE_DIR" "$tmp/package/lib"
    rm -f "$tmp/package/lib/pam.sh"
    set +e
    output=$(cd "$tmp/other" && bash "$tmp/package/server_hardening.sh" --help 2>&1)
    status=$?
    set -e
    [[ $status -ne 0 ]] || { rm -rf "$tmp"; fail "模块缺失时应返回非零状态"; return 1; }
    assert_contains "$output" '服务器加固模块不存在或不可读' "模块缺失错误" || { rm -rf "$tmp"; return 1; }
    assert_contains "$output" '/lib/pam.sh' "模块缺失路径" || { rm -rf "$tmp"; return 1; }
    assert_not_contains "$output" '服务器账户与 SSH 加固工具' "模块缺失时不进入命令处理" || { rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

entry_loads_modules_from_other_working_directory() {
    local tmp output
    tmp=$(mktemp -d)
    mkdir -p "$tmp/package" "$tmp/other"
    cp "$SCRIPT" "$tmp/package/server_hardening.sh"
    cp -R "$MODULE_DIR" "$tmp/package/lib"
    output=$(cd "$tmp/other" && bash "$tmp/package/server_hardening.sh" --help) || { rm -rf "$tmp"; return 1; }
    assert_contains "$output" '服务器账户与 SSH 加固工具' "跨目录加载模块" || { rm -rf "$tmp"; return 1; }
    assert_contains "$output" '必须完整复制 server_hardening.sh' "帮助说明完整目录部署" || { rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

canonical_package_has_no_root_duplicates() {
    [[ ! -e "$ROOT_DIR/server_hardening.sh" ]] || { fail "根目录不应保留重复入口"; return 1; }
    [[ ! -e "$ROOT_DIR/lib" ]] || { fail "根目录不应保留重复模块目录"; return 1; }
}

stub_platform_commands() {
    local dir="$1" command
    mkdir -p "$dir/bin"
    cat > "$dir/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == list-unit-files ]]; then
    printf 'ssh.service enabled\nsshd.service enabled\n'
fi
exit 0
EOF
    chmod +x "$dir/bin/systemctl"
    for command in sshd tar flock; do
        ln -sf "$dir/bin/systemctl" "$dir/bin/$command"
    done
}

unverified_platform_requires_explicit_opt_in() {
    load_script || return 1
    local tmp output status
    tmp=$(mktemp -d)
    stub_platform_commands "$tmp"
    mkdir -p "$tmp/etc"
    printf 'ID=centos\nVERSION_ID="8"\n' > "$tmp/etc/os-release"

    output=$(
        reset_options
        PATH="$tmp/bin:$PATH"
        SYSTEM_ROOT="$tmp"
        OS_RELEASE_FILE="$tmp/etc/os-release"
        ALLOW_UNVERIFIED_PLATFORM=0
        detect_platform 2>&1
    )
    status=$?
    (( status != 0 )) || { rm -rf "$tmp"; fail 'CentOS 8 缺少 --allow-unverified-platform 时必须拒绝'; return 1; }
    assert_contains "$output" '--allow-unverified-platform' '拒绝信息应指明所需参数' || { rm -rf "$tmp"; return 1; }

    output=$(
        reset_options
        PATH="$tmp/bin:$PATH"
        SYSTEM_ROOT="$tmp"
        OS_RELEASE_FILE="$tmp/etc/os-release"
        ALLOW_UNVERIFIED_PLATFORM=1
        detect_platform 2>&1 && printf 'family=%s\n' "$PLATFORM_FAMILY"
    ) || { rm -rf "$tmp"; fail '带 --allow-unverified-platform 时 CentOS 8 应继续'; return 1; }
    assert_contains "$output" 'family=rhel8plus' 'CentOS 8 应归入 rhel8plus' || { rm -rf "$tmp"; return 1; }

    # 明确拒绝的厂商托管平台不受该参数影响。
    printf 'ID=openEuler\nVERSION_ID="22.03"\n' > "$tmp/etc/os-release"
    output=$(
        reset_options
        PATH="$tmp/bin:$PATH"
        SYSTEM_ROOT="$tmp"
        OS_RELEASE_FILE="$tmp/etc/os-release"
        ALLOW_UNVERIFIED_PLATFORM=1
        detect_platform 2>&1
    )
    status=$?
    (( status != 0 )) || { rm -rf "$tmp"; fail 'openEuler 即使带参数也必须拒绝'; return 1; }
    assert_contains "$output" '不支持的系统' 'openEuler 应报告为不支持' || { rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

id_like_matching_does_not_expand_globs() {
    load_script || return 1
    local tmp
    tmp=$(mktemp -d)
    # A glob in ID_LIKE must not be expanded against the filesystem, otherwise a
    # file named after a supported family would forge a match.
    ( cd "$tmp" && touch rhel debian fedora )
    (
        cd "$tmp" || exit 1
        id_like_contains '*' rhel && exit 1
        id_like_contains '?hel' rhel && exit 1
        id_like_contains 'rhel fedora' rhel || exit 1
        id_like_contains 'RHEL' rhel || exit 1
        exit 0
    ) || { rm -rf "$tmp"; fail 'ID_LIKE 匹配不得进行路径展开'; return 1; }

    printf 'ID=unknowncorp\nVERSION_ID="1"\nID_LIKE="*"\n' > "$tmp/os-release"
    (
        cd "$tmp" || exit 1
        [[ "$(platform_classification_tier "$tmp/os-release")" == unsupported ]]
    ) || { rm -rf "$tmp"; fail 'ID_LIKE="*" 不得推断出受支持家族'; return 1; }
    rm -rf "$tmp"
}

unsupported_platform_is_rejected_before_wizard() {
    local tmp output status
    tmp=$(mktemp -d)
    stub_platform_commands "$tmp"
    mkdir -p "$tmp/etc"
    printf 'ID=openEuler\nVERSION_ID="22.03"\n' > "$tmp/etc/os-release"
    # No TTY and no policy options: reaching the wizard would fail on the TTY
    # check instead, so the platform message proves the ordering.
    output=$(SYSTEM_ROOT="$tmp" OS_RELEASE_FILE="$tmp/etc/os-release" \
        PATH="$tmp/bin:$PATH" bash "$SCRIPT" </dev/null 2>&1)
    status=$?
    (( status != 0 )) || { rm -rf "$tmp"; fail '不支持的平台必须以非零状态退出'; return 1; }
    assert_contains "$output" '不支持的系统' '应先报告平台不支持' || { rm -rf "$tmp"; return 1; }
    assert_not_contains "$output" '交互模式需要 TTY' '平台检查必须早于交互向导' || { rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

run_test 'sh 误用时提示改用 Bash' sh_invocation_reports_bash_requirement
run_test '密码默认长度与必需字符类别' password_defaults_and_classes_are_enforced
run_test '密码长度边界' password_length_boundaries_are_enforced
run_test '发行版平台检测' supported_platforms_are_detected
run_test 'SSH 支持 root 与三员独立登录模式' ssh_block_supports_root_and_admin_login_modes
run_test 'SSH Match 配置按账户展开校验' sshd_match_blocks_are_validated_for_managed_accounts
run_test 'SSH 最终生效策略一致时跳过' matching_effective_ssh_policy_is_not_rewritten
run_test 'SSH 无响应超时配置转换为中文说明' ssh_idle_timeout_values_are_explained
run_test '受管理块替换保持幂等' managed_block_replacement_is_idempotent
run_test '一致角色文件不重复写入' matching_managed_artifact_is_not_rewritten
run_test '拒绝残缺的受管理块' malformed_managed_block_is_rejected
run_test '非交互参数校验' non_interactive_options_are_validated
run_test '交互菜单使用中文说明和数字选择' numbered_menu_returns_value_and_prints_chinese_labels
run_test '一致当前值自动跳过' identical_conflict_value_is_skipped_with_current_value
run_test '交互冲突显示当前值并重试无效序号' interactive_conflict_retries_and_keeps_current_value
run_test '非交互冲突策略' non_interactive_conflict_actions_are_enforced
run_test '一致值不标记系统变更' identical_values_do_not_mark_system_changes
run_test '无变更事务跳过 SSH 重载与确认' no_change_transaction_skips_ssh_confirmation
run_test '事务决策日志落盘并屏蔽敏感值' transaction_decisions_are_flushed_and_sanitized
run_test '固定凭据文件包含本次生成的敏感数据' credential_bundle_contains_generated_credentials
run_test '无新增凭据时固定文件保持不变' credential_bundle_is_unchanged_without_new_values
run_test '凭据文件原子替换失败时保留旧文件' credential_bundle_write_failure_preserves_existing_file
run_test '凭据文件拒绝符号链接路径' credential_bundle_rejects_symlink_paths
run_test 'dry-run 不创建决策日志' dry_run_does_not_create_decision_log
run_test '跳过冲突项时输出部分应用结果' partial_result_message_does_not_claim_full_application
run_test '账户当前值读取不泄露密码哈希' account_state_readers_return_sanitized_values
run_test '受管块和文件权限当前值读取' managed_block_and_file_mode_are_readable
run_test '文件和 SSH 密钥摘要不泄露正文' file_and_managed_key_summaries_hide_content
run_test '已有策略值一致时读取并跳过' existing_policy_values_are_read_and_skipped
run_test '缺失策略文件直接创建完整目标配置' missing_policy_files_are_created_without_conflict
run_test '状态摘要拆解为可读中文字段' state_details_are_rendered_with_readable_labels
run_test '三员账户创建不重置已有密码' managed_accounts_are_created_without_resetting_existing_passwords
run_test '一致三员账户不执行修改命令' matching_managed_accounts_do_not_run_mutation_commands
run_test '配置和 shadow 备份恢复' backup_and_restore_preserve_sensitive_files
run_test '回滚删除目标时跳过 SELinux 重标记' restore_skips_selinux_relabel_for_removed_targets
run_test 'Debian PAM 受管理块' debian_pam_blocks_are_managed
run_test '复用已有 pwquality PAM 配置' existing_pwquality_line_is_reused
run_test 'RHEL 失败锁定命令路径' rhel_lockout_uses_platform_commands
run_test '回滚脚本自包含' rollback_script_is_self_contained
run_test '非 root 临时根 dry-run 不修改文件' dry_run_preserves_fixture
run_test 'SSH 服务检测要求精确单元' service_detection_requires_exact_unit
run_test '各平台优先本机 SSH 服务名' platform_prefers_native_ssh_service_name
run_test '各平台使用原生包管理器' platform_uses_native_package_manager
run_test '支持发行版矩阵完成全流程 dry-run' platform_matrix_completes_full_dry_run
run_test '待确认事务阻止新加固' pending_transaction_blocks_new_apply
run_test 'sudo 清理 SSH 环境后仍可确认事务' confirm_works_when_sudo_removes_ssh_environment
run_test '普通用户密码最长 30 天' password_aging_updates_existing_users
run_test '拒绝非受管理的 Debian 失败锁定' unmanaged_debian_lockout_is_rejected
run_test '持久回滚 timer 正确武装' persistent_rollback_timer_is_armed
run_test 'RHEL pwquality 布局校验' rhel_pwquality_layout_is_validated
run_test '三员 sudoers 分权' role_sudoers_enforce_separation_of_duties
run_test '审计辅助命令仅使用固定只读命令' audit_helper_uses_fixed_readonly_commands
run_test '主 sudoers 必须引用角色 drop-in' sudoers_dropin_must_be_included_by_main_policy
run_test '三员账户产物纳入事务' managed_account_artifacts_are_transactional
run_test '每个账户独立密钥导出到启动目录' independent_ssh_keys_are_exported_to_invocation_directory
run_test '已有受管 SSH 密钥直接复用' existing_managed_ssh_key_is_reused
run_test '单独 dry-run 进入交互式预演' dry_run_without_policy_options_enters_interactive_mode
run_test '执行计划输出详细功能说明' execution_plan_prints_detailed_feature_descriptions
run_test '模块布局完整且入口保持精简' modular_layout_is_complete_and_entry_is_short
run_test '模块缺失时在执行前明确失败' missing_module_fails_before_execution
run_test '从其他工作目录加载模块' entry_loads_modules_from_other_working_directory
run_test '服务器加固目录是唯一源码' canonical_package_has_no_root_duplicates
run_test '操作者提示不消费循环 stdin' operator_prompts_do_not_consume_loop_stdin
run_test '未实测平台需显式确认风险' unverified_platform_requires_explicit_opt_in
run_test 'ID_LIKE 匹配不做通配展开' id_like_matching_does_not_expand_globs
run_test '不支持的平台在向导前拒绝' unsupported_platform_is_rejected_before_wizard

printf '1..%d\n' "$TESTS_RUN"
if (( TESTS_FAILED > 0 )); then
    printf '%d 项测试失败\n' "$TESTS_FAILED" >&2
    exit 1
fi
