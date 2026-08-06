#!/usr/bin/env bash

# Sourced by server_hardening.sh; do not execute directly.
# shellcheck disable=SC2034,SC2153

install_package() {
    local package="$1"
    if (( DRY_RUN )); then
        info "[dry-run] 将安装 $package"
        return 0
    fi
    if (( ! INSTALL_PACKAGES )); then
        if (( NON_INTERACTIVE )); then
            die "缺少软件包 ${package}；非交互模式需显式使用 --install-packages"
        fi
        local answer
        answer=$(ask_menu "缺少软件包 ${package}，是否安装" yes \
            yes '安装缺失软件包并继续' \
            no '不安装，停止本次加固')
        [[ "$answer" == yes ]] || die "缺少必需软件包 $package"
    fi
    case "$PLATFORM_FAMILY" in
        debian) DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y "$package" ;;
        rhel7) yum install -y "$package" ;;
        rhel8plus) if command_exists dnf; then dnf install -y "$package"; else yum install -y "$package"; fi ;;
    esac
    SYSTEM_CHANGE_REQUIRED=1
}

find_pam_module() {
    local module="$1" base result
    for base in "$(root_path /lib)" "$(root_path /lib64)" "$(root_path /usr/lib)" "$(root_path /usr/lib64)"; do
        [[ -d "$base" ]] || continue
        result=$(find "$base" -type f -path '*/security/*' -name "$module" -print -quit 2>/dev/null)
        [[ -z "$result" ]] || return 0
    done
    return 1
}

ensure_dependencies() {
    if [[ "$PASSWORD_QUALITY" == enable ]] && ! find_pam_module pam_pwquality.so; then
        PWQUALITY_WOULD_INSTALL=1
        case "$PLATFORM_FAMILY" in
            debian) install_package libpam-pwquality ;;
            rhel7|rhel8plus) install_package libpwquality ;;
        esac
        (( DRY_RUN )) || find_pam_module pam_pwquality.so || die "pam_pwquality.so 安装后仍不可用"
    fi
    if [[ "$LOCKOUT" == enable ]]; then
        if [[ "$PLATFORM_FAMILY" == debian ]] && ! find_pam_module pam_faillock.so && ! find_pam_module pam_tally2.so; then
            LOCKOUT_DEPENDENCY_WOULD_INSTALL=1
            install_package libpam-modules
            (( DRY_RUN )) || find_pam_module pam_faillock.so || find_pam_module pam_tally2.so || die "libpam-modules 安装后仍缺少 faillock/tally2"
        fi
        if [[ "$PLATFORM_FAMILY" == rhel8plus ]] && ! command_exists authselect; then
            LOCKOUT_DEPENDENCY_WOULD_INSTALL=1
            install_package authselect
            (( DRY_RUN )) || command_exists authselect || die "authselect 安装后仍不可用"
        fi
        if [[ "$PLATFORM_FAMILY" == rhel7 ]] && ! command_exists authconfig; then
            LOCKOUT_DEPENDENCY_WOULD_INSTALL=1
            install_package authconfig
            (( DRY_RUN )) || command_exists authconfig || die "authconfig 安装后仍不可用"
        fi
    fi
}

strip_managed_block_to_file() {
    local source="$1" begin="$2" end="$3" output="$4"
    awk -v begin="$begin" -v end="$end" '
        $0 == begin {inside=1; next}
        $0 == end {inside=0; next}
        !inside {print}
    ' "$source" > "$output"
}

insert_before_first_match() {
    local file="$1" regex="$2" block="$3" tmp line
    line=$(grep -n -m1 -E "$regex" "$file" | cut -d: -f1) || return 1
    [[ -n "$line" ]] || return 1
    tmp=$(mktemp "$(dirname "$file")/.server-hardening.XXXXXX")
    {
        if (( line > 1 )); then sed -n "1,$((line - 1))p" "$file"; fi
        printf '%s\n' "$block"
        sed -n "${line},\$p" "$file"
    } > "$tmp"
    chmod --reference="$file" "$tmp" 2>/dev/null || chmod 0644 "$tmp"
    chown --reference="$file" "$tmp" 2>/dev/null || true
    mv -f "$tmp" "$file"
}

insert_after_first_match() {
    local file="$1" regex="$2" block="$3" tmp line
    line=$(grep -n -m1 -E "$regex" "$file" | cut -d: -f1) || return 1
    [[ -n "$line" ]] || return 1
    tmp=$(mktemp "$(dirname "$file")/.server-hardening.XXXXXX")
    {
        sed -n "1,${line}p" "$file"
        printf '%s\n' "$block"
        sed -n "$((line + 1)),\$p" "$file"
    } > "$tmp"
    chmod --reference="$file" "$tmp" 2>/dev/null || chmod 0644 "$tmp"
    chown --reference="$file" "$tmp" 2>/dev/null || true
    mv -f "$tmp" "$file"
}

replace_pam_unix_control() {
    local file="$1" old="$2" new="$3" tmp
    tmp=$(mktemp "$(dirname "$file")/.server-hardening.XXXXXX")
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" == *'pam_unix.so'* && "$line" == *"$old"* ]]; then
            printf '%s%s%s\n' "${line%%"$old"*}" "$new" "${line#*"$old"}"
        else
            printf '%s\n' "$line"
        fi
    done < "$file" > "$tmp"
    chmod --reference="$file" "$tmp" 2>/dev/null || chmod 0644 "$tmp"
    chown --reference="$file" "$tmp" 2>/dev/null || true
    mv -f "$tmp" "$file"
}

prepare_debian_pam() {
    local common_auth common_account common_password module stripped auth_line account_line password_line quality_line quality_count has_authfail_block
    common_auth=$(root_path /etc/pam.d/common-auth)
    common_account=$(root_path /etc/pam.d/common-account)
    common_password=$(root_path /etc/pam.d/common-password)
    [[ -f "$common_auth" && -f "$common_account" && -f "$common_password" ]] || die "Debian/Ubuntu PAM 标准文件不完整"
    auth_line=$(grep -E '^[[:space:]]*auth[[:space:]]+\[success=[12][[:space:]]+default=ignore\][[:space:]]+pam_unix\.so' "$common_auth" || true)
    account_line=$(grep -E '^[[:space:]]*account[[:space:]]+\[success=1[[:space:]]+new_authtok_reqd=done[[:space:]]+default=ignore\][[:space:]]+pam_unix\.so' "$common_account" || true)
    password_line=$(grep -E '^[[:space:]]*password[[:space:]]+\[success=1[[:space:]]+default=ignore\][[:space:]]+pam_unix\.so' "$common_password" || true)
    [[ $(printf '%s\n' "$auth_line" | grep -c .) == 1 ]] || die "common-auth 不是可识别的 Debian 标准控制流"
    [[ $(printf '%s\n' "$account_line" | grep -c .) == 1 ]] || die "common-account 不是可识别的 Debian 标准控制流"
    [[ $(printf '%s\n' "$password_line" | grep -c .) == 1 ]] || die "common-password 不是可识别的 Debian 标准控制流"
    managed_markers_valid "$common_auth" "$PAM_AUTH_BLOCK_BEGIN" "$PAM_AUTH_BLOCK_END" || die "common-auth 锁定受管理块损坏"
    managed_markers_valid "$common_auth" "$PAM_AUTHFAIL_BLOCK_BEGIN" "$PAM_AUTHFAIL_BLOCK_END" || die "common-auth 失败记录受管理块损坏"
    managed_markers_valid "$common_account" "$PAM_ACCOUNT_BLOCK_BEGIN" "$PAM_ACCOUNT_BLOCK_END" || die "common-account 受管理块损坏"
    managed_markers_valid "$common_password" "$PAM_PASSWORD_BLOCK_BEGIN" "$PAM_PASSWORD_BLOCK_END" || die "common-password 受管理块损坏"
    stripped=$(mktemp)
    strip_managed_block_to_file "$common_auth" "$PAM_AUTH_BLOCK_BEGIN" "$PAM_AUTH_BLOCK_END" "$stripped"
    local stripped_authfail
    stripped_authfail=$(mktemp)
    strip_managed_block_to_file "$stripped" "$PAM_AUTHFAIL_BLOCK_BEGIN" "$PAM_AUTHFAIL_BLOCK_END" "$stripped_authfail"
    if grep -Eq '^[[:space:]]*auth.*pam_(faillock|tally2)\.so' "$stripped_authfail"; then
        rm -f "$stripped" "$stripped_authfail"
        die "common-auth 已存在非本脚本管理的 faillock/tally2 配置"
    fi
    rm -f "$stripped" "$stripped_authfail"
    stripped=$(mktemp)
    strip_managed_block_to_file "$common_account" "$PAM_ACCOUNT_BLOCK_BEGIN" "$PAM_ACCOUNT_BLOCK_END" "$stripped"
    if grep -Eq '^[[:space:]]*account.*pam_(faillock|tally2)\.so' "$stripped"; then
        rm -f "$stripped"
        die "common-account 已存在非本脚本管理的 faillock/tally2 配置"
    fi
    rm -f "$stripped"
    has_authfail_block=0
    grep -qF "$PAM_AUTHFAIL_BLOCK_BEGIN" "$common_auth" && has_authfail_block=1
    if [[ "$auth_line" == *'success=2 '* && "$has_authfail_block" == 0 ]]; then
        die "common-auth 使用 success=2 但缺少本脚本的 authfail 受管理块"
    fi
    if [[ "$auth_line" == *'success=1 '* && "$has_authfail_block" == 1 ]]; then
        die "common-auth 的 authfail 受管理块与 pam_unix.so 跳转计数不一致"
    fi
    if [[ "$PASSWORD_QUALITY" == enable ]]; then
        (( DRY_RUN && PWQUALITY_WOULD_INSTALL )) || find_pam_module pam_pwquality.so || die "pam_pwquality.so 安装后仍不可用"
        stripped=$(mktemp)
        strip_managed_block_to_file "$common_password" "$PAM_PASSWORD_BLOCK_BEGIN" "$PAM_PASSWORD_BLOCK_END" "$stripped"
        quality_line=$(grep -E '^[[:space:]]*password[[:space:]]+(requisite|required)[[:space:]]+pam_pwquality\.so' "$stripped" || true)
        quality_count=$(grep -Ec '^[[:space:]]*password.*pam_pwquality\.so' "$stripped" || true)
        if (( quality_count == 0 )); then
            PAM_PWQUALITY_LINE_NEEDED=1
        else
            (( quality_count == 1 )) || { rm -f "$stripped"; die "common-password 包含多个非受管理的 pam_pwquality.so"; }
            [[ -n "$quality_line" ]] || { rm -f "$stripped"; die "common-password 的 pam_pwquality.so control 不可识别"; }
            [[ "$quality_line" != *' conf='* && "$quality_line" != *' minlen='* && "$quality_line" != *'credit='* && "$quality_line" != *'maxrepeat='* ]] || { rm -f "$stripped"; die "pam_pwquality.so 行内参数与统一 pwquality.conf 冲突"; }
            (( $(grep -nF "$quality_line" "$stripped" | cut -d: -f1) < $(grep -n 'pam_unix\.so' "$stripped" | cut -d: -f1) )) || { rm -f "$stripped"; die "pam_pwquality.so 必须位于 pam_unix.so 之前"; }
        fi
        rm -f "$stripped"
    fi
    if [[ "$LOCKOUT" == enable ]]; then
        if find_pam_module pam_faillock.so; then module=faillock; elif find_pam_module pam_tally2.so; then module=tally2; elif (( DRY_RUN && LOCKOUT_DEPENDENCY_WOULD_INSTALL )); then module=faillock; else die "无可用的 faillock/tally2 模块"; fi
        PAM_LOCKOUT_MODULE=$module
    else
        PAM_LOCKOUT_MODULE=''
    fi
}

managed_block_matches() {
    local file="$1" begin="$2" end="$3" expected="$4" current
    if [[ "$expected" == absent ]]; then
        if grep -Fqx "$begin" "$file"; then return 1; fi
        return 0
    fi
    current=$(managed_block_content "$file" "$begin" "$end") || return 1
    [[ "$current" == "$expected" ]]
}

debian_pam_policy_target_summary() {
    local quality
    if [[ "$PASSWORD_QUALITY" == enable ]]; then quality=enabled; else quality=disabled; fi
    if [[ "$LOCKOUT" == enable ]]; then
        printf 'lockout=%s,deny=%s,unlock-time=%s,quality=%s\n' "$PAM_LOCKOUT_MODULE" "$LOCKOUT_DENY" "$UNLOCK_TIME" "$quality"
    else
        printf 'lockout=disabled,quality=%s\n' "$quality"
    fi
}

debian_pam_policy_current_summary() {
    local common_auth common_account common_password auth_digest account_digest password_digest
    common_auth=$(root_path /etc/pam.d/common-auth)
    common_account=$(root_path /etc/pam.d/common-account)
    common_password=$(root_path /etc/pam.d/common-password)
    auth_digest=$(file_sha256_value "$common_auth") || return 1
    account_digest=$(file_sha256_value "$common_account") || return 1
    password_digest=$(file_sha256_value "$common_password") || return 1
    printf 'auth-sha256=%s,account-sha256=%s,password-sha256=%s\n' "$auth_digest" "$account_digest" "$password_digest"
}

debian_pam_policy_is_current() {
    local common_auth common_account common_password auth_expected authfail_expected account_expected password_expected control
    common_auth=$(root_path /etc/pam.d/common-auth)
    common_account=$(root_path /etc/pam.d/common-account)
    common_password=$(root_path /etc/pam.d/common-password)
    auth_expected=absent
    authfail_expected=absent
    account_expected=absent
    password_expected=absent
    control='[success=1 default=ignore]'

    if [[ "$LOCKOUT" == enable && "$PAM_LOCKOUT_MODULE" == faillock ]]; then
        auth_expected='auth required pam_faillock.so preauth silent'
        authfail_expected='auth [default=die] pam_faillock.so authfail'
        account_expected='account required pam_faillock.so'
        control='[success=2 default=ignore]'
    elif [[ "$LOCKOUT" == enable && "$PAM_LOCKOUT_MODULE" == tally2 ]]; then
        auth_expected="auth required pam_tally2.so onerr=fail deny=$LOCKOUT_DENY unlock_time=$UNLOCK_TIME"
        account_expected='account required pam_tally2.so'
    fi
    if [[ "$PASSWORD_QUALITY" == enable && "$PAM_PWQUALITY_LINE_NEEDED" == 1 ]]; then
        password_expected='password requisite pam_pwquality.so retry=3'
    fi

    managed_block_matches "$common_auth" "$PAM_AUTH_BLOCK_BEGIN" "$PAM_AUTH_BLOCK_END" "$auth_expected" || return 1
    managed_block_matches "$common_auth" "$PAM_AUTHFAIL_BLOCK_BEGIN" "$PAM_AUTHFAIL_BLOCK_END" "$authfail_expected" || return 1
    managed_block_matches "$common_account" "$PAM_ACCOUNT_BLOCK_BEGIN" "$PAM_ACCOUNT_BLOCK_END" "$account_expected" || return 1
    managed_block_matches "$common_password" "$PAM_PASSWORD_BLOCK_BEGIN" "$PAM_PASSWORD_BLOCK_END" "$password_expected" || return 1
    [[ $(awk -v control="$control" '$1 == "auth" && ($2 " " $3) == control && $4 == "pam_unix.so" {count++} END {print count + 0}' "$common_auth") == 1 ]] || return 1
}

apply_debian_pam() {
    local common_auth common_account common_password auth_block authfail_block account_block password_block current target
    common_auth=$(root_path /etc/pam.d/common-auth)
    common_account=$(root_path /etc/pam.d/common-account)
    common_password=$(root_path /etc/pam.d/common-password)

    target=$(debian_pam_policy_target_summary) || return 1
    if debian_pam_policy_is_current; then
        resolve_conflict pam.debian 'Debian/Ubuntu PAM 策略组' "$target" "$target" "保留当前登录锁定和密码质量配置" || return 1
        return 0
    fi
    current=$(debian_pam_policy_current_summary) || return 1
    resolve_conflict pam.debian 'Debian/Ubuntu PAM 策略组' "$current" "$target" "调整登录锁定和密码质量控制流" || return 1
    [[ "$CONFLICT_DECISION" == apply ]] || return 0
    if (( DRY_RUN )); then info "[dry-run] 将更新 Debian/Ubuntu PAM 策略组"; return 0; fi

    remove_managed_block "$common_auth" "$PAM_AUTH_BLOCK_BEGIN" "$PAM_AUTH_BLOCK_END"
    remove_managed_block "$common_auth" "$PAM_AUTHFAIL_BLOCK_BEGIN" "$PAM_AUTHFAIL_BLOCK_END"
    remove_managed_block "$common_account" "$PAM_ACCOUNT_BLOCK_BEGIN" "$PAM_ACCOUNT_BLOCK_END"
    remove_managed_block "$common_password" "$PAM_PASSWORD_BLOCK_BEGIN" "$PAM_PASSWORD_BLOCK_END"
    if grep -qE '^[[:space:]]*auth[[:space:]]+\[success=2[[:space:]]+default=ignore\][[:space:]]+pam_unix\.so' "$common_auth"; then
        replace_pam_unix_control "$common_auth" '[success=2 default=ignore]' '[success=1 default=ignore]'
    fi

    if [[ "$LOCKOUT" == enable ]]; then
        if [[ "$PAM_LOCKOUT_MODULE" == faillock ]]; then
            auth_block="$PAM_AUTH_BLOCK_BEGIN
auth required pam_faillock.so preauth silent
$PAM_AUTH_BLOCK_END"
            authfail_block="$PAM_AUTHFAIL_BLOCK_BEGIN
auth [default=die] pam_faillock.so authfail
$PAM_AUTHFAIL_BLOCK_END"
            account_block="$PAM_ACCOUNT_BLOCK_BEGIN
account required pam_faillock.so
$PAM_ACCOUNT_BLOCK_END"
        else
            auth_block="$PAM_AUTH_BLOCK_BEGIN
auth required pam_tally2.so onerr=fail deny=$LOCKOUT_DENY unlock_time=$UNLOCK_TIME
$PAM_AUTH_BLOCK_END"
            account_block="$PAM_ACCOUNT_BLOCK_BEGIN
account required pam_tally2.so
$PAM_ACCOUNT_BLOCK_END"
        fi
        insert_before_first_match "$common_auth" 'pam_unix\.so' "$auth_block" || die "无法在 common-auth 安全插入锁定配置"
        if [[ "$PAM_LOCKOUT_MODULE" == faillock ]]; then
            replace_pam_unix_control "$common_auth" '[success=1 default=ignore]' '[success=2 default=ignore]'
            insert_after_first_match "$common_auth" 'pam_unix\.so' "$authfail_block" || die "无法在 common-auth 安全插入失败记录配置"
        fi
        insert_before_first_match "$common_account" 'pam_unix\.so' "$account_block" || die "无法在 common-account 安全插入锁定配置"
    fi
    if [[ "$PASSWORD_QUALITY" == enable && "$PAM_PWQUALITY_LINE_NEEDED" == 1 ]]; then
        password_block="$PAM_PASSWORD_BLOCK_BEGIN
password requisite pam_pwquality.so retry=3
$PAM_PASSWORD_BLOCK_END"
        insert_before_first_match "$common_password" 'pam_unix\.so' "$password_block" || die "无法在 common-password 安全插入密码质量配置"
    fi
}

prepare_rhel_pam() {
    if [[ "$PLATFORM_FAMILY" == rhel8plus ]]; then
        PAM_LOCKOUT_MARKER=$(root_path /var/lib/server-hardening/authselect-faillock.enabled)
    else
        PAM_LOCKOUT_MARKER=$(root_path /var/lib/server-hardening/authconfig-faillock.enabled)
    fi
    if [[ -f "$PAM_LOCKOUT_MARKER" ]]; then
        PAM_LOCKOUT_WAS_MANAGED=1
    fi
    if [[ "$PLATFORM_FAMILY" == rhel8plus ]]; then
        if command_exists authselect; then
            authselect check >/dev/null 2>&1 || die "authselect 检测到当前 PAM 配置不可管理"
        elif ! ( (( DRY_RUN )) && (( LOCKOUT_DEPENDENCY_WOULD_INSTALL )) ); then
            die "RHEL/Rocky/AlmaLinux 8/9 需要 authselect"
        fi
    else
        [[ -f $(root_path /etc/pam.d/system-auth) && -f $(root_path /etc/pam.d/password-auth) ]] || die "CentOS 7 PAM 标准文件不完整"
        [[ -L $(root_path /etc/pam.d/system-auth) && -L $(root_path /etc/pam.d/password-auth) ]] || die "CentOS 7 PAM 不是 authconfig 标准 symlink 布局"
        [[ $(basename "$(readlink "$(root_path /etc/pam.d/system-auth)")") == system-auth-ac ]] || die "system-auth symlink 不指向 system-auth-ac"
        [[ $(basename "$(readlink "$(root_path /etc/pam.d/password-auth)")") == password-auth-ac ]] || die "password-auth symlink 不指向 password-auth-ac"
        if command_exists authconfig; then
            authconfig --test >/dev/null 2>&1 || die "authconfig 无法读取当前认证状态"
        elif ! ( (( DRY_RUN )) && (( LOCKOUT_DEPENDENCY_WOULD_INSTALL )) ); then
            die "CentOS 7 需要 authconfig"
        fi
    fi
    if [[ "$PASSWORD_QUALITY" == enable ]]; then
        local system_auth quality_lines quality_count quality_line
        system_auth=$(root_path /etc/pam.d/system-auth)
        if (( DRY_RUN && PWQUALITY_WOULD_INSTALL )); then
            :
        else
            quality_lines=$(grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$system_auth" | grep -E '^[[:space:]]*password[[:space:]]+(requisite|required)[[:space:]]+pam_pwquality\.so' || true)
            quality_count=$(printf '%s\n' "$quality_lines" | grep -c . || true)
            (( quality_count == 1 )) || die "RHEL PAM 栈的 pam_pwquality.so 数量不是 1"
            quality_line=$quality_lines
            [[ "$quality_line" != *' conf='* && "$quality_line" != *' minlen='* && "$quality_line" != *'credit='* && "$quality_line" != *'maxrepeat='* ]] || die "RHEL pam_pwquality.so 包含与 pwquality.conf 冲突的行内参数"
            local quality_line_number password_unix_line_number
            quality_line_number=$(grep -nF "$quality_line" "$system_auth" | head -1 | cut -d: -f1)
            password_unix_line_number=$(grep -nE '^[[:space:]]*password[[:space:]].*pam_unix\.so' "$system_auth" | head -1 | cut -d: -f1)
            if ! is_uint "$quality_line_number" || ! is_uint "$password_unix_line_number"; then
                die "RHEL PAM 栈缺少可识别的 password pam_unix.so 顺序锚点"
            fi
            (( quality_line_number < password_unix_line_number )) || die "RHEL pam_pwquality.so 必须位于 password pam_unix.so 之前"
        fi
    fi
}

apply_rhel_pam() {
    if [[ "$LOCKOUT" == enable ]]; then
        if [[ "$PLATFORM_FAMILY" == rhel8plus ]]; then
            if ! authselect current 2>/dev/null | grep -q 'with-faillock'; then
                authselect enable-feature with-faillock
                authselect apply-changes
                SYSTEM_CHANGE_REQUIRED=1
                install -d -m 0700 "$(dirname "$PAM_LOCKOUT_MARKER")"
                install -m 0600 /dev/null "$PAM_LOCKOUT_MARKER"
            fi
        else
            local authconfig_state
            authconfig_state=$(authconfig --test 2>/dev/null) || die "authconfig --test 失败"
            if grep -Eiq 'pam_faillock.*disabled|faillock.*disabled' <<< "$authconfig_state"; then
                authconfig --enablefaillock --faillockargs="deny=$LOCKOUT_DENY unlock_time=$UNLOCK_TIME" --update
                SYSTEM_CHANGE_REQUIRED=1
                install -d -m 0700 "$(dirname "$PAM_LOCKOUT_MARKER")"
                install -m 0600 /dev/null "$PAM_LOCKOUT_MARKER"
            elif ! grep -Eiq 'pam_faillock.*enabled|faillock.*enabled' <<< "$authconfig_state"; then
                die "无法从 authconfig --test 识别 faillock 当前状态"
            fi
        fi
    elif (( PAM_LOCKOUT_WAS_MANAGED )); then
        if [[ "$PLATFORM_FAMILY" == rhel8plus ]]; then
            authselect disable-feature with-faillock
            authselect apply-changes
            SYSTEM_CHANGE_REQUIRED=1
        else
            authconfig --disablefaillock --update
            SYSTEM_CHANGE_REQUIRED=1
        fi
        rm -f "$PAM_LOCKOUT_MARKER"
    fi
}
