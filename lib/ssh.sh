#!/usr/bin/env bash

# Sourced by server_hardening.sh; do not execute directly.
# shellcheck disable=SC2034,SC2153

admin_ssh_keys_enabled() {
    [[ "$ADMIN_LOGIN" == key-only || "$ADMIN_LOGIN" == password-and-key ]]
}

root_ssh_key_enabled() {
    [[ "$ROOT_LOGIN" == key-only || "$ROOT_LOGIN" == password-and-key ]]
}

ssh_keys_requested() {
    root_ssh_key_enabled || admin_ssh_keys_enabled
}

root_login_summary() {
    case "$ROOT_LOGIN" in
        disabled) printf '禁止 root SSH 直接登录\n' ;;
        key-only) printf 'root 仅允许使用独立 Ed25519 密钥登录\n' ;;
        password-and-key) printf 'root 允许使用密码或独立 Ed25519 密钥登录\n' ;;
        *) return 1 ;;
    esac
}

admin_login_summary() {
    case "$ADMIN_LOGIN" in
        password-only) printf '三员账户仅允许 SSH 密码登录\n' ;;
        key-only) printf '三员账户仅允许各自的 Ed25519 密钥登录\n' ;;
        password-and-key) printf '三员账户支持密码和各自的 Ed25519 密钥登录\n' ;;
        *) return 1 ;;
    esac
}

show_root_ssh_result() {
    local private_key
    printf '\n=== root SSH 结果 ===\n'
    printf '%s\n' "$(root_login_summary)"
    if private_key=$(private_key_path_for_user root 2>/dev/null); then
        printf 'SSH 私钥: %s\n' "$private_key"
        printf 'SSH 公钥: %s.pub\n' "$private_key"
    fi
}

render_ssh_managed_block() {
    local root_login="$1" admin_login="$2" timeout="$3" interval count
    if (( timeout <= 300 )); then
        interval=$timeout
        count=1
    else
        interval=$(((timeout + 1) / 2))
        count=2
    fi
    case "$root_login" in
        disabled) printf 'PermitRootLogin no\n' ;;
        key-only) printf 'PermitRootLogin prohibit-password\n' ;;
        password-and-key) printf 'PermitRootLogin yes\n' ;;
        *) return 1 ;;
    esac
    printf 'PasswordAuthentication no\nPubkeyAuthentication yes\n'
    printf 'PermitEmptyPasswords no\nUsePAM yes\nClientAliveInterval %d\nClientAliveCountMax %d\n' "$interval" "$count"
    printf 'Match User opsadmin,auditadmin,secadmin\n'
    case "$admin_login" in
        password-only)
            printf '    PasswordAuthentication yes\n    PubkeyAuthentication no\n    AuthenticationMethods password\n'
            ;;
        key-only)
            printf '    PasswordAuthentication no\n    PubkeyAuthentication yes\n    AuthenticationMethods publickey\n'
            ;;
        password-and-key)
            printf '    PasswordAuthentication yes\n    PubkeyAuthentication yes\n'
            ;;
        *) return 1 ;;
    esac
    printf 'Match all\n'
    if [[ "$root_login" == password-and-key ]]; then
        printf 'Match User root\n'
        printf '    PasswordAuthentication yes\n    PubkeyAuthentication yes\n'
        printf 'Match all\n'
    fi
}

ssh_idle_target_values() {
    local timeout="$1" interval count
    if (( timeout <= 300 )); then interval=$timeout; count=1
    else interval=$(((timeout + 1) / 2)); count=2
    fi
    printf '%s:%s\n' "$interval" "$count"
}

sshd_effective_user_value() {
    local config="$1" user="$2" output
    output=$(sshd -T -f "$config" -C "user=$user,host=localhost,addr=127.0.0.1") || return 1
    printf '%s\n' "$output" | awk '
        $1 == "permitrootlogin" {root=$2; if (root == "without-password") root="prohibit-password"}
        $1 == "passwordauthentication" {password=$2}
        $1 == "pubkeyauthentication" {pubkey=$2}
        $1 == "authenticationmethods" {methods=$2}
        $1 == "clientaliveinterval" {interval=$2}
        $1 == "clientalivecountmax" {count=$2}
        $1 == "permitemptypasswords" {empty=$2}
        $1 == "usepam" {pam=$2}
        END {
            if (password == "" || pubkey == "" || methods == "" || interval == "" || count == "" || empty == "" || pam == "") exit 1
            printf "root=%s,password=%s,pubkey=%s,methods=%s,idle=%s:%s,empty=%s,pam=%s\n", root, password, pubkey, methods, interval, count, empty, pam
        }
    '
}

ssh_login_mode_summary() {
    local permit_root="$1" password="$2" pubkey="$3" methods="$4" account_type="$5"
    if [[ "$account_type" == root && "$permit_root" == no ]]; then
        printf '禁止登录\n'
    elif [[ "$methods" == password || ( "$password" == yes && "$pubkey" == no ) ]]; then
        printf '仅密码登录\n'
    elif [[ "$methods" == publickey || ( "$password" == no && "$pubkey" == yes ) ]]; then
        printf '仅密钥登录\n'
    elif [[ "$password" == yes && "$pubkey" == yes && "$methods" == any ]]; then
        printf '密码或密钥登录\n'
    else
        printf '自定义组合（密码=%s，密钥=%s，认证方法=%s）\n' "$password" "$pubkey" "$methods"
    fi
}

ssh_idle_timeout_summary() {
    local idle interval count total
    idle=$1
    interval=${idle%%:*}
    count=${idle#*:}
    is_uint "$interval" && is_uint "$count" || return 1
    if (( interval == 0 || count == 0 )); then
        printf '未启用（ClientAliveInterval=%s，ClientAliveCountMax=%s）\n' "$interval" "$count"
        return 0
    fi
    total=$((interval * count))
    printf '%s 秒（ClientAliveInterval=%s，ClientAliveCountMax=%s）\n' "$total" "$interval" "$count"
}

sshd_effective_policy_value() {
    local config="$1" user value result=''
    for user in root opsadmin auditadmin secadmin; do
        value=$(sshd_effective_user_value "$config" "$user") || { warn "无法读取 $user 的 SSH 最终生效配置"; return 1; }
        result="${result}${result:+;}$user{$value}"
    done
    printf '%s\n' "$result"
}

ssh_target_policy_value() {
    local idle root_permit root_password admin_password admin_pubkey admin_methods user result
    idle=$(ssh_idle_target_values "$SSH_IDLE_TIMEOUT") || return 1
    case "$ROOT_LOGIN" in
        disabled) root_permit=no; root_password=no ;;
        key-only) root_permit=prohibit-password; root_password=no ;;
        password-and-key) root_permit=yes; root_password=yes ;;
        *) return 1 ;;
    esac
    case "$ADMIN_LOGIN" in
        password-only) admin_password=yes; admin_pubkey=no; admin_methods=password ;;
        key-only) admin_password=no; admin_pubkey=yes; admin_methods=publickey ;;
        password-and-key) admin_password=yes; admin_pubkey=yes; admin_methods=any ;;
        *) return 1 ;;
    esac
    result="root{root=$root_permit,password=$root_password,pubkey=yes,methods=any,idle=$idle,empty=no,pam=yes}"
    for user in opsadmin auditadmin secadmin; do
        result="$result;$user{root=$root_permit,password=$admin_password,pubkey=$admin_pubkey,methods=$admin_methods,idle=$idle,empty=no,pam=yes}"
    done
    printf '%s\n' "$result"
}

apply_ssh_policy() {
    local config="$1" current target content
    current=$(sshd_effective_policy_value "$config") || return 1
    target=$(ssh_target_policy_value) || return 1
    resolve_conflict ssh.effective 'SSH 最终生效策略' "$current" "$target" "调整 root、三员账户认证方式和空闲超时" || return 1
    [[ "$CONFLICT_DECISION" == apply ]] || return 0
    if (( DRY_RUN )); then
        info "[dry-run] 将更新 SSH 最终生效策略"
        return 0
    fi
    content=$(render_ssh_managed_block "$ROOT_LOGIN" "$ADMIN_LOGIN" "$SSH_IDLE_TIMEOUT") || return 1
    replace_managed_block "$config" "$SSH_BLOCK_BEGIN" "$SSH_BLOCK_END" "$content" top yes
}

validate_sshd_config() {
    local config="$1" user
    sshd -t -f "$config" || return 1
    for user in root opsadmin auditadmin secadmin; do
        sshd -T -f "$config" -C "user=$user,host=localhost,addr=127.0.0.1" >/dev/null || return 1
    done
}
