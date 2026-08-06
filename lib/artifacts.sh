#!/usr/bin/env bash

# Sourced by server_hardening.sh; do not execute directly.
# shellcheck disable=SC2034,SC2153

record_account_credential() {
    local user="$1" password="$2" section
    printf -v section '[account]\nusername=%s\npassword=%s\nfirst_login_password_change=yes' "$user" "$password"
    CREDENTIAL_SECTIONS+=("$section")
}

record_root_password_credential() {
    local password="$1" section
    printf -v section '[root-password]\nusername=root\npassword=%s' "$password"
    CREDENTIAL_SECTIONS+=("$section")
}

record_ssh_key_credential() {
    local user="$1" public_key="$2" private_key="$3" section
    printf -v section '[ssh-key]\nusername=%s\npublic_key=%s\nprivate_key_begin\n%s\nprivate_key_end' \
        "$user" "$public_key" "$private_key"
    CREDENTIAL_SECTIONS+=("$section")
}

credential_bundle_has_new_values() {
    (( ${#CREDENTIAL_SECTIONS[@]} > 0 ))
}

validate_credential_bundle_path() {
    local opt_dir bundle_dir bundle
    opt_dir=$(root_path /opt)
    bundle_dir=$(root_path "$(dirname "$CREDENTIAL_BUNDLE_PATH")")
    bundle=$(root_path "$CREDENTIAL_BUNDLE_PATH")
    [[ ! -L "$opt_dir" ]] || { warn "凭据目录父路径不能是符号链接: /opt"; return 1; }
    [[ ! -L "$bundle_dir" ]] || { warn "凭据目录不能是符号链接: $(dirname "$CREDENTIAL_BUNDLE_PATH")"; return 1; }
    [[ ! -L "$bundle" ]] || { warn "凭据文件不能是符号链接: $CREDENTIAL_BUNDLE_PATH"; return 1; }
}

write_credential_bundle() {
    local bundle_dir bundle tmp section
    if ! credential_bundle_has_new_values; then
        info "本次无新增凭据，文件未修改: $CREDENTIAL_BUNDLE_PATH"
        return 0
    fi
    validate_credential_bundle_path || return 1
    bundle_dir=$(root_path "$(dirname "$CREDENTIAL_BUNDLE_PATH")")
    bundle=$(root_path "$CREDENTIAL_BUNDLE_PATH")
    install -d -m 0700 "$bundle_dir" || return 1
    chown_for_system_root 0:0 "$bundle_dir" || return 1
    tmp=$(mktemp "$bundle_dir/.credentials.XXXXXX") || return 1
    chmod 0600 "$tmp" || { rm -f "$tmp"; return 1; }
    chown_for_system_root 0:0 "$tmp" || { rm -f "$tmp"; return 1; }
    {
        printf '# server_hardening.sh credentials\n'
        printf 'transaction_id=%s\n' "$TRANSACTION_ID"
        printf 'generated_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        for section in "${CREDENTIAL_SECTIONS[@]}"; do
            printf '\n%s\n' "$section"
        done
    } > "$tmp" || { rm -f "$tmp"; return 1; }
    chmod 0600 "$tmp" || { rm -f "$tmp"; return 1; }
    chown_for_system_root 0:0 "$tmp" || { rm -f "$tmp"; return 1; }
    mv -f "$tmp" "$bundle" || { rm -f "$tmp"; return 1; }
    if [[ "$SYSTEM_ROOT" == / ]] && command_exists restorecon; then
        restorecon -F "$bundle_dir" "$bundle" >/dev/null 2>&1 || return 1
    fi
    SYSTEM_CHANGE_REQUIRED=1
    info "本次新增凭据已汇总到: ${CREDENTIAL_BUNDLE_PATH}（仅 root 可读取）"
}

render_role_sudoers() {
    cat <<'EOF'
# Managed by server_hardening.sh. Manual changes will be replaced.
Defaults:opsadmin use_pty
Defaults:auditadmin use_pty
Defaults:secadmin use_pty

# 运维管理员: 完整 sudo，需要输入本人密码。
opsadmin ALL=(ALL:ALL) ALL

# 审计管理员: 仅允许固定的只读查询。
Cmnd_Alias SERVER_HARDENING_AUDIT_READ = \
    /usr/local/sbin/server-hardening-audit-read system, \
    /usr/local/sbin/server-hardening-audit-read auth, \
    /usr/local/sbin/server-hardening-audit-read audit, \
    /usr/local/sbin/server-hardening-audit-read services, \
    /usr/local/sbin/server-hardening-audit-read listeners
auditadmin ALL=(root) NOPASSWD: SERVER_HARDENING_AUDIT_READ

# 安全管理员: 仅允许指定配置、SSH 校验/重载和防火墙命令。
Cmnd_Alias SERVER_HARDENING_SECURITY_EDIT = \
    /usr/bin/sudoedit /etc/ssh/sshd_config, \
    /usr/bin/sudoedit /etc/pam.d/common-auth, \
    /usr/bin/sudoedit /etc/pam.d/common-account, \
    /usr/bin/sudoedit /etc/pam.d/common-password, \
    /usr/bin/sudoedit /etc/pam.d/system-auth, \
    /usr/bin/sudoedit /etc/pam.d/password-auth, \
    /usr/bin/sudoedit /etc/security/pwquality.conf, \
    /usr/bin/sudoedit /etc/security/faillock.conf
Cmnd_Alias SERVER_HARDENING_SECURITY_SSH = \
    /usr/sbin/sshd -t -f /etc/ssh/sshd_config, \
    /sbin/sshd -t -f /etc/ssh/sshd_config, \
    /usr/bin/systemctl reload ssh.service, \
    /usr/bin/systemctl reload sshd.service, \
    /bin/systemctl reload ssh.service, \
    /bin/systemctl reload sshd.service
Cmnd_Alias SERVER_HARDENING_SECURITY_FIREWALL = \
    /usr/sbin/ufw *, \
    /sbin/ufw *, \
    /usr/bin/firewall-cmd *, \
    /bin/firewall-cmd *
secadmin ALL=(root) SERVER_HARDENING_SECURITY_EDIT, SERVER_HARDENING_SECURITY_SSH, SERVER_HARDENING_SECURITY_FIREWALL
EOF
}

render_audit_helper() {
    cat <<'EOF'
#!/bin/bash
set -euo pipefail

case "${1:-}" in
    system)
        exec /usr/bin/journalctl --no-pager -n 200
        ;;
    auth)
        exec /usr/bin/journalctl --no-pager -n 200 -u ssh.service -u sshd.service
        ;;
    audit)
        [[ -r /var/log/audit/audit.log ]] || { printf 'auditd 日志不存在或不可读\n' >&2; exit 1; }
        exec /usr/bin/tail -n 200 /var/log/audit/audit.log
        ;;
    services)
        exec /usr/bin/systemctl list-units --type=service --all --no-pager
        ;;
    listeners)
        if [[ -x /usr/bin/ss ]]; then exec /usr/bin/ss -lntup; fi
        if [[ -x /usr/sbin/ss ]]; then exec /usr/sbin/ss -lntup; fi
        printf 'ss 命令不可用\n' >&2
        exit 1
        ;;
    *)
        printf '用法: %s system|auth|audit|services|listeners\n' "$0" >&2
        exit 2
        ;;
esac
EOF
}

write_managed_artifact() {
    local path="$1" mode="$2" content="$3" directory tmp current target
    directory=$(dirname "$path")
    install -d -m 0755 "$directory"
    [[ ! -L "$path" ]] || { warn "拒绝覆盖符号链接: $path"; return 1; }
    tmp=$(mktemp "$directory/.server-hardening.XXXXXX")
    printf '%s\n' "$content" > "$tmp"
    chmod "$mode" "$tmp"
    chown_for_system_root 0:0 "$tmp" || { rm -f "$tmp"; return 1; }
    if [[ -e "$path" ]]; then
        current=$(file_state_summary "$path" "$mode") || { rm -f "$tmp"; return 1; }
        target=$(file_state_summary "$tmp" "$mode") || { rm -f "$tmp"; return 1; }
        resolve_conflict "artifact.$path" "受管理文件 $path" "$current" "$target" "替换文件内容、权限或属主" || { rm -f "$tmp"; return 1; }
        if [[ "$CONFLICT_DECISION" == skip ]]; then
            rm -f "$tmp"
            return 0
        fi
    fi
    mv -f "$tmp" "$path"
    SYSTEM_CHANGE_REQUIRED=1
}

apply_role_artifacts() {
    local sudoers helper
    sudoers=$(root_path "$ROLE_SUDOERS_PATH")
    helper=$(root_path "$AUDIT_HELPER_PATH")
    write_managed_artifact "$helper" 0755 "$(render_audit_helper)"
    write_managed_artifact "$sudoers" 0440 "$(render_role_sudoers)"
    visudo -cf "$sudoers" >/dev/null
    visudo -c >/dev/null
}
