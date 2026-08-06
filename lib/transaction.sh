#!/usr/bin/env bash

# Sourced by server_hardening.sh; do not execute directly.
# shellcheck disable=SC2034,SC2153

create_transaction() {
    local stamp random line
    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    random=$(od -An -N4 -tx4 < /dev/urandom | tr -d ' ')
    TRANSACTION_ID="$stamp-$random"
    TRANSACTION_DIR="${BACKUP_ROOT%/}/$TRANSACTION_ID"
    if (( DRY_RUN )); then return 0; fi
    [[ "$BACKUP_ROOT" == /* && "$BACKUP_ROOT" != *[[:space:]]* ]] || die "备份目录必须是不含空白的绝对路径"
    [[ ! -e "$TRANSACTION_DIR" ]] || die "事务目录已存在: $TRANSACTION_DIR"
    install -d -m 0700 "$BACKUP_ROOT" "$TRANSACTION_DIR" "$TRANSACTION_DIR/archives"
    : > "$TRANSACTION_DIR/manifest.tsv"
    chmod 0600 "$TRANSACTION_DIR/manifest.tsv"
    : > "$TRANSACTION_DIR/exported-keys.list"
    chmod 0600 "$TRANSACTION_DIR/exported-keys.list"
    : > "$TRANSACTION_DIR/decisions.tsv"
    chmod 0600 "$TRANSACTION_DIR/decisions.tsv"
    for line in "${DECISION_RECORDS[@]:-}"; do
        [[ -n "$line" ]] || continue
        printf '%s\n' "$line" >> "$TRANSACTION_DIR/decisions.tsv"
    done
    DECISION_RECORDS=()
    DECISION_LOG_READY=1
    printf 'id=%s\ncreated_epoch=%s\nstatus=preparing\nssh_service=%s\n' \
        "$TRANSACTION_ID" "$(date +%s)" "$SSH_SERVICE" > "$TRANSACTION_DIR/metadata"
    chmod 0600 "$TRANSACTION_DIR/metadata"
}

backup_target() {
    local system_path="$1" sensitive=${2:-no} actual relative index archive existed
    actual=$(root_path "$system_path")
    index=$(awk 'END {print NR + 1}' "$TRANSACTION_DIR/manifest.tsv")
    archive="$TRANSACTION_DIR/archives/$index.tar"
    existed=no
    if [[ -e "$actual" || -L "$actual" ]]; then
        existed=yes
        relative=${system_path#/}
        tar_create_archive "$archive" "$SYSTEM_ROOT" "$relative"
        chmod 0600 "$archive"
    fi
    printf '%s\t%s\t%s\t%s\n' "$index" "$existed" "$sensitive" "$system_path" >> "$TRANSACTION_DIR/manifest.tsv"
}

tar_supports_security_metadata() {
    tar --help 2>/dev/null | grep -q -- '--selinux'
}

tar_create_archive() {
    local archive="$1" root="$2" relative="$3"
    if tar_supports_security_metadata; then
        tar --acls --xattrs --selinux --numeric-owner -cpf "$archive" -C "$root" "$relative"
    else
        tar -cpf "$archive" -C "$root" "$relative"
    fi
}

tar_extract_archive() {
    local archive="$1" destination="$2"
    if tar_supports_security_metadata; then
        tar --acls --xattrs --selinux --numeric-owner -xpf "$archive" -C "$destination"
    else
        tar -xpf "$archive" -C "$destination"
    fi
}

transaction_target_list() {
    printf '%s\n' /etc/ssh/sshd_config
    printf '%s\n' /etc/login.defs /etc/security/pwquality.conf /etc/security/faillock.conf
    printf '%s\n' /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/subuid /etc/subgid
    printf '%s\n' "$ROLE_SUDOERS_PATH" "$AUDIT_HELPER_PATH"
    printf '%s\n' "$SYSINFO_COLLECTOR_PATH" "$SYSINFO_PROFILE_PATH"
    printf '%s\n' "$CREDENTIAL_BUNDLE_PATH"
    printf '%s\n' /home/opsadmin /home/auditadmin /home/secadmin
    printf '%s\n' /var/mail/opsadmin /var/mail/auditadmin /var/mail/secadmin
    printf '%s\n' /var/spool/mail/opsadmin /var/spool/mail/auditadmin /var/spool/mail/secadmin
    if admin_ssh_keys_enabled; then
        managed_account_ssh_transaction_targets
    fi
    if root_ssh_key_enabled; then
        if [[ -d $(root_path /root/.ssh) ]]; then
            printf '%s\n' /root/.ssh/authorized_keys
        else
            printf '%s\n' /root/.ssh
        fi
    fi
    if [[ "$PLATFORM_FAMILY" == debian ]]; then
        printf '%s\n' /etc/pam.d/common-auth /etc/pam.d/common-account /etc/pam.d/common-password
    elif [[ "$PLATFORM_FAMILY" == rhel8plus ]]; then
        printf '%s\n' /etc/authselect /etc/pam.d /etc/nsswitch.conf \
            /etc/dconf/db/distro.d/20-authselect /etc/dconf/db/distro.d/locks/20-authselect-locks \
            /var/lib/server-hardening/authselect-faillock.enabled
    elif [[ "$PLATFORM_FAMILY" == rhel7 ]]; then
        printf '%s\n' /etc/pam.d /etc/sysconfig/authconfig /var/lib/server-hardening/authconfig-faillock.enabled
    fi
}

backup_all_targets() {
    local target sensitive
    while IFS= read -r target; do
        [[ -n "$target" ]] || continue
        sensitive=no
        [[ "$target" == /etc/shadow || "$target" == /etc/gshadow || "$target" == "$CREDENTIAL_BUNDLE_PATH" ]] && sensitive=yes
        backup_target "$target" "$sensitive"
    done < <(transaction_target_list | awk '!seen[$0]++')
}

metadata_value() {
    local file="$1" key="$2"
    sed -n "s/^${key}=//p" "$file" | head -1
}

acquire_global_lock() {
    local lock_file
    lock_file=$(root_path "$GLOBAL_LOCK_FILE")
    install -d -m 0700 "$(dirname "$lock_file")"
    (umask 077; : >> "$lock_file")
    chmod 0600 "$lock_file"
    exec 8>>"$lock_file"
    flock -n 8 || die "另一个加固、确认或回滚进程正在运行"
}

assert_no_pending_transaction() {
    local metadata status
    [[ -d "$BACKUP_ROOT" ]] || return 0
    for metadata in "$BACKUP_ROOT"/*/metadata; do
        [[ -f "$metadata" ]] || continue
        status=$(metadata_value "$metadata" status)
        [[ "$status" != preparing && "$status" != pending-confirmation ]] || die "存在未完成事务: $(dirname "$metadata")"
    done
}

set_transaction_status() {
    set_metadata_value "$1" status "$2"
}

set_metadata_value() {
    local dir="$1" key="$2" value="$3" metadata tmp
    metadata="$dir/metadata"
    tmp=$(mktemp "$dir/.metadata.XXXXXX")
    awk -v key="$key" -v value="$value" 'BEGIN{done=0} index($0, key "=") == 1 {print key "=" value; done=1; next} {print} END{if(!done) print key "=" value}' "$metadata" > "$tmp"
    chmod 0600 "$tmp"
    mv -f "$tmp" "$metadata"
}

restore_transaction_dir() {
    local dir="$1" manifest index existed _sensitive system_path archive actual staging restored old
    manifest="$dir/manifest.tsv"
    [[ -f "$manifest" ]] || die "事务 manifest 不存在: $dir"
    remove_transaction_exported_keys "$dir"
    while IFS=$'\t' read -r index existed _sensitive system_path; do
        [[ -n "$system_path" ]] || continue
        actual=$(root_path "$system_path")
        if [[ "$existed" == yes ]]; then
            archive="$dir/archives/$index.tar"
            [[ -f "$archive" ]] || die "缺少备份归档: $index"
            staging=$(mktemp -d "$(dirname "$actual")/.server-hardening-restore.XXXXXX")
            tar_extract_archive "$archive" "$staging"
            restored="$staging/${system_path#/}"
            if [[ -d "$restored" && ! -L "$restored" ]]; then
                old="${actual}.server-hardening-old-$$"
                [[ ! -e "$actual" && ! -L "$actual" ]] || mv "$actual" "$old"
                mv "$restored" "$actual"
                rm -rf "$old"
            else
                mkdir -p "$(dirname "$actual")"
                mv -f "$restored" "$actual"
            fi
            rm -rf "$staging"
        else
            rm -rf "$actual"
        fi
        if command_exists restorecon && [[ -e "$actual" || -L "$actual" ]]; then
            restorecon -RF "$actual" >/dev/null 2>&1 || die "SELinux 上下文恢复失败: $system_path"
        fi
    done < "$manifest"
    if [[ "$SYSTEM_ROOT" == / ]]; then
        sshd -t -f /etc/ssh/sshd_config || die "回滚后 sshd 语法校验失败，已保留现场"
        systemctl reload "$(metadata_value "$dir/metadata" ssh_service)" || die "回滚后 SSH 重载失败"
    fi
    set_transaction_status "$dir" rolled-back
}

remove_transaction_exported_keys() {
    local dir="$1" list path name
    list="$dir/exported-keys.list"
    [[ -f "$list" ]] || return 0
    while IFS= read -r path; do
        [[ "$path" == /* ]] || continue
        name=${path##*/}
        [[ "$name" == server-hardening-*-ed25519 || "$name" == server-hardening-*-ed25519.pub ]] || continue
        rm -f "$path"
    done < "$list"
}

generate_rollback_script() {
    local script="$TRANSACTION_DIR/rollback.sh"
    cat > "$script" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
MANIFEST="$DIR/manifest.tsv"
install -d -m 0700 /run/server-hardening
umask 077
exec 8>>/run/server-hardening/operation.lock
chmod 0600 /run/server-hardening/operation.lock
flock -x 8
status=$(sed -n 's/^status=//p' "$DIR/metadata" | head -1)
[[ "$status" == preparing || "$status" == pending-confirmation ]] || exit 0
trap 'printf "[ERROR] automatic rollback failed; inspect %s\n" "$DIR" >&2' ERR
if [[ -f "$DIR/exported-keys.list" ]]; then
    while IFS= read -r path; do
        [[ "$path" == /* ]] || continue
        name=${path##*/}
        [[ "$name" == server-hardening-*-ed25519 || "$name" == server-hardening-*-ed25519.pub ]] || continue
        rm -f "$path"
    done < "$DIR/exported-keys.list"
fi
tar_extract() {
    if tar --help 2>/dev/null | grep -q -- '--selinux'; then
        tar --acls --xattrs --selinux --numeric-owner -xpf "$1" -C "$2"
    else
        tar -xpf "$1" -C "$2"
    fi
}
while IFS=$'\t' read -r index existed _sensitive system_path; do
    [[ -n "$system_path" ]] || continue
    if [[ "$existed" == yes ]]; then
        staging=$(mktemp -d "$(dirname "$system_path")/.server-hardening-restore.XXXXXX")
        tar_extract "$DIR/archives/$index.tar" "$staging"
        restored="$staging/${system_path#/}"
        if [[ -d "$restored" && ! -L "$restored" ]]; then
            old="${system_path}.server-hardening-old-$$"
            [[ ! -e "$system_path" && ! -L "$system_path" ]] || mv "$system_path" "$old"
            mv "$restored" "$system_path"
            rm -rf "$old"
        else
            mkdir -p "$(dirname "$system_path")"
            mv -f "$restored" "$system_path"
        fi
        rm -rf "$staging"
    else
        rm -rf "$system_path"
    fi
    if command -v restorecon >/dev/null 2>&1 && [[ -e "$system_path" || -L "$system_path" ]]; then
        restorecon -RF "$system_path" >/dev/null 2>&1
    fi
done < "$MANIFEST"
ssh_service=$(sed -n 's/^ssh_service=//p' "$DIR/metadata" | head -1)
sshd -t -f /etc/ssh/sshd_config
systemctl reload "$ssh_service"
timer_unit=$(sed -n 's/^timer_unit=//p' "$DIR/metadata" | head -1)
service_unit=$(sed -n 's/^service_unit=//p' "$DIR/metadata" | head -1)
systemctl disable "$timer_unit" >/dev/null 2>&1 || true
rm -f "/etc/systemd/system/$timer_unit" "/etc/systemd/system/$service_unit"
systemctl daemon-reload
tmp=$(mktemp "$DIR/.metadata.XXXXXX")
awk 'BEGIN{done=0} /^status=/{print "status=rolled-back"; done=1; next} {print} END{if(!done) print "status=rolled-back"}' "$DIR/metadata" > "$tmp"
chmod 0600 "$tmp"
mv -f "$tmp" "$DIR/metadata"
EOF
    chmod 0700 "$script"
}

find_transaction_dir() {
    local id="$1"
    [[ "$id" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9a-fA-F]{8}$ ]] || die "事务 ID 格式无效"
    local dir="${BACKUP_ROOT%/}/$id"
    [[ -d "$dir" ]] || die "未找到事务: $id"
    printf '%s\n' "$dir"
}

manual_rollback() {
    local dir status
    dir=$(find_transaction_dir "$ROLLBACK_TRANSACTION")
    status=$(metadata_value "$dir/metadata" status)
    [[ "$status" != rolled-back ]] || die "事务已回滚"
    disarm_automatic_rollback "$dir"
    restore_transaction_dir "$dir"
    info "事务 $ROLLBACK_TRANSACTION 已回滚"
}

session_start_epoch() {
    local pid=$PPID parent command started=''
    while (( pid > 1 )); do
        command=$(ps -o comm= -p "$pid" 2>/dev/null | sed 's/^[[:space:]]*//')
        if [[ "$command" == sshd* ]]; then
            started=$(ps -o lstart= -p "$pid" 2>/dev/null | sed 's/^[[:space:]]*//')
            break
        fi
        parent=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')
        is_uint "$parent" || return 1
        pid=$parent
    done
    [[ -n "$started" ]] || return 1
    date -d "$started" +%s 2>/dev/null
}

ssh_tty_session_start_epoch() {
    [[ -t 0 ]] || return 1
    session_start_epoch
}

confirm_transaction() {
    local dir status applied session
    session=$(ssh_tty_session_start_epoch) || die "--confirm 必须在可识别的新 SSH TTY 会话中执行"
    dir=$(find_transaction_dir "$CONFIRM_TRANSACTION")
    status=$(metadata_value "$dir/metadata" status)
    [[ "$status" == pending-confirmation ]] || die "事务状态不是待确认: $status"
    applied=$(metadata_value "$dir/metadata" applied_epoch)
    is_uint "$applied" || die "事务缺少有效 applied_epoch"
    (( session > applied )) || die "必须从 SSH 重载成功后新建的会话确认"
    set_transaction_status "$dir" confirmed
    disarm_automatic_rollback "$dir"
    info "事务 $CONFIRM_TRANSACTION 已确认，自动回滚已取消"
}

systemd_compatible_calendar_timestamp() {
    local value="$1"
    value=${value% UTC}
    [[ "$value" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]][0-9]{2}:[0-9]{2}:[0-9]{2}$ ]] || return 1
    printf '%s\n' "$value"
}

arm_automatic_rollback() {
    local unit="server-hardening-rollback-$TRANSACTION_ID" due service_file timer_file
    generate_rollback_script
    if [[ -n ${ROLLBACK_DUE_TIMESTAMP_OVERRIDE:-} ]]; then
        due=$(systemd_compatible_calendar_timestamp "$ROLLBACK_DUE_TIMESTAMP_OVERRIDE") || die "回滚 timer 时间格式无效"
    else
        due=$(date -d "@$(( $(date +%s) + PREPARATION_WATCHDOG_TIMEOUT ))" '+%Y-%m-%d %H:%M:%S')
    fi
    service_file=$(root_path "/etc/systemd/system/$unit.service")
    timer_file=$(root_path "/etc/systemd/system/$unit.timer")
    install -d -m 0755 "$(dirname "$service_file")"
    {
        printf 'timer_unit=%s.timer\n' "$unit"
        printf 'service_unit=%s.service\n' "$unit"
    } >> "$TRANSACTION_DIR/metadata"
    cat > "$service_file" <<EOF
[Unit]
Description=Rollback unconfirmed server hardening transaction $TRANSACTION_ID

[Service]
Type=simple
ExecStart=/bin/bash $TRANSACTION_DIR/rollback.sh
Restart=on-failure
RestartSec=30s
EOF
    cat > "$timer_file" <<EOF
[Unit]
Description=Rollback timer for server hardening transaction $TRANSACTION_ID

[Timer]
OnCalendar=$due
Persistent=true
AccuracySec=1s
Unit=$unit.service

[Install]
WantedBy=timers.target
EOF
    chmod 0644 "$service_file" "$timer_file"
    if command_exists restorecon; then restorecon -F "$service_file" "$timer_file" >/dev/null 2>&1 || die "systemd unit SELinux 上下文设置失败"; fi
    systemctl daemon-reload
    systemctl enable "$unit.timer" >/dev/null
    systemctl start "$unit.timer"
    systemctl is-active --quiet "$unit.timer" || die "自动回滚 timer 未激活"
}

reset_rollback_deadline_after_apply() {
    local dir="$1" timer_unit service_unit timer_file due tmp applied
    timer_unit=$(metadata_value "$dir/metadata" timer_unit)
    service_unit=$(metadata_value "$dir/metadata" service_unit)
    timer_file=$(root_path "/etc/systemd/system/$timer_unit")
    [[ -f "$timer_file" ]] || die "回滚 timer 文件不存在"
    applied=$(date +%s)
    if [[ -n ${ROLLBACK_DUE_TIMESTAMP_OVERRIDE:-} ]]; then
        due=$(systemd_compatible_calendar_timestamp "$ROLLBACK_DUE_TIMESTAMP_OVERRIDE") || die "回滚 timer 时间格式无效"
    else
        due=$(date -d "@$(( applied + ROLLBACK_TIMEOUT ))" '+%Y-%m-%d %H:%M:%S')
    fi
    set_metadata_value "$dir" applied_epoch "$applied"
    systemctl stop "$service_unit" >/dev/null 2>&1 || true
    tmp=$(mktemp "$(dirname "$timer_file")/.server-hardening.XXXXXX")
    awk -v due="$due" '/^OnCalendar=/{print "OnCalendar=" due; next} {print}' "$timer_file" > "$tmp"
    chmod 0644 "$tmp"
    mv -f "$tmp" "$timer_file"
    if command_exists restorecon; then restorecon -F "$timer_file" >/dev/null 2>&1; fi
    systemctl daemon-reload
    systemctl restart "$timer_unit"
    systemctl is-active --quiet "$timer_unit" || die "应用后回滚 timer 未激活"
}

disarm_automatic_rollback() {
    local dir="$1" timer_unit service_unit
    timer_unit=$(metadata_value "$dir/metadata" timer_unit)
    service_unit=$(metadata_value "$dir/metadata" service_unit)
    [[ -z "$timer_unit" ]] || systemctl disable --now "$timer_unit" >/dev/null 2>&1 || true
    [[ -z "$timer_unit" ]] || rm -f "$(root_path "/etc/systemd/system/$timer_unit")"
    [[ -z "$service_unit" ]] || rm -f "$(root_path "/etc/systemd/system/$service_unit")"
    systemctl daemon-reload >/dev/null 2>&1 || true
}
