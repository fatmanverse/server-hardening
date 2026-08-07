#!/usr/bin/env bash

# Sourced by server_hardening.sh; do not execute directly.
# shellcheck disable=SC2034,SC2153

pick_char() {
    local charset="$1" n=${#1} byte limit
    (( n > 0 && n <= 256 )) || return 1
    limit=$((256 - (256 % n)))
    while :; do
        byte=$(od -An -N1 -tu1 < /dev/urandom | tr -d ' ')
        if (( byte < limit )); then
            printf '%s' "${charset:$((byte % n)):1}"
            return 0
        fi
    done
}

random_index() {
    local upper="$1" byte limit
    (( upper >= 1 && upper <= 256 )) || return 1
    limit=$((256 - (256 % upper)))
    while :; do
        byte=$(od -An -N1 -tu1 < /dev/urandom | tr -d ' ')
        if (( byte < limit )); then
            printf '%d\n' $((byte % upper))
            return 0
        fi
    done
}

generate_password() {
    local length=${1:-$DEFAULT_PASSWORD_LENGTH}
    is_uint "$length" || return 1
    (( length >= MIN_PASSWORD_LENGTH && length <= MAX_PASSWORD_LENGTH )) || return 1
    local upper='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    local lower='abcdefghijklmnopqrstuvwxyz'
    local digit='0123456789'
    local symbol='!@#%^&*()-_=+[]{}:,.?'
    local all="${upper}${lower}${digit}${symbol}"
    local -a chars
    local i j tmp
    chars=("$(pick_char "$upper")" "$(pick_char "$lower")" "$(pick_char "$digit")" "$(pick_char "$symbol")")
    for ((i = 4; i < length; i++)); do
        chars+=("$(pick_char "$all")")
    done
    for ((i = ${#chars[@]} - 1; i > 0; i--)); do
        j=$(random_index $((i + 1)))
        tmp=${chars[i]}
        chars[i]=${chars[j]}
        chars[j]=$tmp
    done
    printf '%s\n' "${chars[*]}" | tr -d ' '
}

reset_managed_account_state() {
    CREATED_ACCOUNT_USERS=()
    CREATED_ACCOUNT_PASSWORDS=()
}

reset_managed_ssh_key_state() {
    EXPORTED_SSH_KEY_FILES=()
    PROVISIONED_SSH_KEY_USERS=()
    PROVISIONED_SSH_PRIVATE_PATHS=()
}

managed_account_names() {
    printf '%s\n' opsadmin auditadmin secadmin
}

managed_account_description() {
    case "$1" in
        opsadmin) printf '运维管理员\n' ;;
        auditadmin) printf '审计管理员\n' ;;
        secadmin) printf '安全管理员\n' ;;
        *) return 1 ;;
    esac
}

managed_account_role_summary() {
    case "$1" in
        opsadmin) printf '完整 sudo 运维权限，使用本人密码提权\n' ;;
        auditadmin) printf '只读系统、SSH/认证、auditd 日志和固定查询，无通用 sudo\n' ;;
        secadmin) printf '受限管理 SSH、PAM、密码策略和防火墙，无通用 sudo\n' ;;
        *) return 1 ;;
    esac
}

local_account_exists() {
    local user="$1" passwd_file=${PASSWD_FILE:-$(root_path /etc/passwd)}
    awk -F: -v user="$user" '$1 == user {found=1} END {exit !found}' "$passwd_file"
}

local_account_identity() {
    local user="$1" passwd_file=${PASSWD_FILE:-$(root_path /etc/passwd)}
    awk -F: -v user="$user" '$1 == user {printf "%s\t%s\t%s\n", $3, $4, $6; found=1; exit} END {exit !found}' "$passwd_file"
}

account_shell_value() {
    local user="$1" passwd_file=${PASSWD_FILE:-$(root_path /etc/passwd)}
    [[ -r "$passwd_file" ]] || { warn "无法读取账户文件: $passwd_file"; return 1; }
    awk -F: -v user="$user" '
        $1 == user && NF >= 7 {print $7; found=1; exit}
        END {exit !found}
    ' "$passwd_file"
}

account_aging_value() {
    local user="$1" shadow_file=${SHADOW_FILE:-$(root_path /etc/shadow)}
    [[ -r "$shadow_file" ]] || { warn "无法读取密码状态文件: $shadow_file"; return 1; }
    awk -F: -v user="$user" '
        $1 == user && NF >= 7 {
            password="set"
            if ($2 == "") password="unset"
            else if ($2 ~ /^[!*]/) password="locked"
            must_change=($3 == "0" ? "yes" : "no")
            printf "min=%s,max=%s,warn=%s,must-change=%s,password=%s\n", $4, $5, $6, must_change, password
            found=1
            exit
        }
        END {exit !found}
    ' "$shadow_file"
}

managed_authorized_key_fingerprint() {
    local user="$1" identity _uid _gid home authorized_keys marker key_line key_type fingerprint count
    identity=$(local_account_identity "$user") || return 2
    IFS=$'\t' read -r _uid _gid home <<< "$identity"
    authorized_keys=$(root_path "$home/.ssh/authorized_keys")
    [[ -r "$authorized_keys" ]] || return 1
    marker="server-hardening:$user:"
    count=$(awk -v marker="$marker" 'index($0, marker) {count++} END {print count + 0}' "$authorized_keys") || return 1
    (( count == 0 )) && return 1
    (( count == 1 )) || { warn "账户 $user 的 authorized_keys 中受管密钥数量异常: $count"; return 2; }
    key_line=$(awk -v marker="$marker" 'index($0, marker) {print; exit}' "$authorized_keys") || return 1
    key_type=${key_line%%[[:space:]]*}
    fingerprint=$(printf '%s\n' "$key_line" | ssh-keygen -lf - 2>/dev/null | awk 'NR == 1 {print $2}')
    [[ -n "$fingerprint" ]] || { warn "账户 $user 的受管 SSH 公钥无法读取指纹"; return 2; }
    printf 'path=%s,type=%s,fingerprint=%s\n' "$home/.ssh/authorized_keys" "$key_type" "$fingerprint"
}

managed_account_ssh_transaction_targets() {
    local user identity _uid _gid home
    while IFS= read -r user; do
        if identity=$(local_account_identity "$user" 2>/dev/null); then
            IFS=$'\t' read -r _uid _gid home <<< "$identity"
        else
            home="/home/$user"
        fi
        [[ "$home" == /* && "$home" != / && "$home" != *$'\t'* && "$home" != *$'\n'* ]] || return 1
        if [[ -d $(root_path "$home/.ssh") ]]; then
            printf '%s\n' "$home/.ssh/authorized_keys"
        else
            printf '%s\n' "$home/.ssh"
        fi
    done < <(managed_account_names)
}

local_group_exists() {
    local group="$1" group_file=${GROUP_FILE:-$(root_path /etc/group)}
    awk -F: -v group="$group" '$1 == group {found=1} END {exit !found}' "$group_file"
}

local_group_has_member() {
    local group="$1" user="$2" group_file=${GROUP_FILE:-$(root_path /etc/group)}
    awk -F: -v group="$group" -v user="$user" '
        $1 == group {
            count=split($4, members, ",")
            for (i=1; i<=count; i++) if (members[i] == user) found=1
        }
        END {exit !found}
    ' "$group_file"
}

local_account_primary_gid() {
    local user="$1" passwd_file=${PASSWD_FILE:-$(root_path /etc/passwd)}
    awk -F: -v user="$user" '$1 == user {print $4; found=1; exit} END {exit !found}' "$passwd_file"
}

local_group_gid() {
    local group="$1" group_file=${GROUP_FILE:-$(root_path /etc/group)}
    awk -F: -v group="$group" '$1 == group {print $3; found=1; exit} END {exit !found}' "$group_file"
}

local_group_name_from_gid() {
    local gid="$1" group_file=${GROUP_FILE:-$(root_path /etc/group)}
    awk -F: -v gid="$gid" '$3 == gid {print $1; found=1; exit} END {exit !found}' "$group_file"
}

account_group_membership_value() {
    local user="$1" group="$2" primary_gid group_gid
    local_group_exists "$group" || { printf 'group-missing\n'; return 0; }
    primary_gid=$(local_account_primary_gid "$user") || return 1
    group_gid=$(local_group_gid "$group") || return 1
    if [[ "$primary_gid" == "$group_gid" ]] || local_group_has_member "$group" "$user"; then
        printf 'member=yes\n'
    else
        printf 'member=no\n'
    fi
}

ensure_account_shell() {
    local user="$1" target=/bin/bash current
    current=$(account_shell_value "$user") || return 1
    resolve_conflict "account.$user.shell" "账户 $user 的登录 Shell" "$current" "$target" "修改账户登录 Shell" || return 1
    [[ "$CONFLICT_DECISION" == apply ]] || return 0
    (( DRY_RUN )) && return 0
    usermod -s "$target" "$user"
}

ensure_password_aging() {
    local user="$1" max_days="$2" min_days="$3" warn_days="$4" current target must_change password_state
    current=$(account_aging_value "$user") || return 1
    must_change=$(printf '%s\n' "$current" | sed -n 's/.*must-change=\([^,]*\).*/\1/p')
    password_state=${current##*,password=}
    [[ -n "$must_change" && -n "$password_state" ]] || return 1
    target="min=$min_days,max=$max_days,warn=$warn_days,must-change=$must_change,password=$password_state"
    resolve_conflict "account.$user.aging" "账户 $user 的密码周期" "$current" "$target" "设置最长 $max_days 天、最短 $min_days 天、提前 $warn_days 天警告" || return 1
    [[ "$CONFLICT_DECISION" == apply ]] || return 0
    (( DRY_RUN )) && return 0
    chage -M "$max_days" -m "$min_days" -W "$warn_days" "$user"
}

ensure_account_aging() {
    ensure_password_aging "$1" 30 1 7
}

ensure_restricted_account_primary_group() {
    local user="$1" primary_gid primary_group group admin_gid
    primary_gid=$(local_account_primary_gid "$user") || return 0
    for group in sudo wheel; do
        admin_gid=$(local_group_gid "$group" 2>/dev/null) || continue
        [[ "$primary_gid" == "$admin_gid" ]] || continue
        primary_group=$(local_group_name_from_gid "$primary_gid" 2>/dev/null || printf 'gid=%s\n' "$primary_gid")
        resolve_conflict "account.$user.primary-group" "账户 $user 的主组" "$primary_group" "$user" "移除受限角色的完整管理权限" || return 1
        [[ "$CONFLICT_DECISION" == apply ]] || return 0
        (( DRY_RUN )) && return 0
        local_group_exists "$user" || groupadd "$user"
        usermod -g "$user" "$user"
        return 0
    done
}

add_account_to_group_if_present() {
    local user="$1" group="$2" current
    local_group_exists "$group" || return 0
    if ! managed_account_was_created "$user"; then
        current=$(account_group_membership_value "$user" "$group") || return 1
        resolve_conflict "account.$user.group.$group" "账户 $user 的 $group 组成员关系" "$current" 'member=yes' "授予该角色所需权限" || return 1
        [[ "$CONFLICT_DECISION" == apply ]] || return 0
    fi
    (( DRY_RUN )) && return 0
    usermod -a -G "$group" "$user" || return 1
}

remove_account_from_admin_groups() {
    local user="$1" group current
    ensure_restricted_account_primary_group "$user" || return 1
    for group in sudo wheel; do
        local_group_exists "$group" || continue
        current=$(account_group_membership_value "$user" "$group") || return 1
        resolve_conflict "account.$user.group.$group" "账户 $user 的 $group 组成员关系" "$current" 'member=no' "移除受限角色的完整管理权限" || return 1
        [[ "$CONFLICT_DECISION" == apply ]] || continue
        if (( DRY_RUN )); then continue; fi
        gpasswd -d "$user" "$group" || return 1
    done
}

record_created_account() {
    CREATED_ACCOUNT_USERS+=("$1")
    CREATED_ACCOUNT_PASSWORDS+=("$2")
    record_account_credential "$1" "$2"
    SYSTEM_CHANGE_REQUIRED=1
}

managed_account_was_created() {
    local expected="$1" user
    for user in "${CREATED_ACCOUNT_USERS[@]:-}"; do
        [[ "$user" == "$expected" ]] && return 0
    done
    return 1
}

created_account_password() {
    local expected="$1" index
    for ((index = 0; index < ${#CREATED_ACCOUNT_USERS[@]}; index++)); do
        if [[ "${CREATED_ACCOUNT_USERS[index]}" == "$expected" ]]; then
            printf '%s\n' "${CREATED_ACCOUNT_PASSWORDS[index]}"
            return 0
        fi
    done
    return 1
}

apply_managed_accounts() {
    local user description password admin_group
    admin_group=wheel
    [[ "$PLATFORM_FAMILY" == debian ]] && admin_group=sudo
    # Read on fd 3: the loop body prompts the operator through resolve_conflict,
    # which reads stdin.
    while IFS= read -r user <&3; do
        description=$(managed_account_description "$user")
        if local_account_exists "$user"; then
            ensure_account_shell "$user" || return 1
            ensure_account_aging "$user" || return 1
        else
            password=$(generate_password "$MANAGED_ACCOUNT_PASSWORD_LENGTH") || return 1
            useradd -m -s /bin/bash -c "$description" "$user" || return 1
            printf '%s:%s\n' "$user" "$password" | chpasswd || return 1
            chage -d 0 -M 30 -m 1 -W 7 "$user" || return 1
            record_created_account "$user" "$password"
        fi

        case "$user" in
            opsadmin)
                add_account_to_group_if_present "$user" "$admin_group" || return 1
                ;;
            auditadmin)
                remove_account_from_admin_groups "$user" || return 1
                add_account_to_group_if_present "$user" adm || return 1
                add_account_to_group_if_present "$user" systemd-journal || return 1
                ;;
            secadmin)
                remove_account_from_admin_groups "$user" || return 1
                ;;
        esac
    done 3< <(managed_account_names)
}

install_authorized_key() {
    local user="$1" public_key="$2" identity uid gid home actual_home ssh_dir authorized_keys
    identity=$(local_account_identity "$user") || return 1
    IFS=$'\t' read -r uid gid home <<< "$identity"
    actual_home=$(root_path "$home")
    [[ -d "$actual_home" ]] || return 1
    ssh_dir="$actual_home/.ssh"
    authorized_keys="$ssh_dir/authorized_keys"
    install -d -m 0700 "$ssh_dir" || return 1
    chown_for_system_root "$uid:$gid" "$ssh_dir" || return 1
    if [[ ! -f "$authorized_keys" ]]; then
        install -m 0600 /dev/null "$authorized_keys" || return 1
    fi
    grep -Fqx "$public_key" "$authorized_keys" 2>/dev/null || printf '%s\n' "$public_key" >> "$authorized_keys" || return 1
    chmod 0600 "$authorized_keys" || return 1
    chown_for_system_root "$uid:$gid" "$authorized_keys" || return 1
    if [[ "$SYSTEM_ROOT" == / ]] && command_exists restorecon; then
        restorecon -RF "$ssh_dir" >/dev/null 2>&1 || return 1
    fi
}

record_exported_ssh_key() {
    EXPORTED_SSH_KEY_FILES+=("$1" "$2")
    PROVISIONED_SSH_KEY_USERS+=("$3")
    PROVISIONED_SSH_PRIVATE_PATHS+=("$1")
    printf '%s\n%s\n' "$1" "$2" >> "$TRANSACTION_DIR/exported-keys.list"
}

private_key_path_for_user() {
    local expected="$1" index
    for ((index = 0; index < ${#PROVISIONED_SSH_KEY_USERS[@]}; index++)); do
        [[ "${PROVISIONED_SSH_KEY_USERS[index]}" == "$expected" ]] || continue
        printf '%s\n' "${PROVISIONED_SSH_PRIVATE_PATHS[index]}"
        return 0
    done
    return 1
}

provision_ssh_key_for_account() {
    local user="$1" tmp_dir tmp_key public_key private_key private_output public_output current status
    if current=$(managed_authorized_key_fingerprint "$user"); then
        resolve_conflict "ssh-key.$user" "账户 $user 的脚本受管 SSH 密钥" "$current" "$current" "保留现有受管公钥和已导出的私钥" || return 1
        return 0
    else
        status=$?
        (( status == 1 )) || return 1
    fi
    [[ "$KEY_EXPORT_DIR" == /* && -d "$KEY_EXPORT_DIR" && ! -L "$KEY_EXPORT_DIR" ]] || return 1
    tmp_dir=$(mktemp -d "$TRANSACTION_DIR/.ssh-key.XXXXXX") || return 1
    chmod 0700 "$tmp_dir" || { rm -rf "$tmp_dir"; return 1; }
    tmp_key="$tmp_dir/id_ed25519"
    if ! ssh-keygen -q -t ed25519 -N '' -C "server-hardening:$user:$TRANSACTION_ID" -f "$tmp_key"; then
        rm -rf "$tmp_dir"
        return 1
    fi
    [[ -s "$tmp_key" && -s "$tmp_key.pub" ]] || { rm -rf "$tmp_dir"; return 1; }
    public_key=$(<"$tmp_key.pub")
    private_output="$KEY_EXPORT_DIR/server-hardening-$user-$TRANSACTION_ID-ed25519"
    public_output="$private_output.pub"
    if [[ -e "$private_output" || -e "$public_output" ]]; then
        rm -rf "$tmp_dir"
        return 1
    fi
    record_exported_ssh_key "$private_output" "$public_output" "$user" || {
        rm -rf "$tmp_dir"
        return 1
    }
    install -m 0600 "$tmp_key" "$private_output" || { rm -rf "$tmp_dir"; return 1; }
    install -m 0644 "$tmp_key.pub" "$public_output" || { rm -f "$private_output"; rm -rf "$tmp_dir"; return 1; }
    chown "$KEY_EXPORT_UID:$KEY_EXPORT_GID" "$private_output" "$public_output" || {
        rm -f "$private_output" "$public_output"
        rm -rf "$tmp_dir"
        return 1
    }
    install_authorized_key "$user" "$public_key" || { rm -rf "$tmp_dir"; return 1; }
    private_key=$(<"$tmp_key")
    record_ssh_key_credential "$user" "$public_key" "$private_key" || { rm -rf "$tmp_dir"; return 1; }
    SYSTEM_CHANGE_REQUIRED=1
    rm -rf "$tmp_dir"
}

provision_managed_ssh_keys() {
    local user
    if root_ssh_key_enabled; then
        provision_ssh_key_for_account root || return 1
    fi
    if admin_ssh_keys_enabled; then
        while IFS= read -r user; do
            provision_ssh_key_for_account "$user" || return 1
        done < <(managed_account_names)
    fi
}

cleanup_exported_ssh_keys() {
    local path
    for path in "${EXPORTED_SSH_KEY_FILES[@]:-}"; do
        [[ -z "$path" ]] || rm -f "$path"
    done
    reset_managed_ssh_key_state
}

show_managed_account_results() {
    local user password private_key
    printf '\n=== 三员账户结果 ===\n'
    while IFS= read -r user; do
        printf '%s (%s)\n' "$user" "$(managed_account_description "$user")"
        printf '  权限: %s\n' "$(managed_account_role_summary "$user")"
        printf '  SSH: %s\n' "$(admin_login_summary)"
        if managed_account_was_created "$user"; then
            password=$(created_account_password "$user")
            printf '  临时密码: %s\n' "$password"
            printf '  首次登录: 必须立即修改密码\n'
        else
            printf '  状态: 账户已存在，未重置密码，已补齐角色权限和 30 天策略\n'
        fi
        if private_key=$(private_key_path_for_user "$user" 2>/dev/null); then
            printf '  SSH 私钥: %s\n' "$private_key"
            printf '  SSH 公钥: %s.pub\n' "$private_key"
        fi
    done < <(managed_account_names)
    if (( ${#CREATED_ACCOUNT_USERS[@]} > 0 )); then
        printf '\n请立即安全记录临时密码；本脚本不会再次显示。\n\n'
    else
        printf '\n本次未新建三员账户，因此没有生成或重置临时密码。\n\n'
    fi
}

uid_minimum() {
    local login_defs value
    login_defs=$(root_path /etc/login.defs)
    value=$(awk '$1 == "UID_MIN" {print $2; exit}' "$login_defs")
    printf '%s\n' "${value:-1000}"
}

list_regular_users() {
    local passwd_file=${PASSWD_FILE:-$(root_path /etc/passwd)} min_uid user _ uid _gid _gecos _home shell
    min_uid=$(uid_minimum)
    while IFS=: read -r user _ uid _gid _gecos _home shell; do
        (( uid >= min_uid && uid != 65534 )) || continue
        shell_is_valid "$shell" || continue
        printf '%s\n' "$user"
    done < "$passwd_file"
}
