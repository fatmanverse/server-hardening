#!/usr/bin/env bash

# Sourced by server_hardening.sh; do not execute directly.
# shellcheck disable=SC2034,SC2153

sanitize_decision_field() {
    printf '%s' "$1" | tr '\t\r\n' '   '
}

sanitize_decision_summary() {
    local value
    value=$(sanitize_decision_field "$1")
    if [[ "$value" == *'PRIVATE KEY'* || "$value" =~ \$[0-9A-Za-z]+\$ || "$value" =~ ssh-(ed25519|rsa|ecdsa)[[:space:]]+[A-Za-z0-9+/]{20,} ]]; then
        printf '[REDACTED]'
        return
    fi
    if (( ${#value} >= 8 )) && [[ "$value" != *[[:space:]]* && "$value" != *=* && "$value" =~ [A-Z] && "$value" =~ [a-z] && "$value" =~ [0-9] && "$value" =~ [^[:alnum:]] ]]; then
        printf '[REDACTED]'
        return
    fi
    printf '%s' "$value"
}

record_decision() {
    local id current target decision reason line
    id=$(sanitize_decision_field "$1")
    current=$(sanitize_decision_summary "$2")
    target=$(sanitize_decision_summary "$3")
    decision=$(sanitize_decision_field "$4")
    reason=$(sanitize_decision_field "$5")
    printf -v line '%s\t%s\t%s\t%s\t%s\t%s' "$(date +%s)" "$id" "$current" "$target" "$decision" "$reason"
    if (( DECISION_LOG_READY )); then
        printf '%s\n' "$line" >> "$TRANSACTION_DIR/decisions.tsv"
    else
        DECISION_RECORDS+=("$line")
    fi
}

summary_field() {
    local value="$1" field="$2"
    printf '%s\n' "$value" | awk -F, -v field="$field" '
        {
            for (i = 1; i <= NF; i++) {
                key=$i
                sub(/=.*/, "", key)
                if (key == field) {
                    sub("^[^=]*=", "", $i)
                    print $i
                    exit
                }
            }
        }
    '
}

yes_no_summary() {
    case "$1" in
        yes) printf '是\n' ;;
        no) printf '否\n' ;;
        *) return 1 ;;
    esac
}

password_state_summary() {
    case "$1" in
        set) printf '已设置\n' ;;
        locked) printf '已锁定\n' ;;
        unset) printf '未设置\n' ;;
        *) return 1 ;;
    esac
}

enabled_state_summary() {
    case "$1" in
        enabled|enable|yes) printf '启用\n' ;;
        disabled|disable|no) printf '禁用\n' ;;
        *) return 1 ;;
    esac
}

pwquality_credit_summary() {
    local value="$1"
    case "$value" in
        -[0-9]*) printf '至少 %s 个\n' "${value#-}" ;;
        0) printf '不强制\n' ;;
        [0-9]*) printf '未强制（可计入 %s 点）\n' "$value" ;;
        *) return 1 ;;
    esac
}

pam_lockout_summary() {
    case "$1" in
        faillock) printf '启用（pam_faillock）\n' ;;
        tally2) printf '启用（pam_tally2）\n' ;;
        disabled) printf '禁用\n' ;;
        *) return 1 ;;
    esac
}

membership_state_summary() {
    case "$1" in
        member=yes) printf '已加入\n' ;;
        member=no) printf '未加入\n' ;;
        group-missing) printf '用户组不存在\n' ;;
        *) return 1 ;;
    esac
}

print_ssh_policy_details() {
    local value="$1" indent="$2" item user data root_value ops_value audit_value sec_value
    local root_mode ops_mode audit_mode sec_mode idle empty pam interval count timeout
    local -a items
    local old_ifs=$IFS
    IFS=';'
    read -r -a items <<< "$value"
    IFS=$old_ifs
    for item in "${items[@]}"; do
        user=${item%%\{*}
        data=${item#*\{}
        data=${data%\}}
        case "$user" in
            root) root_value=$data ;;
            opsadmin) ops_value=$data ;;
            auditadmin) audit_value=$data ;;
            secadmin) sec_value=$data ;;
            *) return 1 ;;
        esac
    done
    [[ -n "$root_value" && -n "$ops_value" && -n "$audit_value" && -n "$sec_value" ]] || return 1
    root_mode=$(ssh_login_mode_summary "$(summary_field "$root_value" root)" "$(summary_field "$root_value" password)" "$(summary_field "$root_value" pubkey)" "$(summary_field "$root_value" methods)" root) || return 1
    ops_mode=$(ssh_login_mode_summary '' "$(summary_field "$ops_value" password)" "$(summary_field "$ops_value" pubkey)" "$(summary_field "$ops_value" methods)" admin) || return 1
    audit_mode=$(ssh_login_mode_summary '' "$(summary_field "$audit_value" password)" "$(summary_field "$audit_value" pubkey)" "$(summary_field "$audit_value" methods)" admin) || return 1
    sec_mode=$(ssh_login_mode_summary '' "$(summary_field "$sec_value" password)" "$(summary_field "$sec_value" pubkey)" "$(summary_field "$sec_value" methods)" admin) || return 1
    idle=$(ssh_idle_timeout_summary "$(summary_field "$root_value" idle)") || return 1
    empty=$(summary_field "$root_value" empty) || return 1
    pam=$(summary_field "$root_value" pam) || return 1
    if [[ "$idle" == '未启用'* ]]; then timeout=未启用
    else timeout=${idle%% 秒*}' 秒'
    fi
    interval=${idle#*ClientAliveInterval=}; interval=${interval%%，*}
    count=${idle#*ClientAliveCountMax=}; count=${count%%）*}
    [[ "$empty" == no ]] && empty=禁止 || empty=允许
    [[ "$pam" == yes ]] && pam=启用 || pam=禁用
    printf '%sroot 登录方式: %s\n' "$indent" "$root_mode"
    printf '%sopsadmin 登录方式: %s\n' "$indent" "$ops_mode"
    printf '%sauditadmin 登录方式: %s\n' "$indent" "$audit_mode"
    printf '%ssecadmin 登录方式: %s\n' "$indent" "$sec_mode"
    printf '%sSSH 无响应超时: %s\n' "$indent" "$timeout"
    printf '%sClientAliveInterval: %s 秒\n' "$indent" "$interval"
    printf '%sClientAliveCountMax: %s\n' "$indent" "$count"
    printf '%s空密码登录: %s\n' "$indent" "$empty"
    printf '%sPAM: %s\n' "$indent" "$pam"
}

print_state_details() {
    local id="$1" value="$2" indent=${3:-'  '} user group path mode expected owner digest key_type
    local min max warn must_change password_state state
    case "$id" in
        account.*.shell)
            printf '%s登录 Shell: %s\n' "$indent" "$value"
            ;;
        account.*.aging)
            min=$(summary_field "$value" min); max=$(summary_field "$value" max); warn=$(summary_field "$value" warn)
            must_change=$(summary_field "$value" must-change); password_state=$(summary_field "$value" password)
            [[ -n "$min" && -n "$max" && -n "$warn" && -n "$must_change" && -n "$password_state" ]] || return 1
            printf '%s最长有效期: %s 天\n' "$indent" "$max"
            printf '%s最小修改间隔: %s 天\n' "$indent" "$min"
            printf '%s提前警告: %s 天\n' "$indent" "$warn"
            printf '%s首次登录必须修改密码: %s\n' "$indent" "$(yes_no_summary "$must_change")"
            printf '%s密码状态: %s\n' "$indent" "$(password_state_summary "$password_state")"
            ;;
        account.*.primary-group)
            printf '%s主用户组: %s\n' "$indent" "$value"
            ;;
        account.*.group.*)
            group=${id#*.group.}
            state=$(membership_state_summary "$value") || return 1
            printf '%s用户组: %s\n' "$indent" "$group"
            printf '%s成员状态: %s\n' "$indent" "$state"
            ;;
        ssh-key.*)
            path=$(summary_field "$value" path); key_type=$(summary_field "$value" type); digest=$(summary_field "$value" fingerprint)
            [[ -n "$path" && -n "$key_type" && -n "$digest" ]] || return 1
            [[ "$key_type" == ssh-ed25519 ]] && key_type=Ed25519
            printf '%s安装位置: %s\n' "$indent" "$path"
            printf '%s密钥类型: %s\n' "$indent" "$key_type"
            printf '%s密钥指纹: %s\n' "$indent" "$digest"
            ;;
        artifact.*)
            path=${id#artifact.}
            mode=$(summary_field "$value" mode); expected=$(summary_field "$value" expected-mode)
            owner=$(summary_field "$value" owner); digest=$(summary_field "$value" sha256)
            [[ -n "$mode" && -n "$expected" && -n "$owner" && -n "$digest" ]] || return 1
            [[ "$owner" == 0:0 ]] && owner=root:root
            printf '%s文件路径: %s\n' "$indent" "$path"
            printf '%s权限: 0%s\n' "$indent" "$mode"
            printf '%s目标权限: 0%s\n' "$indent" "$expected"
            printf '%s属主: %s\n' "$indent" "$owner"
            printf '%s内容校验值: SHA-256 %s\n' "$indent" "$digest"
            ;;
        ssh.effective)
            print_ssh_policy_details "$value" "$indent"
            ;;
        password.login-defs)
            max=$(summary_field "$value" max); min=$(summary_field "$value" min); warn=$(summary_field "$value" warn)
            if [[ -n "$max" && -n "$min" && -n "$warn" ]]; then
                printf '%s最长有效期: %s 天\n' "$indent" "$max"
                printf '%s最小修改间隔: %s 天\n' "$indent" "$min"
                printf '%s提前警告: %s 天\n' "$indent" "$warn"
            else
                printf '%s最长有效期配置数量: %s\n' "$indent" "$(summary_field "$value" max-count)"
                printf '%s最小修改间隔配置数量: %s\n' "$indent" "$(summary_field "$value" min-count)"
                printf '%s提前警告配置数量: %s\n' "$indent" "$(summary_field "$value" warn-count)"
            fi
            ;;
        password.quality)
            if [[ "$value" == 不存在 ]]; then printf '%s状态: 配置文件不存在\n' "$indent"; return 0; fi
            if [[ "$value" == *-count=* ]]; then
                printf '%s最小长度配置数量: %s\n' "$indent" "$(summary_field "$value" minlen-count)"
                printf '%s数字规则数量: %s\n' "$indent" "$(summary_field "$value" dcredit-count)"
                printf '%s大写规则数量: %s\n' "$indent" "$(summary_field "$value" ucredit-count)"
                printf '%s小写规则数量: %s\n' "$indent" "$(summary_field "$value" lcredit-count)"
                printf '%s符号规则数量: %s\n' "$indent" "$(summary_field "$value" ocredit-count)"
                printf '%s连续字符规则数量: %s\n' "$indent" "$(summary_field "$value" maxrepeat-count)"
                printf '%sroot 限制规则数量: %s\n' "$indent" "$(summary_field "$value" enforce-count)"
                return 0
            fi
            printf '%s最小密码长度: %s 位\n' "$indent" "$(summary_field "$value" minlen)"
            printf '%s数字要求: %s\n' "$indent" "$(pwquality_credit_summary "$(summary_field "$value" dcredit)")"
            printf '%s大写字母要求: %s\n' "$indent" "$(pwquality_credit_summary "$(summary_field "$value" ucredit)")"
            printf '%s小写字母要求: %s\n' "$indent" "$(pwquality_credit_summary "$(summary_field "$value" lcredit)")"
            printf '%s符号要求: %s\n' "$indent" "$(pwquality_credit_summary "$(summary_field "$value" ocredit)")"
            printf '%s连续相同字符上限: %s\n' "$indent" "$(summary_field "$value" maxrepeat)"
            printf '%sroot 同样受限: %s\n' "$indent" "$(yes_no_summary "$(summary_field "$value" enforce-root)")"
            ;;
        password.lockout)
            if [[ "$value" == 不存在 ]]; then printf '%s状态: 配置文件不存在\n' "$indent"; return 0; fi
            if [[ "$value" == *-count=* ]]; then
                printf '%s失败次数规则数量: %s\n' "$indent" "$(summary_field "$value" deny-count)"
                printf '%s解锁时间规则数量: %s\n' "$indent" "$(summary_field "$value" unlock-time-count)"
                return 0
            fi
            printf '%s连续失败次数: %s 次\n' "$indent" "$(summary_field "$value" deny)"
            printf '%s锁定时间: %s 秒\n' "$indent" "$(summary_field "$value" unlock-time)"
            ;;
        pam.debian)
            if [[ "$value" == auth-sha256=* ]]; then
                printf '%scommon-auth 内容校验值: SHA-256 %s\n' "$indent" "$(summary_field "$value" auth-sha256)"
                printf '%scommon-account 内容校验值: SHA-256 %s\n' "$indent" "$(summary_field "$value" account-sha256)"
                printf '%scommon-password 内容校验值: SHA-256 %s\n' "$indent" "$(summary_field "$value" password-sha256)"
            else
                printf '%s登录失败锁定: %s\n' "$indent" "$(pam_lockout_summary "$(summary_field "$value" lockout)")"
                [[ -z $(summary_field "$value" deny) ]] || printf '%s连续失败次数: %s 次\n' "$indent" "$(summary_field "$value" deny)"
                [[ -z $(summary_field "$value" unlock-time) ]] || printf '%s锁定时间: %s 秒\n' "$indent" "$(summary_field "$value" unlock-time)"
                printf '%s密码复杂度: %s\n' "$indent" "$(enabled_state_summary "$(summary_field "$value" quality)")"
            fi
            ;;
        managed-block.*)
            printf '%s配置行数: %s\n' "$indent" "$(summary_field "$value" lines)"
            printf '%s内容校验值: SHA-256 %s\n' "$indent" "$(summary_field "$value" sha256)"
            ;;
        *)
            printf '%s值: %s\n' "$indent" "$value"
            ;;
    esac
}

print_conflict_summary() {
    local id="$1" label="$2" current="$3" target="$4" impact="$5"
    printf '\n%s\n' "$label" >&2
    printf '  当前值:\n' >&2
    print_state_details "$id" "$current" '    ' >&2 || return 1
    printf '  目标值:\n' >&2
    print_state_details "$id" "$target" '    ' >&2 || return 1
    printf '  影响: %s\n' "$impact" >&2
}

resolve_conflict() {
    local id="$1" label="$2" current="$3" target="$4" impact="$5" action choice
    current=$(sanitize_decision_field "$current")
    target=$(sanitize_decision_field "$target")
    CONFLICT_DECISION=''
    if [[ "$current" == "$target" ]]; then
        CONFLICT_DECISION=skip
        info "已存在，跳过: $label"
        print_state_details "$id" "$current" '  ' || return 1
        record_decision "$id" "$current" "$target" skip identical
        return 0
    fi

    print_conflict_summary "$id" "$label" "$current" "$target" "$impact" || return 1
    action=$CONFLICT_ACTION
    if [[ -z "$action" ]]; then
        while :; do
            printf '  1) 覆盖为目标值\n  2) 保留当前值并跳过\n' >&2
            printf '请输入序号 [1]: ' >&2
            IFS= read -r choice || { warn "读取冲突选择失败"; return 1; }
            choice=${choice:-1}
            case "$choice" in
                1) action=overwrite; break ;;
                2) action=skip; break ;;
                *) warn "无效选择，请输入 1-2" ;;
            esac
        done
    fi

    case "$action" in
        overwrite)
            CONFLICT_DECISION=apply
            SYSTEM_CHANGE_REQUIRED=1
            info "将覆盖当前值: $label"
            record_decision "$id" "$current" "$target" apply overwrite
            ;;
        skip)
            CONFLICT_DECISION=skip
            PARTIAL_HARDENING=1
            warn "已保留当前值: $label"
            print_state_details "$id" "$current" '  ' >&2 || return 1
            record_decision "$id" "$current" "$target" skip operator-kept-current
            ;;
        fail)
            record_decision "$id" "$current" "$target" fail conflict
            printf '[ERROR] 配置冲突，未执行覆盖: %s\n' "$label" >&2
            return 1
            ;;
        *)
            printf '[ERROR] 未知冲突处理策略: %s\n' "$action" >&2
            return 1
            ;;
    esac
}

managed_block_content() {
    local file="$1" begin="$2" end="$3"
    [[ -r "$file" ]] || { warn "无法读取配置文件: $file"; return 1; }
    managed_markers_valid "$file" "$begin" "$end" || return 1
    grep -Fqx "$begin" "$file" || return 1
    awk -v begin="$begin" -v end="$end" '
        $0 == begin {inside=1; next}
        $0 == end {inside=0; found=1; exit}
        inside {print}
        END {exit !found}
    ' "$file"
}

file_mode_value() {
    local file="$1" mode
    [[ -e "$file" ]] || return 1
    if mode=$(stat -c '%a' "$file" 2>/dev/null); then
        printf '%s\n' "$mode"
    else
        stat -f '%Lp' "$file"
    fi
}

file_owner_value() {
    local file="$1" owner
    [[ -e "$file" ]] || return 1
    if owner=$(stat -c '%u:%g' "$file" 2>/dev/null); then
        printf '%s\n' "$owner"
    else
        stat -f '%u:%g' "$file"
    fi
}

file_sha256_value() {
    local file="$1"
    [[ -f "$file" && -r "$file" ]] || return 1
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" | awk '{print $1}'
    else
        warn "缺少 SHA-256 计算命令: sha256sum 或 shasum"
        return 1
    fi
}

text_state_summary() {
    local content="$1" digest lines
    if command -v sha256sum >/dev/null 2>&1; then
        digest=$(printf '%s' "$content" | sha256sum | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        digest=$(printf '%s' "$content" | shasum -a 256 | awk '{print $1}')
    else
        warn "缺少 SHA-256 计算命令: sha256sum 或 shasum"
        return 1
    fi
    lines=$(printf '%s\n' "$content" | awk 'END {print NR}')
    printf 'lines=%s,sha256=%s\n' "$lines" "$digest"
}

file_state_summary() {
    local path="$1" expected_mode="$2" mode owner digest
    [[ -e "$path" ]] || { printf '不存在\n'; return 0; }
    expected_mode=${expected_mode#0}
    mode=$(file_mode_value "$path") || return 1
    owner=$(file_owner_value "$path") || return 1
    digest=$(file_sha256_value "$path") || return 1
    printf 'mode=%s,expected-mode=%s,owner=%s,sha256=%s\n' "$mode" "$expected_mode" "$owner" "$digest"
}

replace_managed_block() {
    local file="$1" begin="$2" end="$3" content="$4" position=${5:-bottom}
    local conflict_checked=${6:-no} directory tmp stripped current current_summary target_summary
    directory=$(dirname "$file")
    mkdir -p "$directory"
    tmp=$(mktemp "$directory/.server-hardening.XXXXXX")
    stripped=$(mktemp "$directory/.server-hardening.XXXXXX")
    if [[ -f "$file" ]]; then
        managed_markers_valid "$file" "$begin" "$end" || { rm -f "$tmp" "$stripped"; return 1; }
        if [[ "$conflict_checked" != yes ]] && grep -Fqx "$begin" "$file"; then
            current=$(managed_block_content "$file" "$begin" "$end") || { rm -f "$tmp" "$stripped"; return 1; }
            current_summary=$(text_state_summary "$current") || { rm -f "$tmp" "$stripped"; return 1; }
            target_summary=$(text_state_summary "$content") || { rm -f "$tmp" "$stripped"; return 1; }
            resolve_conflict "managed-block.$file" "受管理配置块 $file" "$current_summary" "$target_summary" "替换该配置块内容" || { rm -f "$tmp" "$stripped"; return 1; }
            if [[ "$CONFLICT_DECISION" == skip ]]; then
                rm -f "$tmp" "$stripped"
                return 0
            fi
        fi
        awk -v begin="$begin" -v end="$end" '
            $0 == begin {inside=1; next}
            $0 == end {inside=0; next}
            !inside {print}
        ' "$file" > "$stripped"
    else
        : > "$stripped"
    fi
    if [[ "$position" == top ]]; then
        {
            printf '%s\n%s\n%s\n' "$begin" "$content" "$end"
            sed '/^[[:space:]]*$/N;/^\n$/D' "$stripped"
        } > "$tmp"
    else
        {
            cat "$stripped"
            [[ ! -s "$stripped" ]] || printf '\n'
            printf '%s\n%s\n%s\n' "$begin" "$content" "$end"
        } > "$tmp"
    fi
    if [[ -e "$file" ]]; then
        chmod --reference="$file" "$tmp" 2>/dev/null || chmod 0644 "$tmp"
        chown --reference="$file" "$tmp" 2>/dev/null || true
    else
        chmod 0644 "$tmp"
    fi
    mv -f "$tmp" "$file"
    rm -f "$stripped"
    SYSTEM_CHANGE_REQUIRED=1
}

managed_markers_valid() {
    local file="$1" begin="$2" end="$3" begin_count end_count begin_line end_line
    [[ -f "$file" ]] || return 0
    begin_count=$(grep -Fxc "$begin" "$file" || true)
    end_count=$(grep -Fxc "$end" "$file" || true)
    if (( begin_count == 0 && end_count == 0 )); then return 0; fi
    (( begin_count == 1 && end_count == 1 )) || { warn "受管理块标记重复或残缺: $file"; return 1; }
    begin_line=$(grep -Fn "$begin" "$file" | cut -d: -f1)
    end_line=$(grep -Fn "$end" "$file" | cut -d: -f1)
    (( begin_line < end_line )) || { warn "受管理块标记顺序错误: $file"; return 1; }
}

remove_managed_block() {
    local file="$1" begin="$2" end="$3" tmp
    [[ -f "$file" ]] || return 0
    managed_markers_valid "$file" "$begin" "$end" || return 1
    tmp=$(mktemp "$(dirname "$file")/.server-hardening.XXXXXX")
    strip_managed_block_to_file "$file" "$begin" "$end" "$tmp"
    chmod --reference="$file" "$tmp" 2>/dev/null || chmod 0644 "$tmp"
    chown --reference="$file" "$tmp" 2>/dev/null || true
    mv -f "$tmp" "$file"
}
