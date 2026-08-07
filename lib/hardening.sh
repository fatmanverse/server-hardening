#!/usr/bin/env bash

# Sourced by server_hardening.sh; do not execute directly.
# shellcheck disable=SC2034,SC2153

show_execution_plan() {
    cat <<EOF

=== 本次加固功能说明 ===
[1] SSH 登录方式
    root: $(root_login_summary)
    三员: $(admin_login_summary)
    需要密钥时，每个账户生成独立密钥，私钥导出到: $KEY_EXPORT_DIR
    新生成的公私钥还会写入 root 专用汇总文件: $CREDENTIAL_BUNDLE_PATH

[2] 运维管理员 opsadmin
    不存在时自动创建，授予完整 sudo 权限，提权需输入本人密码。

[3] 审计管理员 auditadmin
    不存在时自动创建，仅可读取系统、SSH/认证、auditd 日志和执行固定只读查询。
    如账户原在 sudo/wheel 组，将移除其完整管理权限。

[4] 安全管理员 secadmin
    不存在时自动创建，可修改指定 SSH/PAM/密码策略文件、校验/重载 SSH、管理防火墙。
    不允许任意 systemctl、通用 Shell、任意编辑器或无限制 sudo。
    注意: 该角色可修改认证边界，仍属高权限安全角色。

[5] 密码生命周期
    新建三员账户各自生成 ${MANAGED_ACCOUNT_PASSWORD_LENGTH} 位强密码，应用成功后在控制台仅显示一次。
    新建账户首次登录必须改密；已有同名账户不重置密码。
    所有本地普通用户的密码最长 30 天，最小修改间隔 1 天，提前 7 天警告。
    本次新生成的账户密码和自动生成的 root 密码还会写入: $CREDENTIAL_BUNDLE_PATH

[6] 密码复杂度与失败锁定
    密码复杂度: ${PASSWORD_QUALITY:-未选择}；登录失败锁定: ${LOCKOUT:-未选择}。
    启用时仅在可识别的 PAM 布局上应用，未识别布局会明确失败。

[7] 重复执行与已有配置
    脚本先读取当前生效值；完全一致的项目提示"已存在，跳过"，且不改写文件。
    不一致时显示当前值、目标值和影响，交互模式使用数字选择覆盖或保留。
    非交互模式由 --conflict-action 控制；选择保留后最终结果标记为"部分策略未应用"。
    SSH 密钥仅显示类型和指纹；密码、shadow 哈希、私钥及完整公钥不打印、不记录。
    如果全部项目均跳过，事务标记为 no-changes，并自动移除临时回滚 timer，无需新建 SSH 会话确认。

[8] 备份、校验与自动回滚
    变更前备份 SSH、PAM、账户数据库、家目录和角色授权文件。
    应用后执行 visudo 和 sshd 语法校验，任一步失败立即同步回滚。
    SSH 重载后启动 ${ROLLBACK_TIMEOUT:-$DEFAULT_ROLLBACK_TIMEOUT} 秒自动回滚，必须从新 SSH 会话确认。

[9] 登录系统信息展示
    安装 /usr/local/bin/server-hardening-sysinfo（0755）和
    /etc/profile.d/99-server-hardening-sysinfo.sh（0644）。
    交互式 TTY 登录时自动展示系统基本信息（不执行 df，避免 I/O 阻塞）。
    设置 SERVER_HARDENING_SYSINFO_DISABLE=1 可在当前会话禁用展示。
    两个文件纳入事务备份与自动回滚。
EOF
}

read_os_release_value() {
    local file="$1" key="$2" line value
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" == "$key="* ]] || continue
        value=${line#*=}
        value=${value#\"}; value=${value%\"}
        value=${value#\'}; value=${value%\'}
        printf '%s\n' "$value"
        return 0
    done < "$file"
    return 1
}

os_release_id_like() {
    local file="$1"
    read_os_release_value "$file" ID_LIKE 2>/dev/null || true
}

version_major_number() {
    local version="$1" major
    version=${version#[Vv]}
    major=${version%%.*}
    is_uint "$major" || return 1
    printf '%d\n' "$((10#$major))"
}

# Matches a whole space-delimited token. Word splitting an untrusted ID_LIKE
# would also glob-expand it, so "*" could match files in the working directory.
id_like_contains() {
    local id_like expected="$2"
    id_like=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -s '[:space:]' ' ')
    case " $id_like " in
        *" $expected "*) return 0 ;;
    esac
    return 1
}

# Emits: family<TAB>tier<TAB>reason. tier is verified, derived or unsupported.
classify_platform() {
    local family="$1" tier="$2" reason="$3"
    printf '%s\t%s\t%s\n' "$family" "$tier" "$reason"
}

# Debian derivatives keep /etc/pam.d/common-* and pam-auth-update.
classify_debian_like_platform() {
    local id="$1" version="$2" major="$3"
    case "$id" in
        ubuntu)
            case "$version" in
                18.04|20.04|22.04|24.04)
                    classify_platform debian verified '已验证的 Ubuntu LTS'
                    ;;
                *)
                    if [[ -n "$major" ]] && (( major >= 18 && major <= MAX_KNOWN_UBUNTU_MAJOR )); then
                        classify_platform debian derived "Ubuntu $version 未经本项目实测，PAM 布局与已验证 LTS 相同"
                    else
                        classify_platform '' unsupported "Ubuntu $version 超出已知兼容区间（18.04-${MAX_KNOWN_UBUNTU_MAJOR}.x）"
                    fi
                    ;;
            esac
            ;;
        debian)
            case "$major" in
                10|11|12)
                    classify_platform debian verified '已验证的 Debian 版本'
                    ;;
                13)
                    classify_platform debian derived 'Debian 13 仍使用 common-* 与 pam-auth-update，未经本项目实测'
                    ;;
                *)
                    classify_platform '' unsupported "Debian $version 超出已知兼容区间（10-13）"
                    ;;
            esac
            ;;
        linuxmint|pop|zorin|elementary|kali|raspbian|devuan)
            classify_platform debian derived "$id 属于 Debian/Ubuntu 衍生版，沿用 common-* PAM 布局"
            ;;
    esac
}

# RHEL family: major 7 uses authconfig with the system-auth-ac symlink layout,
# major 8 and later use authselect.
classify_rhel_like_platform() {
    local id="$1" version="$2" major="$3"
    case "$id" in
        centos)
            case "$major" in
                7) classify_platform rhel7 verified '已验证的 CentOS 7' ;;
                8|9|10) classify_platform rhel8plus derived "CentOS $version 与同版本 RHEL 同源，使用 authselect" ;;
                *) classify_platform '' unsupported "CentOS $version 超出已知兼容区间（7-10）" ;;
            esac
            ;;
        rhel|rocky|almalinux)
            case "$major" in
                8|9) classify_platform rhel8plus verified '已验证的 RHEL 系 authselect 平台' ;;
                10) classify_platform rhel8plus derived "$id 10 仍使用 authselect，默认 profile 已改为 local，未经本项目实测" ;;
                *) classify_platform '' unsupported "$id $version 超出已知兼容区间（8-10）" ;;
            esac
            ;;
        ol)
            case "$major" in
                7) classify_platform rhel7 derived 'Oracle Linux 7 沿用 authconfig 布局，未经本项目实测' ;;
                8|9|10) classify_platform rhel8plus derived "Oracle Linux $major 沿用 authselect 布局，未经本项目实测" ;;
                *) classify_platform '' unsupported "Oracle Linux $version 超出已知兼容区间（7-10）" ;;
            esac
            ;;
        fedora)
            if [[ -n "$major" ]] && (( major >= 36 && major <= MAX_KNOWN_FEDORA_MAJOR )); then
                classify_platform rhel8plus derived "Fedora $major 由 authselect 强制管理 PAM，未经本项目实测"
            else
                classify_platform '' unsupported "Fedora $version 超出已知兼容区间（36-${MAX_KNOWN_FEDORA_MAJOR}）"
            fi
            ;;
        amzn)
            # VERSION_ID is a release year, not an EL major; match it literally.
            case "$version" in
                2|2.*) classify_platform rhel7 derived 'Amazon Linux 2 沿用 RHEL 7 时代 authconfig 布局，未经本项目实测' ;;
                2023|2023.*) classify_platform rhel8plus derived 'Amazon Linux 2023 以 Fedora 为上游并提供 authselect，未经本项目实测' ;;
                *) classify_platform '' unsupported "无法识别的 Amazon Linux 版本: $version" ;;
            esac
            ;;
        anolis)
            case "$major" in
                8|23|25) classify_platform rhel8plus derived "Anolis OS $version 提供 authselect（版本号不是 EL major），未经本项目实测" ;;
                *) classify_platform '' unsupported "无法识别的 Anolis OS 版本: $version" ;;
            esac
            ;;
        eurolinux|circle|navylinux|springdale|cloudlinux|miraclelinux)
            case "$major" in
                7) classify_platform rhel7 derived "$id $major 属于 EL7 重打包，未经本项目实测" ;;
                8|9|10) classify_platform rhel8plus derived "$id $major 属于 EL8+ 重打包，未经本项目实测" ;;
                *) classify_platform '' unsupported "$id $version 超出已知兼容区间（7-10）" ;;
            esac
            ;;
    esac
}

platform_classification_from_os_release() {
    local file="$1" id version id_like major
    local like_debian=0 like_rhel=0
    [[ -r "$file" ]] || { classify_platform '' unsupported "无法读取 $file"; return 0; }
    id=$(read_os_release_value "$file" ID) || { classify_platform '' unsupported 'os-release 缺少 ID'; return 0; }
    version=$(read_os_release_value "$file" VERSION_ID) || { classify_platform '' unsupported 'os-release 缺少 VERSION_ID'; return 0; }
    id=$(printf '%s' "$id" | tr '[:upper:]' '[:lower:]')
    id_like=$(os_release_id_like "$file")
    major=$(version_major_number "$version" 2>/dev/null || true)

    case "$id" in
        ubuntu|debian|linuxmint|pop|zorin|elementary|kali|raspbian|devuan)
            classify_debian_like_platform "$id" "$version" "$major"
            return 0
            ;;
        centos|rhel|rocky|almalinux|ol|fedora|amzn|anolis|eurolinux|circle|navylinux|springdale|cloudlinux|miraclelinux)
            classify_rhel_like_platform "$id" "$version" "$major"
            return 0
            ;;
        openeuler)
            classify_platform '' unsupported 'openEuler 的 PAM 由厂商策略管理，authselect 接管未经验证，可能导致 root 无法登录'
            return 0
            ;;
        kylin|uos|deepin)
            classify_platform '' unsupported "$id 同一发行版 ID 覆盖多种不同底层（EL7/EL8/openEuler/Debian），无法安全推断 PAM 布局"
            return 0
            ;;
        opensuse*|sles|sled|suse)
            classify_platform '' unsupported 'SUSE 使用 pam-config 管理 PAM，与本脚本的实现不兼容'
            return 0
            ;;
        alpine)
            classify_platform '' unsupported 'Alpine 默认不使用 glibc/PAM 认证栈'
            return 0
            ;;
        arch|manjaro|gentoo|nixos|void)
            classify_platform '' unsupported "$id 属于滚动更新或非 PAM 托管家族，没有稳定的 PAM 布局合同"
            return 0
            ;;
    esac

    id_like_contains "$id_like" debian && like_debian=1
    id_like_contains "$id_like" ubuntu && like_debian=1
    id_like_contains "$id_like" rhel && like_rhel=1
    id_like_contains "$id_like" centos && like_rhel=1
    id_like_contains "$id_like" fedora && like_rhel=1

    if (( like_debian && like_rhel )); then
        classify_platform '' unsupported "$id 的 ID_LIKE 同时命中 Debian 和 RHEL 家族，无法安全推断"
    elif (( like_debian )); then
        classify_platform debian derived "未知发行版 $id，依据 ID_LIKE 推断为 Debian PAM 布局"
    elif (( like_rhel )); then
        classify_platform rhel8plus derived "未知发行版 $id，依据 ID_LIKE 推断为 authselect PAM 布局"
    else
        classify_platform '' unsupported "未知发行版 $id，且 ID_LIKE 未命中任何受支持家族"
    fi
}

# Splits a classification record into family, tier and reason. TAB is IFS
# whitespace, so `IFS=$'\t' read` would drop the leading empty family field on
# unsupported records and shift tier into its place.
split_platform_classification() {
    # Locals are prefixed because callers pass their own variable names in, and
    # a collision would make printf -v write to this scope instead of theirs.
    local _spc_record="$1" _spc_family_var="$2" _spc_tier_var="$3" _spc_reason_var="$4" _spc_rest
    _spc_rest=${_spc_record#*$'\t'}
    printf -v "$_spc_family_var" '%s' "${_spc_record%%$'\t'*}"
    printf -v "$_spc_tier_var" '%s' "${_spc_rest%%$'\t'*}"
    printf -v "$_spc_reason_var" '%s' "${_spc_record##*$'\t'}"
}

platform_classification_family() {
    local record family tier reason
    record=$(platform_classification_from_os_release "$1")
    split_platform_classification "$record" family tier reason
    printf '%s\n' "$family"
}

platform_classification_tier() {
    local record family tier reason
    record=$(platform_classification_from_os_release "$1")
    split_platform_classification "$record" family tier reason
    printf '%s\n' "$tier"
}

platform_family_from_os_release() {
    local record family tier reason
    record=$(platform_classification_from_os_release "$1")
    split_platform_classification "$record" family tier reason
    case "$family:$tier" in
        debian:verified|debian:derived|rhel7:verified|rhel7:derived|rhel8plus:verified|rhel8plus:derived) ;;
        *) return 1 ;;
    esac
    printf '%s\n' "$family"
}

detect_platform() {
    local file=${OS_RELEASE_FILE:-$(root_path /etc/os-release)}
    [[ -r "$file" ]] || die "无法读取 $file"
    PLATFORM_ID=$(read_os_release_value "$file" ID) || die "os-release 缺少 ID"
    PLATFORM_VERSION=$(read_os_release_value "$file" VERSION_ID) || die "os-release 缺少 VERSION_ID"
    # TAB is IFS whitespace, so `IFS=$'\t' read` would drop the leading empty
    # family field and shift tier into it. Split on the literal separator.
    local classification
    classification=$(platform_classification_from_os_release "$file")
    split_platform_classification "$classification" PLATFORM_FAMILY PLATFORM_TIER PLATFORM_REASON
    # An unrecognised tier means the dispatch tables disagree; refuse rather
    # than fall through to PAM edits with an unknown family.
    case "$PLATFORM_TIER" in
        verified|derived)
            case "$PLATFORM_FAMILY" in
                debian|rhel7|rhel8plus) ;;
                *) die "无法判定平台家族: $PLATFORM_ID $PLATFORM_VERSION" ;;
            esac
            ;;
        unsupported)
            die "不支持的系统: $PLATFORM_ID $PLATFORM_VERSION（$PLATFORM_REASON）"
            ;;
        *)
            die "无法判定平台兼容性: $PLATFORM_ID $PLATFORM_VERSION"
            ;;
    esac
    if [[ "$PLATFORM_TIER" == derived ]]; then
        if (( ! ALLOW_UNVERIFIED_PLATFORM )); then
            warn "未实测的平台: $PLATFORM_ID $PLATFORM_VERSION -> $PLATFORM_FAMILY（$PLATFORM_REASON）"
            die "如确认承担风险，请追加 --allow-unverified-platform 重新执行"
        fi
        # detect_platform runs before the wizard and again from apply_hardening.
        if (( ! PLATFORM_WARNED )); then
            warn "平台未经本项目实测: $PLATFORM_ID $PLATFORM_VERSION -> $PLATFORM_FAMILY（$PLATFORM_REASON）"
            warn "已按 --allow-unverified-platform 继续；PAM 结构校验仍会强制执行"
        fi
    fi
    if [[ "$PLATFORM_FAMILY" == rhel7 ]] && (( ! PLATFORM_WARNED )); then
        warn "$PLATFORM_ID $PLATFORM_VERSION 属于 EL7 代际，已停止上游安全更新；本脚本仍完整支持，但建议尽快升级系统"
    fi
    PLATFORM_WARNED=1
    local required
    for required in systemctl sshd tar flock; do
        command -v "$required" >/dev/null 2>&1 || die "缺少必需命令: $required"
    done
    case "$PLATFORM_FAMILY" in
        debian)
            if systemd_unit_exists ssh.service; then SSH_SERVICE=ssh
            elif systemd_unit_exists sshd.service; then SSH_SERVICE=sshd
            else die "未找到 ssh.service 或 sshd.service"
            fi
            ;;
        rhel7|rhel8plus)
            if systemd_unit_exists sshd.service; then SSH_SERVICE=sshd
            elif systemd_unit_exists ssh.service; then SSH_SERVICE=ssh
            else die "未找到 sshd.service 或 ssh.service"
            fi
            ;;
    esac
}

systemd_unit_exists() {
    local unit="$1"
    systemctl list-unit-files --no-legend "$unit" 2>/dev/null | awk -v unit="$unit" '$1 == unit {found=1} END {exit !found}'
}

render_login_defs_block() {
    printf 'PASS_MAX_DAYS\t%s\nPASS_MIN_DAYS\t%s\nPASS_WARN_AGE\t%s\n' "$PASS_MAX_DAYS" "$PASS_MIN_DAYS" "$PASS_WARN_AGE"
}

render_pwquality_block() {
    printf 'minlen = %s\ndcredit = -1\nucredit = -1\nlcredit = -1\nocredit = -1\nmaxrepeat = 3\nenforce_for_root\n' "$MIN_CONFIGURED_PASSWORD_LENGTH"
}

render_faillock_block() {
    printf 'deny = %s\nunlock_time = %s\n' "$LOCKOUT_DENY" "$UNLOCK_TIME"
}

shell_is_valid() {
    local shell="$1" shells_file=${SHELLS_FILE:-$(root_path /etc/shells)}
    [[ -x $(root_path "$shell") ]] || return 1
    grep -Fqx "$shell" "$shells_file"
}

preflight_access_check() {
    local required
    for required in sudo groupadd useradd usermod gpasswd chpasswd chage visudo; do
        command_exists "$required" || die "三员账户管理缺少必需命令: $required"
    done
    if ssh_keys_requested; then
        command_exists ssh-keygen || die "SSH 密钥模式缺少必需命令: ssh-keygen"
        [[ "$KEY_EXPORT_DIR" == /* && -d "$KEY_EXPORT_DIR" && ! -L "$KEY_EXPORT_DIR" ]] || \
            die "SSH 私钥导出目录必须是存在且非符号链接的绝对路径: $KEY_EXPORT_DIR"
    fi
    validate_credential_bundle_path || die "凭据汇总文件路径不安全"
    if (( ! DRY_RUN )); then
        sudoers_dropin_is_enabled || die "/etc/sudoers 未引用 /etc/sudoers.d，无法安全安装三员角色权限"
    fi
}

sudoers_dropin_is_enabled() {
    local sudoers_file=${SUDOERS_FILE:-$(root_path /etc/sudoers)}
    [[ -r "$sudoers_file" ]] || return 1
    grep -Eq '^[[:space:]]*(#|@)includedir[[:space:]]+/etc/sudoers\.d([[:space:]]|$)' "$sudoers_file"
}

show_apply_result() {
    if (( PARTIAL_HARDENING )); then
        warn "部分策略未应用，已保留操作者选择的当前值；事务 ID: $TRANSACTION_ID"
    else
        info "加固已完整应用，事务 ID: $TRANSACTION_ID"
    fi
}

finish_no_change_transaction() {
    disarm_automatic_rollback "$TRANSACTION_DIR"
    set_transaction_status "$TRANSACTION_DIR" no-changes
    CHANGE_STARTED=0
    unset ROOT_PASSWORD_VALUE
    reset_managed_account_state
    reset_managed_ssh_key_state
    CREDENTIAL_SECTIONS=()
    if (( PARTIAL_HARDENING )); then
        warn "本次未执行系统变更；部分目标策略按选择保留当前值。事务 ID: $TRANSACTION_ID"
    else
        info "所有配置均已符合目标，无需重载 SSH，也无需新建会话确认。事务 ID: $TRANSACTION_ID"
    fi
}

login_defs_policy_value() {
    local file="$1"
    [[ -r "$file" ]] || return 1
    awk '
        /^[[:space:]]*#/ {next}
        $1 == "PASS_MAX_DAYS" {max[++max_count]=$2}
        $1 == "PASS_MIN_DAYS" {min[++min_count]=$2}
        $1 == "PASS_WARN_AGE" {warn[++warn_count]=$2}
        END {
            if (max_count == 1 && min_count == 1 && warn_count == 1) {
                printf "max=%s,min=%s,warn=%s\n", max[1], min[1], warn[1]
                exit
            }
            printf "max-count=%d,min-count=%d,warn-count=%d\n", max_count, min_count, warn_count
        }
    ' "$file"
}

pwquality_policy_value() {
    local file="$1"
    [[ -r "$file" ]] || { printf '不存在\n'; return 0; }
    awk '
        /^[[:space:]]*#/ || /^[[:space:]]*$/ {next}
        {
            line=$0
            sub(/^[[:space:]]*/, "", line)
            if (line == "enforce_for_root") {enforce++; next}
            split(line, pair, "=")
            key=pair[1]; value=pair[2]
            gsub(/[[:space:]]/, "", key); gsub(/[[:space:]]/, "", value)
            if (key ~ /^(minlen|dcredit|ucredit|lcredit|ocredit|maxrepeat)$/) {
                count[key]++
                values[key]=value
            }
        }
        END {
            keys[1]="minlen"; keys[2]="dcredit"; keys[3]="ucredit"; keys[4]="lcredit"; keys[5]="ocredit"; keys[6]="maxrepeat"
            valid=(enforce == 1)
            for (i=1; i<=6; i++) if (count[keys[i]] != 1) valid=0
            if (!valid) {
                printf "minlen-count=%d,dcredit-count=%d,ucredit-count=%d,lcredit-count=%d,ocredit-count=%d,maxrepeat-count=%d,enforce-count=%d\n", count["minlen"], count["dcredit"], count["ucredit"], count["lcredit"], count["ocredit"], count["maxrepeat"], enforce
                exit
            }
            printf "minlen=%s,dcredit=%s,ucredit=%s,lcredit=%s,ocredit=%s,maxrepeat=%s,enforce-root=yes\n", values["minlen"], values["dcredit"], values["ucredit"], values["lcredit"], values["ocredit"], values["maxrepeat"]
        }
    ' "$file"
}

faillock_policy_value() {
    local file="$1"
    [[ -r "$file" ]] || { printf '不存在\n'; return 0; }
    awk '
        /^[[:space:]]*#/ || /^[[:space:]]*$/ {next}
        {
            line=$0; split(line, pair, "=")
            key=pair[1]; value=pair[2]
            gsub(/[[:space:]]/, "", key); gsub(/[[:space:]]/, "", value)
            if (key == "deny") {deny[++deny_count]=value}
            if (key == "unlock_time") {unlock[++unlock_count]=value}
        }
        END {
            if (deny_count == 1 && unlock_count == 1) printf "deny=%s,unlock-time=%s\n", deny[1], unlock[1]
            else printf "deny-count=%d,unlock-time-count=%d\n", deny_count, unlock_count
        }
    ' "$file"
}

remove_policy_keys() {
    local file="$1" policy="$2" tmp
    tmp=$(mktemp "$(dirname "$file")/.server-hardening.XXXXXX")
    case "$policy" in
        login-defs)
            awk '!/^[[:space:]]*PASS_(MAX_DAYS|MIN_DAYS|WARN_AGE)[[:space:]]/' "$file" > "$tmp"
            ;;
        pwquality)
            awk '!/^[[:space:]]*(minlen|dcredit|ucredit|lcredit|ocredit|maxrepeat)[[:space:]]*=/ && !/^[[:space:]]*enforce_for_root[[:space:]]*($|#)/' "$file" > "$tmp"
            ;;
        faillock)
            awk '!/^[[:space:]]*(deny|unlock_time)[[:space:]]*=/' "$file" > "$tmp"
            ;;
        *) rm -f "$tmp"; return 1 ;;
    esac
    chmod --reference="$file" "$tmp" 2>/dev/null || chmod 0644 "$tmp"
    chown --reference="$file" "$tmp" 2>/dev/null || true
    mv -f "$tmp" "$file"
}

remove_managed_block_with_conflict() {
    local file="$1" begin="$2" end="$3" label="$4" current current_summary target='不存在'
    if [[ ! -f "$file" ]] || ! grep -Fqx "$begin" "$file"; then
        resolve_conflict "managed-block.$file" "$label" "$target" "$target" "保留系统当前配置" || return 1
        return 0
    fi
    current=$(managed_block_content "$file" "$begin" "$end") || return 1
    current_summary=$(text_state_summary "$current") || return 1
    resolve_conflict "managed-block.$file" "$label" "$current_summary" "$target" "移除本脚本此前写入的配置块" || return 1
    [[ "$CONFLICT_DECISION" == apply ]] || return 0
    if (( DRY_RUN )); then return 0; fi
    remove_managed_block "$file" "$begin" "$end"
}

apply_login_defs_policy() {
    local file="$1" current target
    current=$(login_defs_policy_value "$file") || return 1
    target="max=$PASS_MAX_DAYS,min=$PASS_MIN_DAYS,warn=$PASS_WARN_AGE"
    resolve_conflict password.login-defs '系统默认密码周期' "$current" "$target" "统一新建账户的默认密码周期" || return 1
    [[ "$CONFLICT_DECISION" == apply ]] || return 0
    if (( DRY_RUN )); then info "[dry-run] 将更新系统默认密码周期"; return 0; fi
    remove_managed_block "$file" "$LOGIN_DEFS_BLOCK_BEGIN" "$LOGIN_DEFS_BLOCK_END" || return 1
    remove_policy_keys "$file" login-defs || return 1
    replace_managed_block "$file" "$LOGIN_DEFS_BLOCK_BEGIN" "$LOGIN_DEFS_BLOCK_END" "$(render_login_defs_block)" bottom
}

apply_pwquality_policy() {
    local file="$1" current target
    if [[ "$PASSWORD_QUALITY" != enable ]]; then
        remove_managed_block_with_conflict "$file" "$PWQUALITY_BLOCK_BEGIN" "$PWQUALITY_BLOCK_END" '脚本管理的密码复杂度配置'
        return
    fi
    target="minlen=$MIN_CONFIGURED_PASSWORD_LENGTH,dcredit=-1,ucredit=-1,lcredit=-1,ocredit=-1,maxrepeat=3,enforce-root=yes"
    if [[ ! -e "$file" ]]; then
        info "配置不存在，将创建: ${file}（目标值: ${target}）"
        if (( DRY_RUN )); then return 0; fi
        replace_managed_block "$file" "$PWQUALITY_BLOCK_BEGIN" "$PWQUALITY_BLOCK_END" "$(render_pwquality_block)" bottom
        return
    fi
    current=$(pwquality_policy_value "$file") || return 1
    resolve_conflict password.quality '密码复杂度策略' "$current" "$target" "统一密码长度和字符类别要求" || return 1
    [[ "$CONFLICT_DECISION" == apply ]] || return 0
    if (( DRY_RUN )); then info "[dry-run] 将更新密码复杂度策略"; return 0; fi
    remove_managed_block "$file" "$PWQUALITY_BLOCK_BEGIN" "$PWQUALITY_BLOCK_END" || return 1
    remove_policy_keys "$file" pwquality || return 1
    replace_managed_block "$file" "$PWQUALITY_BLOCK_BEGIN" "$PWQUALITY_BLOCK_END" "$(render_pwquality_block)" bottom
}

apply_faillock_file_policy() {
    local file="$1" enabled="$2" current target
    if [[ "$enabled" != yes ]]; then
        remove_managed_block_with_conflict "$file" "$FAILLOCK_BLOCK_BEGIN" "$FAILLOCK_BLOCK_END" '脚本管理的登录失败锁定配置'
        return
    fi
    target="deny=$LOCKOUT_DENY,unlock-time=$UNLOCK_TIME"
    if [[ ! -e "$file" ]]; then
        info "配置不存在，将创建: ${file}（目标值: ${target}）"
        if (( DRY_RUN )); then return 0; fi
        replace_managed_block "$file" "$FAILLOCK_BLOCK_BEGIN" "$FAILLOCK_BLOCK_END" "$(render_faillock_block)" bottom
        return
    fi
    current=$(faillock_policy_value "$file") || return 1
    resolve_conflict password.lockout '登录失败锁定参数' "$current" "$target" "设置失败次数和解锁等待时间" || return 1
    [[ "$CONFLICT_DECISION" == apply ]] || return 0
    if (( DRY_RUN )); then info "[dry-run] 将更新登录失败锁定参数"; return 0; fi
    remove_managed_block "$file" "$FAILLOCK_BLOCK_BEGIN" "$FAILLOCK_BLOCK_END" || return 1
    remove_policy_keys "$file" faillock || return 1
    replace_managed_block "$file" "$FAILLOCK_BLOCK_BEGIN" "$FAILLOCK_BLOCK_END" "$(render_faillock_block)" bottom
}

apply_file_policies() {
    local sshd_config login_defs pwquality faillock
    sshd_config=$(root_path /etc/ssh/sshd_config)
    apply_ssh_policy "$sshd_config" || return 1
    login_defs=$(root_path /etc/login.defs)
    apply_login_defs_policy "$login_defs" || return 1
    pwquality=$(root_path /etc/security/pwquality.conf)
    apply_pwquality_policy "$pwquality" || return 1
    faillock=$(root_path /etc/security/faillock.conf)
    if [[ "$LOCKOUT" == enable && "$PAM_LOCKOUT_MODULE" == faillock ]] || [[ "$LOCKOUT" == enable && ( "$PLATFORM_FAMILY" == rhel8plus || "$PLATFORM_FAMILY" == rhel7 ) ]]; then
        apply_faillock_file_policy "$faillock" yes || return 1
    else
        apply_faillock_file_policy "$faillock" no || return 1
    fi
}

apply_account_policies() {
    local user
    if [[ "$ROOT_PASSWORD_ACTION" != keep ]]; then
        printf 'root:%s\n' "$ROOT_PASSWORD_VALUE" | chpasswd
        SYSTEM_CHANGE_REQUIRED=1
        if [[ "$ROOT_PASSWORD_ACTION" == generate ]]; then
            record_root_password_credential "$ROOT_PASSWORD_VALUE"
        fi
    fi
    if [[ "$APPLY_AGING_EXISTING" == yes ]]; then
        while IFS= read -r user; do
            [[ -n "$user" ]] || continue
            ensure_password_aging "$user" "$PASS_MAX_DAYS" "$PASS_MIN_DAYS" "$PASS_WARN_AGE" || return 1
        done < <(list_regular_users)
    fi
}

show_dry_run() {
    info "[dry-run] 平台: $PLATFORM_ID $PLATFORM_VERSION ($PLATFORM_FAMILY)"
    printf '\n--- 三员账户计划 ---\n'
    printf 'opsadmin: 不存在时创建，完整 sudo，新账户首次登录改密\n'
    printf 'auditadmin: 不存在时创建，日志和固定查询只读，无通用 sudo\n'
    printf 'secadmin: 不存在时创建，受限 SSH/PAM/防火墙管理，无通用 sudo\n'
    printf 'root SSH: %s\n' "$(root_login_summary)"
    printf '三员 SSH: %s\n' "$(admin_login_summary)"
    if ssh_keys_requested; then
        printf '密钥计划: 每个启用密钥登录的账户生成独立 Ed25519 密钥，私钥导出到 %s\n' "$KEY_EXPORT_DIR"
    fi
    printf '凭据汇总: 仅有新增凭据时原子更新 %s（root:root，0600）\n' "$CREDENTIAL_BUNDLE_PATH"
    printf '\n--- %s ---\n%s\n' "$ROLE_SUDOERS_PATH" "$(render_role_sudoers)"
    printf '\n--- /etc/ssh/sshd_config managed block ---\n%s\n' "$(render_ssh_managed_block "$ROOT_LOGIN" "$ADMIN_LOGIN" "$SSH_IDLE_TIMEOUT")"
    printf '\n--- /etc/login.defs managed block ---\n%s\n' "$(render_login_defs_block)"
    if [[ "$PASSWORD_QUALITY" == enable ]]; then
        printf '\n--- /etc/security/pwquality.conf managed block ---\n%s\n' "$(render_pwquality_block)"
    fi
    if [[ "$LOCKOUT" == enable ]]; then
        printf '\n--- lockout policy ---\ndeny=%s unlock_time=%s\n' "$LOCKOUT_DENY" "$UNLOCK_TIME"
    fi
    printf '\n--- %s ---\n%s\n' "$SYSINFO_COLLECTOR_PATH" "$(sysinfo_collector_content)"
    printf '\n--- %s ---\n%s\n' "$SYSINFO_PROFILE_PATH" "$(sysinfo_profile_content)"
    info "[dry-run] 不会写入文件、修改密码、安装包或重载 SSH"
}

apply_hardening() {
    detect_platform
    if (( ! DRY_RUN )); then
        (( EUID == 0 )) || die "应用加固必须以 root 运行"
        acquire_global_lock
        assert_no_pending_transaction
    fi
    show_execution_plan
    preflight_access_check

    if (( ! DRY_RUN )); then
        if [[ "$ROOT_PASSWORD_ACTION" == custom ]]; then
            read_custom_root_password
        elif [[ "$ROOT_PASSWORD_ACTION" == generate ]]; then
            ROOT_PASSWORD_VALUE=$(generate_password "$GENERATED_PASSWORD_LENGTH") || die "密码生成失败"
        fi
    fi

    if (( DRY_RUN )); then
        ensure_dependencies
        if [[ "$PLATFORM_FAMILY" == debian ]]; then prepare_debian_pam; else prepare_rhel_pam; fi
        show_dry_run
        unset ROOT_PASSWORD_VALUE
        return 0
    fi

    create_transaction
    backup_all_targets
    CHANGE_STARTED=1
    arm_automatic_rollback
    ensure_dependencies
    if [[ "$PLATFORM_FAMILY" == debian ]]; then prepare_debian_pam; else prepare_rhel_pam; fi

    set +e
    apply_managed_accounts
    local result=$?
    if (( result == 0 )); then provision_managed_ssh_keys; result=$?; fi
    if (( result == 0 )); then apply_role_artifacts; result=$?; fi
    if (( result == 0 )); then apply_sysinfo_artifacts; result=$?; fi
    if (( result == 0 )); then apply_file_policies; result=$?; fi
    if (( result == 0 )); then
        if [[ "$PLATFORM_FAMILY" == debian ]]; then apply_debian_pam; else apply_rhel_pam; fi
        result=$?
    fi
    if (( result == 0 )); then apply_account_policies; result=$?; fi
    if (( result == 0 )); then write_credential_bundle; result=$?; fi
    if (( result == 0 && SYSTEM_CHANGE_REQUIRED == 1 )) && command_exists restorecon; then
        restorecon -RF /etc/ssh /etc/pam.d /etc/security /etc/login.defs /etc/sudoers.d /usr/local/sbin /usr/local/bin /etc/profile.d >/dev/null 2>&1
        result=$?
    fi
    if (( result == 0 && SYSTEM_CHANGE_REQUIRED == 1 )); then validate_sshd_config "$(root_path /etc/ssh/sshd_config)"; result=$?; fi
    if (( result == 0 && SYSTEM_CHANGE_REQUIRED == 1 )); then systemctl reload "$SSH_SERVICE"; result=$?; fi
    if (( result == 0 && SYSTEM_CHANGE_REQUIRED == 1 )); then reset_rollback_deadline_after_apply "$TRANSACTION_DIR"; result=$?; fi
    set -e

    if (( result != 0 )); then
        warn "加固失败，正在同步回滚事务 $TRANSACTION_ID"
        cleanup_exported_ssh_keys
        disarm_automatic_rollback "$TRANSACTION_DIR"
        restore_transaction_dir "$TRANSACTION_DIR" || die "加固失败且回滚失败，备份位于 $TRANSACTION_DIR"
        CHANGE_STARTED=0
        die "加固未应用，系统已回滚"
    fi

    if (( SYSTEM_CHANGE_REQUIRED == 0 )); then
        finish_no_change_transaction
        return 0
    fi

    set_transaction_status "$TRANSACTION_DIR" pending-confirmation
    CHANGE_STARTED=0
    info "已调度 ${ROLLBACK_TIMEOUT} 秒后自动回滚"
    info "请新建 SSH 会话并执行: sudo $0 --confirm $TRANSACTION_ID"
    show_managed_account_results
    show_root_ssh_result
    if [[ "$ROOT_PASSWORD_ACTION" == generate ]]; then
        printf '\n新 root 密码（仅显示一次）: %s\n\n' "$ROOT_PASSWORD_VALUE"
    fi
    unset ROOT_PASSWORD_VALUE
    reset_managed_account_state
    reset_managed_ssh_key_state
    show_apply_result
}

handle_exit() {
    local status="$1"
    trap - EXIT
    if (( status != 0 && CHANGE_STARTED == 1 )) && [[ -n "$TRANSACTION_DIR" && -d "$TRANSACTION_DIR" ]]; then
        warn "检测到异常退出，正在回滚事务 ${TRANSACTION_ID:-unknown}"
        set +e
        cleanup_exported_ssh_keys
        disarm_automatic_rollback "$TRANSACTION_DIR"
        restore_transaction_dir "$TRANSACTION_DIR"
        local rollback_status=$?
        set -e
        if (( rollback_status != 0 )); then
            warn "紧急回滚失败，请使用备份目录手工恢复: $TRANSACTION_DIR"
        fi
    fi
    exit "$status"
}

should_run_interactive_wizard() {
    (( ! NON_INTERACTIVE && POLICY_OPTIONS_SET == 0 ))
}
