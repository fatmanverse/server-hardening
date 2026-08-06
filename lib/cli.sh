#!/usr/bin/env bash

# Sourced by server_hardening.sh; do not execute directly.
# shellcheck disable=SC2034,SC2153

usage() {
    cat <<'EOF'
服务器账户与 SSH 加固工具

用法:
  server_hardening.sh                         # 交互式向导
  server_hardening.sh [选项]                # 应用加固
  server_hardening.sh --confirm TRANSACTION  # 新 SSH 会话确认
  server_hardening.sh --rollback TRANSACTION # 手动回滚

支持的发行版:
  Ubuntu 18.04 / 20.04 / 22.04 / 24.04
  Debian 10 / 11 / 12
  CentOS 7（脚本仍完整支持；但系统已停止上游安全更新）
  RHEL / Rocky Linux / AlmaLinux 8 / 9

  其他版本会明确拒绝，不以“更高版本应该兼容”作为隐式假设。

部署要求:
  必须完整复制 server_hardening.sh 和同目录 lib/ 模块目录。
  仅复制入口脚本时会明确报告缺失模块并停止，不执行任何加固操作。

强制安全基线:
  1. root SSH: 可选禁用、仅密钥、密码+密钥，默认禁用。
  2. 三员分立: 自动创建 opsadmin、auditadmin、secadmin，已存在账户不重置密码。
  3. 凭据: 新建账户生成 8 位强密码；选择密钥模式时每个账户生成独立 Ed25519 密钥。
     私钥以 0600 权限保存到脚本启动目录，使用 sudo 时归属原始运维用户。
     本次新生成的用户名、密码和公私钥同时汇总到 /opt/server-hardening/credentials.txt，
     目录权限 0700、文件权限 0600、属主 root:root；无新增凭据时不修改原文件。
  4. 首次改密: 新建账户使用 chage -d 0，首次登录必须修改密码。
  5. 密码周期: 本地普通用户统一为最长 30 天、最小 1 天、提前 7 天警告。

三员权限:
  opsadmin   完整 sudo 运维权限，使用本人密码提权。
  auditadmin 仅可读取系统、SSH/认证、auditd 日志和执行固定只读查询。
  secadmin   可编辑指定 SSH/PAM/密码策略文件、校验/重载 SSH、管理 ufw/firewalld；
             不授予任意 systemctl、通用 Shell、任意编辑器或无限制 sudo。

可配置选项:
  --root-login disabled|key-only|password-and-key
  --admin-login password-only|key-only|password-and-key
  --root-password-action keep|custom|generate
  --generated-password-length N              默认 8，范围 8-128
  --password-aging enable                     仅接受 enable
  --pass-max-days 30 --pass-min-days 1 --pass-warn-age 7
  --apply-aging-to-existing-users yes         仅接受 yes
  --password-quality enable|disable
  --min-password-length N
  --lockout enable|disable --deny N --unlock-time SECONDS
  --ssh-idle-timeout SECONDS
  --rollback-timeout SECONDS
  --conflict-action overwrite|skip|fail      非交互默认 fail
  --install-packages
  --non-interactive
  --dry-run
  --help

交互说明:
  所有枚举选项均显示中文释义，输入 1、2、3 等序号选择；直接回车使用标明的默认项。
  重复执行时会读取 SSH 最终生效值、账户属性、密码周期、组成员、PAM 和受管文件状态。
  当前值与目标值一致时直接跳过且不改写文件；不一致时显示当前值、目标值和影响，使用数字选择覆盖或保留。
  如果全部项目均已符合目标，脚本会撤销临时回滚任务，不重载 SSH，也不要求新会话确认。
  非交互模式用 --conflict-action overwrite|skip|fail 指定冲突处理；默认 fail，避免无人值守覆盖已有配置。
  决策记录在事务目录 decisions.tsv 中，密码、shadow 哈希、私钥和完整公钥不会写入日志。

示例:
  sudo ./server_hardening.sh

  sudo ./server_hardening.sh --non-interactive --dry-run \
    --root-login disabled --admin-login key-only --root-password-action keep \
    --password-aging enable --pass-max-days 30 --pass-min-days 1 \
    --pass-warn-age 7 --apply-aging-to-existing-users yes \
    --password-quality enable --min-password-length 8 \
    --lockout enable --deny 5 --unlock-time 900

  sudo ./server_hardening.sh --confirm 20260803T120000Z-a1b2c3d4

安全说明:
  自定义 root 密码只能从 TTY 隐藏输入，不接受命令行明文。
  secadmin 可修改认证边界，仍属高权限安全角色，但不具备通用 root 命令权限。
  SSH 变更默认在 5 分钟后自动回滚，必须从新 SSH 会话确认。
EOF
}

reset_options() {
    ROOT_LOGIN=''
    ADMIN_LOGIN=''
    ROOT_PASSWORD_ACTION=''
    GENERATED_PASSWORD_LENGTH=$DEFAULT_PASSWORD_LENGTH
    PASSWORD_AGING=enable
    PASS_MAX_DAYS=$DEFAULT_PASS_MAX_DAYS
    PASS_MIN_DAYS=$DEFAULT_PASS_MIN_DAYS
    PASS_WARN_AGE=$DEFAULT_PASS_WARN_AGE
    APPLY_AGING_EXISTING=yes
    PASSWORD_QUALITY=''
    MIN_CONFIGURED_PASSWORD_LENGTH=$MIN_PASSWORD_LENGTH
    LOCKOUT=''
    LOCKOUT_DENY=$DEFAULT_LOCKOUT_DENY
    UNLOCK_TIME=$DEFAULT_UNLOCK_TIME
    SSH_IDLE_TIMEOUT=$DEFAULT_SSH_IDLE_TIMEOUT
    ROLLBACK_TIMEOUT=$DEFAULT_ROLLBACK_TIMEOUT
    CONFLICT_ACTION=''
    CONFLICT_DECISION=''
    PARTIAL_HARDENING=0
    SYSTEM_CHANGE_REQUIRED=0
    DECISION_LOG_READY=0
    DECISION_RECORDS=()
    INSTALL_PACKAGES=0
    NON_INTERACTIVE=0
    DRY_RUN=0
    CONFIRM_TRANSACTION=''
    ROLLBACK_TRANSACTION=''
    ROOT_PASSWORD_VALUE=''
    PASS_MAX_DAYS_SET=0
    PASS_MIN_DAYS_SET=0
    PASS_WARN_AGE_SET=0
    APPLY_AGING_EXISTING_SET=0
    MIN_PASSWORD_LENGTH_SET=0
    LOCKOUT_DENY_SET=0
    UNLOCK_TIME_SET=0
    PLATFORM_FAMILY=''
    PLATFORM_ID=''
    PLATFORM_VERSION=''
    SSH_SERVICE=''
    PAM_LOCKOUT_MODULE=''
    PAM_LOCKOUT_WAS_MANAGED=0
    PAM_LOCKOUT_MARKER=''
    PAM_PWQUALITY_LINE_NEEDED=0
    PWQUALITY_WOULD_INSTALL=0
    LOCKOUT_DEPENDENCY_WOULD_INSTALL=0
    TRANSACTION_ID=''
    TRANSACTION_DIR=''
    CHANGE_STARTED=0
    POLICY_OPTIONS_SET=0
    KEY_EXPORT_DIR=$INVOCATION_DIR
    KEY_EXPORT_UID=$INVOKING_UID
    KEY_EXPORT_GID=$INVOKING_GID
    CREDENTIAL_SECTIONS=()
    reset_managed_account_state
    reset_managed_ssh_key_state
}

parse_args() {
    while (( $# > 0 )); do
        case "$1" in
            --root-login|--admin-login|--root-password-action|--generated-password-length|--password-aging|--pass-max-days|--pass-min-days|--pass-warn-age|--apply-aging-to-existing-users|--password-quality|--min-password-length|--lockout|--deny|--unlock-time|--ssh-idle-timeout|--rollback-timeout|--conflict-action|--confirm|--rollback)
                (( $# >= 2 )) || die "$1 缺少参数"
                ;;
        esac
        case "$1" in
            --root-login|--admin-login|--root-password-action|--generated-password-length|--password-aging|--pass-max-days|--pass-min-days|--pass-warn-age|--apply-aging-to-existing-users|--password-quality|--min-password-length|--lockout|--deny|--unlock-time|--ssh-idle-timeout|--rollback-timeout|--install-packages)
                POLICY_OPTIONS_SET=1
                ;;
        esac
        case "$1" in
            --root-login) ROOT_LOGIN=${2:-}; shift 2 ;;
            --admin-login) ADMIN_LOGIN=${2:-}; shift 2 ;;
            --root-password-action) ROOT_PASSWORD_ACTION=${2:-}; shift 2 ;;
            --generated-password-length) GENERATED_PASSWORD_LENGTH=${2:-}; shift 2 ;;
            --password-aging) PASSWORD_AGING=${2:-}; shift 2 ;;
            --pass-max-days) PASS_MAX_DAYS=${2:-}; PASS_MAX_DAYS_SET=1; shift 2 ;;
            --pass-min-days) PASS_MIN_DAYS=${2:-}; PASS_MIN_DAYS_SET=1; shift 2 ;;
            --pass-warn-age) PASS_WARN_AGE=${2:-}; PASS_WARN_AGE_SET=1; shift 2 ;;
            --apply-aging-to-existing-users) APPLY_AGING_EXISTING=${2:-}; APPLY_AGING_EXISTING_SET=1; shift 2 ;;
            --password-quality) PASSWORD_QUALITY=${2:-}; shift 2 ;;
            --min-password-length) MIN_CONFIGURED_PASSWORD_LENGTH=${2:-}; MIN_PASSWORD_LENGTH_SET=1; shift 2 ;;
            --lockout) LOCKOUT=${2:-}; shift 2 ;;
            --deny) LOCKOUT_DENY=${2:-}; LOCKOUT_DENY_SET=1; shift 2 ;;
            --unlock-time) UNLOCK_TIME=${2:-}; UNLOCK_TIME_SET=1; shift 2 ;;
            --ssh-idle-timeout) SSH_IDLE_TIMEOUT=${2:-}; shift 2 ;;
            --rollback-timeout) ROLLBACK_TIMEOUT=${2:-}; shift 2 ;;
            --conflict-action) CONFLICT_ACTION=${2:-}; shift 2 ;;
            --install-packages) INSTALL_PACKAGES=1; shift ;;
            --non-interactive) NON_INTERACTIVE=1; shift ;;
            --dry-run) DRY_RUN=1; shift ;;
            --confirm) CONFIRM_TRANSACTION=${2:-}; shift 2 ;;
            --rollback) ROLLBACK_TRANSACTION=${2:-}; shift 2 ;;
            --root-password|--password)
                die "不允许通过命令行传入明文密码"
                ;;
            -h|--help) usage; exit 0 ;;
            --version) printf '%s %s\n' "$PROGRAM_NAME" "$VERSION"; exit 0 ;;
            *) die "未知选项: $1" ;;
        esac
    done
}

enum_value() {
    local value="$1" label="$2"
    shift 2
    local allowed
    for allowed in "$@"; do
        [[ "$value" == "$allowed" ]] && return 0
    done
    die "$label 的值无效: $value"
}

validate_options() {
    if [[ -n "$CONFIRM_TRANSACTION" || -n "$ROLLBACK_TRANSACTION" ]]; then
        [[ -z "$CONFIRM_TRANSACTION" || -z "$ROLLBACK_TRANSACTION" ]] || die "--confirm 和 --rollback 不能同时使用"
        return 0
    fi

    if (( NON_INTERACTIVE )); then
        [[ -n "$ROOT_LOGIN" ]] || die "非交互模式缺少 --root-login"
        [[ -n "$ADMIN_LOGIN" ]] || die "非交互模式缺少 --admin-login"
        [[ -n "$ROOT_PASSWORD_ACTION" ]] || die "非交互模式缺少 --root-password-action"
        [[ -n "$PASSWORD_QUALITY" ]] || die "非交互模式缺少 --password-quality"
        [[ -n "$LOCKOUT" ]] || die "非交互模式缺少 --lockout"
        if [[ "$PASSWORD_AGING" == enable ]]; then
            (( PASS_MAX_DAYS_SET )) || die "密码过期启用时缺少 --pass-max-days"
            (( PASS_MIN_DAYS_SET )) || die "密码过期启用时缺少 --pass-min-days"
            (( PASS_WARN_AGE_SET )) || die "密码过期启用时缺少 --pass-warn-age"
        fi
        (( APPLY_AGING_EXISTING_SET )) || die "非交互模式缺少 --apply-aging-to-existing-users"
        if [[ "$PASSWORD_QUALITY" == enable ]]; then
            (( MIN_PASSWORD_LENGTH_SET )) || die "密码复杂度启用时缺少 --min-password-length"
        fi
        if [[ "$LOCKOUT" == enable ]]; then
            (( LOCKOUT_DENY_SET )) || die "失败锁定启用时缺少 --deny"
            (( UNLOCK_TIME_SET )) || die "失败锁定启用时缺少 --unlock-time"
        fi
        [[ "$ROOT_PASSWORD_ACTION" != custom ]] || die "非交互模式不支持 custom 密码，请使用 generate 或交互运行"
    fi

    enum_value "$ROOT_LOGIN" '--root-login' disabled key-only password-and-key
    enum_value "$ADMIN_LOGIN" '--admin-login' password-only key-only password-and-key
    enum_value "$ROOT_PASSWORD_ACTION" '--root-password-action' keep custom generate
    enum_value "$PASSWORD_AGING" '--password-aging' enable
    enum_value "$PASSWORD_QUALITY" '--password-quality' enable disable
    enum_value "$LOCKOUT" '--lockout' enable disable
    [[ -z "$CONFLICT_ACTION" ]] || enum_value "$CONFLICT_ACTION" '--conflict-action' overwrite skip fail
    if (( NON_INTERACTIVE )) && [[ -z "$CONFLICT_ACTION" ]]; then
        CONFLICT_ACTION=fail
    fi
    if [[ "$PASSWORD_AGING" == enable ]]; then
        enum_value "$APPLY_AGING_EXISTING" '--apply-aging-to-existing-users' yes
    fi
    if [[ "$ROOT_PASSWORD_ACTION" == generate ]]; then
        [[ -t 0 || -t 1 ]] || die "生成 root 密码需要 TTY 以便安全显示一次"
    fi
    require_range "$GENERATED_PASSWORD_LENGTH" 8 128 '--generated-password-length'
    require_range "$PASS_MAX_DAYS" 1 99999 '--pass-max-days'
    require_range "$PASS_MIN_DAYS" 0 99999 '--pass-min-days'
    require_range "$PASS_WARN_AGE" 0 99999 '--pass-warn-age'
    (( PASS_MIN_DAYS <= PASS_MAX_DAYS )) || die "--pass-min-days 不能大于 --pass-max-days"
    require_range "$MIN_CONFIGURED_PASSWORD_LENGTH" 8 128 '--min-password-length'
    require_range "$LOCKOUT_DENY" 1 100 '--deny'
    require_range "$UNLOCK_TIME" 1 86400 '--unlock-time'
    require_range "$SSH_IDLE_TIMEOUT" 60 86400 '--ssh-idle-timeout'
    require_range "$ROLLBACK_TIMEOUT" 60 3600 '--rollback-timeout'
    [[ "$PASS_MAX_DAYS" == 30 && "$PASS_MIN_DAYS" == 1 && "$PASS_WARN_AGE" == 7 ]] || \
        die "密码周期为强制基线: 最长 30 天、最小 1 天、提前 7 天警告"
}

ask_menu() {
    local prompt="$1" default="$2"
    shift 2
    (( $# >= 2 && $# % 2 == 0 )) || return 1
    local -a values=() labels=()
    local default_index=0 choice index
    while (( $# > 0 )); do
        values+=("$1")
        labels+=("$2")
        shift 2
    done
    printf '\n%s\n' "$prompt" >&2
    for ((index = 0; index < ${#values[@]}; index++)); do
        printf '  %d) %s\n' "$((index + 1))" "${labels[index]}" >&2
        [[ "${values[index]}" != "$default" ]] || default_index=$((index + 1))
    done
    (( default_index > 0 )) || return 1
    while :; do
        printf '请输入序号 [%d]: ' "$default_index" >&2
        IFS= read -r choice || return 1
        choice=${choice:-$default_index}
        if is_uint "$choice" && (( choice >= 1 && choice <= ${#values[@]} )); then
            printf '%s\n' "${values[choice - 1]}"
            return 0
        fi
        warn "无效选择，请输入 1-${#values[@]}"
    done
}

ask_number() {
    local prompt="$1" default="$2" min="$3" max="$4" value
    while :; do
        printf '%s [%s，范围 %s-%s]: ' "$prompt" "$default" "$min" "$max" >&2
        IFS= read -r value || return 1
        value=${value:-$default}
        if is_uint "$value" && (( value >= min && value <= max )); then
            printf '%s\n' "$value"
            return 0
        fi
        warn "请输入 $min-$max 的整数"
    done
}

interactive_wizard() {
    [[ -t 0 ]] || die "交互模式需要 TTY；批量运行请使用 --non-interactive"
    info "开始服务器账户与 SSH 加固向导（版本 ${VERSION}）"
    ROOT_LOGIN=$(ask_menu 'root SSH 登录方式' disabled \
        disabled '禁止 root SSH 直接登录（推荐）' \
        key-only '仅允许 root 使用独立密钥登录' \
        password-and-key '允许 root 使用密码或独立密钥登录')
    ADMIN_LOGIN=$(ask_menu '三员账户 SSH 登录方式' key-only \
        password-only '仅密码登录，不生成 SSH 私钥' \
        key-only '仅独立密钥登录（推荐）' \
        password-and-key '密码和独立密钥都可登录')
    ROOT_PASSWORD_ACTION=$(ask_menu 'root 密码处理' keep \
        keep '保持现有 root 密码（推荐）' \
        custom '在当前终端隐藏输入新 root 密码' \
        generate '自动生成 root 强密码，成功后仅显示一次')
    if [[ "$ROOT_PASSWORD_ACTION" == generate ]]; then
        GENERATED_PASSWORD_LENGTH=$(ask_number '生成密码长度' "$DEFAULT_PASSWORD_LENGTH" 8 128)
    fi
    PASSWORD_AGING=enable
    PASS_MAX_DAYS=30
    PASS_MIN_DAYS=1
    PASS_WARN_AGE=7
    APPLY_AGING_EXISTING=yes
    info "固定策略: 本地普通用户密码最长 30 天，并同步现有用户"
    PASSWORD_QUALITY=$(ask_menu '密码复杂度策略' enable \
        enable '启用（推荐：大写、小写、数字、符号均必须包含）' \
        disable '禁用（保留系统当前密码复杂度配置）')
    if [[ "$PASSWORD_QUALITY" == enable ]]; then
        MIN_CONFIGURED_PASSWORD_LENGTH=$(ask_number '最小密码长度' "$MIN_PASSWORD_LENGTH" 8 128)
    fi
    LOCKOUT=$(ask_menu '登录失败锁定策略' enable \
        enable '启用（推荐：连续失败后临时锁定账户）' \
        disable '禁用（不由本脚本配置 faillock/tally2）')
    if [[ "$LOCKOUT" == enable ]]; then
        LOCKOUT_DENY=$(ask_number '失败次数' "$DEFAULT_LOCKOUT_DENY" 1 100)
        UNLOCK_TIME=$(ask_number '锁定秒数' "$DEFAULT_UNLOCK_TIME" 1 86400)
    fi
    SSH_IDLE_TIMEOUT=$(ask_number 'SSH 无响应超时秒数' "$DEFAULT_SSH_IDLE_TIMEOUT" 60 86400)
    ROLLBACK_TIMEOUT=$(ask_number '自动回滚等待秒数' "$DEFAULT_ROLLBACK_TIMEOUT" 60 3600)
}

read_custom_root_password() {
    local first second
    [[ -t 0 ]] || die "自定义 root 密码需要 TTY"
    read -r -s -p '输入新 root 密码: ' first; printf '\n' >&2
    read -r -s -p '再次输入: ' second; printf '\n' >&2
    [[ "$first" == "$second" ]] || die "两次输入的密码不一致"
    (( ${#first} >= MIN_CONFIGURED_PASSWORD_LENGTH )) || die "密码长度小于 $MIN_CONFIGURED_PASSWORD_LENGTH"
    ROOT_PASSWORD_VALUE=$first
    unset first second
}
