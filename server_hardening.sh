#!/usr/bin/env bash

if [ -z "${BASH_VERSION:-}" ]; then
    printf '[ERROR] 本脚本需要 Bash，不能使用 sh 执行。\n' >&2
    printf '[ERROR] 请使用: sudo bash %s  或  sudo ./%s\n' "${0##*/}" "${0##*/}" >&2
    exit 2
fi

case ":${SHELLOPTS:-}:" in
    *:posix:*)
        printf '[ERROR] 本脚本需要 Bash，不能使用 sh 或 Bash POSIX 模式执行。\n' >&2
        printf '[ERROR] 请使用: sudo bash %s  或  sudo ./%s\n' "${0##*/}" "${0##*/}" >&2
        exit 2
        ;;
esac

set +x
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
MODULE_DIR="$SCRIPT_DIR/lib"
MODULE_NAMES=(
    core.sh
    cli.sh
    state.sh
    accounts.sh
    artifacts.sh
    sysinfo.sh
    ssh.sh
    pam.sh
    transaction.sh
    hardening.sh
)

for module_name in "${MODULE_NAMES[@]}"; do
    module_path="$MODULE_DIR/$module_name"
    if [[ ! -f "$module_path" || ! -r "$module_path" ]]; then
        printf '[ERROR] 服务器加固模块不存在或不可读: %s\n' "$module_path" >&2
        if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
            exit 1
        fi
        return 1
    fi
    # shellcheck source=/dev/null
    source "$module_path"
done
unset module_name module_path

main() {
    reset_options
    trap 'handle_exit $?' EXIT
    parse_args "$@"
    if [[ -n "$CONFIRM_TRANSACTION" ]]; then
        (( EUID == 0 )) || die "确认事务必须以 root 运行"
        acquire_global_lock
        confirm_transaction
        return 0
    fi
    if [[ -n "$ROLLBACK_TRANSACTION" ]]; then
        (( EUID == 0 )) || die "回滚事务必须以 root 运行"
        acquire_global_lock
        manual_rollback
        return 0
    fi
    if should_run_interactive_wizard; then
        interactive_wizard
    fi
    validate_options
    apply_hardening
}

reset_options
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
