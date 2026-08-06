#!/usr/bin/env bash

# Sourced by server_hardening.sh; do not execute directly.
# shellcheck disable=SC2034,SC2153

sysinfo_collector_content() {
    cat <<'SYSINFO_COLLECTOR_EOF'
#!/bin/bash

set +e

PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
export PATH
LC_ALL=C
export LC_ALL

UNKNOWN='unknown'

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

run_probe() {
    if command_exists timeout; then
        timeout 5 "$@"
    else
        "$@"
    fi
}

single_line() {
    tr '\r\n\t' '   ' |
        LC_ALL=C tr -d '\000-\010\013\014\016-\037\177'
}

first_line_or_unknown() {
    local value
    value="$(single_line | awk 'NF { print; exit }')"
    if [ -n "$value" ]; then
        printf '%s' "$value"
    else
        printf '%s' "$UNKNOWN"
    fi
}

read_os_name() {
    if [ ! -r /etc/os-release ]; then
        printf '%s' "$UNKNOWN"
        return
    fi

    awk -F= '
        $1 == "PRETTY_NAME" {
            value = substr($0, index($0, "=") + 1)
            if (value ~ /^".*"$/) {
                value = substr(value, 2, length(value) - 2)
            }
            print value
            exit
        }
    ' /etc/os-release | first_line_or_unknown
}

read_hostname() {
    run_probe hostname 2>/dev/null | first_line_or_unknown
}

read_ip_address() {
    local value

    value="$(
        run_probe hostname -I 2>/dev/null |
            awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+\./) { print $i; exit } }'
    )"

    if [ -z "$value" ]; then
        value="$(
            run_probe hostname -i 2>/dev/null |
                awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+\./ && $i !~ /^127\./) { print $i; exit } }'
        )"
    fi

    if [ -z "$value" ] && command_exists ip; then
        value="$(
            run_probe ip -4 route get 1.1.1.1 2>/dev/null |
                awk '
                    {
                        for (i = 1; i < NF; i++) {
                            if ($i == "src") {
                                print $(i + 1)
                                exit
                            }
                        }
                    }
                '
        )"
    fi

    printf '%s\n' "$value" | first_line_or_unknown
}

read_cpu_model() {
    local value

    if command_exists lscpu; then
        value="$(
            run_probe lscpu 2>/dev/null |
                awk -F: '
                    /^[[:space:]]*Model name[[:space:]]*:/ {
                        sub(/^[[:space:]]+/, "", $2)
                        print $2
                        exit
                    }
                '
        )"
    fi

    if [ -z "$value" ] && [ -r /proc/cpuinfo ]; then
        value="$(
            awk -F: '
                /^[[:space:]]*model name[[:space:]]*:/ ||
                /^[[:space:]]*Model[[:space:]]*:/ {
                    sub(/^[[:space:]]+/, "", $2)
                    print $2
                    exit
                }
            ' /proc/cpuinfo
        )"
    fi

    printf '%s\n' "$value" | first_line_or_unknown
}

read_uptime() {
    local value

    if command_exists uptime; then
        value="$(run_probe uptime -p 2>/dev/null)"
    fi

    if [ -z "$value" ] && [ -r /proc/uptime ]; then
        value="$(
            awk '
                {
                    seconds = int($1)
                    days = int(seconds / 86400)
                    hours = int((seconds % 86400) / 3600)
                    minutes = int((seconds % 3600) / 60)

                    output = ""
                    if (days > 0)
                        output = output days "d "
                    if (hours > 0 || days > 0)
                        output = output hours "h "
                    output = output minutes "m"
                    print output
                }
            ' /proc/uptime
        )"
    fi

    printf '%s\n' "$value" | first_line_or_unknown
}

read_memory() {
    if [ ! -r /proc/meminfo ]; then
        printf '%s' "$UNKNOWN"
        return
    fi

    awk '
        function human(kib, value, unit) {
            value = kib
            unit = "KiB"
            if (value >= 1024) {
                value /= 1024
                unit = "MiB"
            }
            if (value >= 1024) {
                value /= 1024
                unit = "GiB"
            }
            return sprintf("%.1f%s", value, unit)
        }

        $1 == "MemTotal:"     { total = $2 }
        $1 == "MemAvailable:" { available = $2 }
        $1 == "MemFree:"      { free = $2 }
        $1 == "Buffers:"      { buffers = $2 }
        $1 == "Cached:"       { cached = $2 }
        $1 == "SReclaimable:" { reclaimable = $2 }

        END {
            if (!total) {
                print "unknown"
                exit
            }

            if (!available)
                available = free + buffers + cached + reclaimable

            used = total - available
            if (used < 0)
                used = 0

            printf "%s / %s used, %s available",
                human(used), human(total), human(available)
        }
    ' /proc/meminfo | first_line_or_unknown
}

read_swap() {
    if [ ! -r /proc/meminfo ]; then
        printf '%s' "$UNKNOWN"
        return
    fi

    awk '
        function human(kib, value, unit) {
            value = kib
            unit = "KiB"
            if (value >= 1024) {
                value /= 1024
                unit = "MiB"
            }
            if (value >= 1024) {
                value /= 1024
                unit = "GiB"
            }
            return sprintf("%.1f%s", value, unit)
        }

        $1 == "SwapTotal:" { total = $2 }
        $1 == "SwapFree:"  { free = $2 }

        END {
            if (total == "") {
                print "unknown"
                exit
            }

            used = total - free
            if (used < 0)
                used = 0

            printf "%s / %s used", human(used), human(total)
        }
    ' /proc/meminfo | first_line_or_unknown
}

read_load_average() {
    if [ ! -r /proc/loadavg ]; then
        printf '%s' "$UNKNOWN"
        return
    fi

    awk '{
        printf "1m=%s 5m=%s 15m=%s", $1, $2, $3
    }' /proc/loadavg | first_line_or_unknown
}

read_logged_in_users() {
    if ! command_exists who; then
        printf '%s' "$UNKNOWN"
        return
    fi

    run_probe who 2>/dev/null |
        awk 'END { print NR + 0 }' |
        first_line_or_unknown
}

show_summary() {
    printf '\n'
    printf 'Server information\n'
    printf '%s\n' '------------------'
    printf 'Date:          %s\n' "$(run_probe date '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null | first_line_or_unknown)"
    printf 'OS:            %s\n' "$(read_os_name)"
    printf 'Kernel:        %s\n' "$(run_probe uname -r 2>/dev/null | first_line_or_unknown)"
    printf 'Uptime:        %s\n' "$(read_uptime)"
    printf 'Hostname:      %s\n' "$(read_hostname)"
    printf 'IPv4:          %s\n' "$(read_ip_address)"
    printf 'CPU:           %s\n' "$(read_cpu_model)"
    printf 'Memory:        %s\n' "$(read_memory)"
    printf 'Swap:          %s\n' "$(read_swap)"
    printf 'Load average:  %s\n' "$(read_load_average)"
    printf 'Login users:   %s\n' "$(read_logged_in_users)"
}

case "${1---login}" in
    --login)
        show_summary
        printf '\n'
        ;;
    *)
        printf 'Usage: %s [--login]\n' "$0" >&2
        exit 2
        ;;
esac

exit 0
SYSINFO_COLLECTOR_EOF
}

sysinfo_profile_content() {
    cat <<'SYSINFO_PROFILE_EOF'
case $- in
    *i*)
        if [ -t 1 ] &&
           [ "${SERVER_HARDENING_SYSINFO_DISABLE-0}" != "1" ] &&
           [ -x /usr/local/bin/server-hardening-sysinfo ]; then
            /usr/local/bin/server-hardening-sysinfo --login 2>/dev/null || :
        fi
        ;;
esac
SYSINFO_PROFILE_EOF
}

install_validated_artifact() {
    local path="$1" mode="$2" content="$3" checker="$4" tmp
    [[ -x "$checker" ]] || die "受管产物校验器不可执行: $checker"
    tmp=$(mktemp "${TMPDIR:-/tmp}/server-hardening-validate.XXXXXX") || die "无法创建受管产物校验临时文件"
    chmod 0600 "$tmp" || { rm -f "$tmp"; die "无法设置校验临时文件权限"; }
    printf '%s\n' "$content" > "$tmp" || { rm -f "$tmp"; die "无法写入受管产物校验临时文件"; }
    if ! "$checker" -n "$tmp"; then
        rm -f "$tmp"
        die "生成的受管产物语法校验失败: $path"
    fi
    rm -f "$tmp"
    write_managed_artifact "$path" "$mode" "$content"
}

apply_sysinfo_artifacts() {
    local collector_content profile_content collector profile
    collector_content=$(sysinfo_collector_content)
    profile_content=$(sysinfo_profile_content)
    collector=$(root_path "$SYSINFO_COLLECTOR_PATH")
    profile=$(root_path "$SYSINFO_PROFILE_PATH")
    install_validated_artifact "$collector" "$SYSINFO_COLLECTOR_MODE" "$collector_content" /bin/bash
    install_validated_artifact "$profile" "$SYSINFO_PROFILE_MODE" "$profile_content" /bin/sh
}