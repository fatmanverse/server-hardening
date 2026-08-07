#!/usr/bin/env bash

# Sourced by server_hardening.sh; do not execute directly.
# shellcheck disable=SC2034,SC2153

readonly PROGRAM_NAME=${0##*/}
readonly VERSION='2.0.0'
readonly SSH_BLOCK_BEGIN='# BEGIN SERVER-HARDENING SSH'
readonly SSH_BLOCK_END='# END SERVER-HARDENING SSH'
readonly LOGIN_DEFS_BLOCK_BEGIN='# BEGIN SERVER-HARDENING PASSWORD AGING'
readonly LOGIN_DEFS_BLOCK_END='# END SERVER-HARDENING PASSWORD AGING'
readonly PWQUALITY_BLOCK_BEGIN='# BEGIN SERVER-HARDENING PWQUALITY'
readonly PWQUALITY_BLOCK_END='# END SERVER-HARDENING PWQUALITY'
readonly FAILLOCK_BLOCK_BEGIN='# BEGIN SERVER-HARDENING FAILLOCK'
readonly FAILLOCK_BLOCK_END='# END SERVER-HARDENING FAILLOCK'
readonly PAM_AUTH_BLOCK_BEGIN='# BEGIN SERVER-HARDENING AUTH LOCKOUT'
readonly PAM_AUTH_BLOCK_END='# END SERVER-HARDENING AUTH LOCKOUT'
readonly PAM_AUTHFAIL_BLOCK_BEGIN='# BEGIN SERVER-HARDENING AUTH FAILURE RECORDING'
readonly PAM_AUTHFAIL_BLOCK_END='# END SERVER-HARDENING AUTH FAILURE RECORDING'
readonly PAM_ACCOUNT_BLOCK_BEGIN='# BEGIN SERVER-HARDENING ACCOUNT LOCKOUT'
readonly PAM_ACCOUNT_BLOCK_END='# END SERVER-HARDENING ACCOUNT LOCKOUT'
readonly PAM_PASSWORD_BLOCK_BEGIN='# BEGIN SERVER-HARDENING PASSWORD QUALITY'
readonly PAM_PASSWORD_BLOCK_END='# END SERVER-HARDENING PASSWORD QUALITY'
readonly DEFAULT_PASSWORD_LENGTH=8
readonly MIN_PASSWORD_LENGTH=8
readonly MAX_PASSWORD_LENGTH=128
readonly DEFAULT_PASS_MAX_DAYS=30
readonly DEFAULT_PASS_MIN_DAYS=1
readonly DEFAULT_PASS_WARN_AGE=7
readonly DEFAULT_LOCKOUT_DENY=5
readonly DEFAULT_UNLOCK_TIME=900
readonly DEFAULT_SSH_IDLE_TIMEOUT=600
readonly DEFAULT_ROLLBACK_TIMEOUT=300
readonly PREPARATION_WATCHDOG_TIMEOUT=1800
readonly DEFAULT_BACKUP_ROOT='/var/backups/server-hardening'
readonly GLOBAL_LOCK_FILE='/run/server-hardening/operation.lock'
readonly ROLE_SUDOERS_PATH='/etc/sudoers.d/server-hardening-roles'
readonly AUDIT_HELPER_PATH='/usr/local/sbin/server-hardening-audit-read'
readonly SYSINFO_COLLECTOR_PATH='/usr/local/bin/server-hardening-sysinfo'
readonly SYSINFO_PROFILE_PATH='/etc/profile.d/99-server-hardening-sysinfo.sh'
readonly SYSINFO_COLLECTOR_MODE='0755'
readonly SYSINFO_PROFILE_MODE='0644'
readonly CREDENTIAL_BUNDLE_PATH='/opt/server-hardening/credentials.txt'
readonly MANAGED_ACCOUNT_PASSWORD_LENGTH=8
# Upper bounds of the known-compatible window. Releases beyond these are
# rejected until their PAM layout has been checked, because a newer major can
# change PAM ownership without renaming any file.
readonly MAX_KNOWN_UBUNTU_MAJOR=26
readonly MAX_KNOWN_FEDORA_MAJOR=44

INVOCATION_DIR=$(pwd -P)
INVOKING_UID=${SUDO_UID:-$(id -u)}
INVOKING_GID=${SUDO_GID:-$(id -g)}

SYSTEM_ROOT=${SYSTEM_ROOT:-/}
BACKUP_ROOT=${BACKUP_ROOT:-$DEFAULT_BACKUP_ROOT}
OS_RELEASE_FILE=${OS_RELEASE_FILE:-}
info() { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

root_path() {
    local path="$1"
    if [[ "$SYSTEM_ROOT" == / ]]; then
        printf '%s\n' "$path"
    else
        printf '%s%s\n' "${SYSTEM_ROOT%/}" "$path"
    fi
}

is_uint() { [[ ${1:-} =~ ^[0-9]+$ ]]; }

require_range() {
    local value="$1" min="$2" max="$3" label="$4"
    is_uint "$value" || die "$label 必须是整数"
    (( value >= min && value <= max )) || die "$label 必须在 $min-$max 之间"
}

chown_for_system_root() {
    local owner="$1" path="$2"
    chown "$owner" "$path" 2>/dev/null || [[ "$SYSTEM_ROOT" != / ]]
}

command_exists() { command -v "$1" >/dev/null 2>&1; }
