#!/usr/bin/env bash
# ==============================================================================
# deploy-mde-cron.sh — Microsoft Defender for Endpoint (MDE) Cron Scheduler
# ==============================================================================
# Deploys cron-based scheduled scans AND automatic definition updates
# for MDE on Linux endpoints.
#
# Version: 1.2
# Changelog:
#   v1.2 — Default scan schedule changed to Tuesday & Saturday at 00:00.
#           Added MDE definition auto-update cron job (every 15 days + pkg check).
#           New flags: --update-schedule, --no-update.
#   v1.0 — Initial release.
#
# Copyright (c) 2026 SOS Group Limited — Cyber Security Unit
# Licensed under the MIT License. See LICENSE for details.
# ==============================================================================

set -euo pipefail
IFS=$'\n\t'

# ── Defaults ──────────────────────────────────────────────────────────────────
SCAN_TYPE="quick"
SCAN_SCHEDULE="0 0 * * 2,6"              # Every Tuesday & Saturday at midnight
LOG_DIR="/var/log/mde-scheduler"
LOG_FILE="${LOG_DIR}/mde-scan.log"
UPDATE_LOG_FILE="${LOG_DIR}/mde-update.log"
CRON_JOB_FILE="/etc/cron.d/mde-scheduled-scan"
CRON_UPDATE_FILE="/etc/cron.d/mde-definition-update"
MDATP_BIN="/usr/bin/mdatp"
MAX_LOG_SIZE_MB=50
RETENTION_DAYS=90
DRY_RUN=false
UNINSTALL=false
VERBOSE=false
INSTALL_UPDATE=true
UPDATE_SCHEDULE="30 0 1,16 * *"           # 1st and 16th of every month at 00:30 (≈15 days)

# ── Colors & formatting ──────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Helper functions ─────────────────────────────────────────────────────────
usage() {
    cat <<EOF
${BOLD}Usage:${NC} $(basename "$0") [OPTIONS]

Deploy cron-based scheduled scans and automatic definition updates
for Microsoft Defender for Endpoint on Linux.

${BOLD}Scan Options:${NC}
  -t, --type TYPE            Scan type: quick | full (default: quick)
  -s, --schedule CRON        Cron expression for scans
                             (default: "0 0 * * 2,6" — Tue & Sat at midnight)

${BOLD}Update Options:${NC}
  --update-schedule CRON     Cron expression for definition updates
                             (default: "30 0 1,16 * *" — every ~15 days)
  --no-update                Skip installing the definition update cron job

${BOLD}General Options:${NC}
  -l, --log-dir DIR          Log directory (default: /var/log/mde-scheduler)
  -r, --retention DAYS       Log retention in days (default: 90)
  -n, --dry-run              Show what would be done without making changes
  -u, --uninstall            Remove all cron jobs and clean up
  -v, --verbose              Enable verbose output
  -h, --help                 Show this help message

${BOLD}Examples:${NC}
  sudo ./deploy-mde-cron.sh                          # Scans Tue/Sat 00:00 + updates every 15 days
  sudo ./deploy-mde-cron.sh -t full                  # Full scans Tue/Sat at midnight
  sudo ./deploy-mde-cron.sh --no-update              # Scans only, no auto-update
  sudo ./deploy-mde-cron.sh -s "0 3 * * 0"           # Quick scan every Sunday at 03:00
  sudo ./deploy-mde-cron.sh -u                        # Remove all scheduled tasks

${BOLD}Supported Distributions:${NC}
  RHEL/CentOS 7+, Ubuntu 18.04+, Debian 10+, SLES 12+, Oracle Linux 7+,
  Amazon Linux 2/2023, Fedora 33+, Rocky Linux 8+, AlmaLinux 8+

EOF
    exit 0
}

log_info()    { echo -e "${GREEN}[INFO]${NC}  $(date '+%Y-%m-%d %H:%M:%S') — $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $(date '+%Y-%m-%d %H:%M:%S') — $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') — $*" >&2; }
log_step()    { echo -e "${CYAN}[STEP]${NC}  $(date '+%Y-%m-%d %H:%M:%S') — $*"; }
log_verbose() { [[ "$VERBOSE" == true ]] && echo -e "        $(date '+%Y-%m-%d %H:%M:%S') — $*"; return 0; }

die() { log_error "$*"; exit 1; }

# ── Pre-flight checks ───────────────────────────────────────────────────────
preflight_checks() {
    log_step "Running pre-flight checks..."

    # Root check
    if [[ $EUID -ne 0 ]]; then
        die "This script must be run as root (use sudo)."
    fi

    # Verify mdatp is installed
    if ! command -v mdatp &>/dev/null && [[ ! -x "$MDATP_BIN" ]]; then
        die "mdatp binary not found. Install Microsoft Defender for Endpoint first."
    fi
    log_verbose "mdatp binary found at $(command -v mdatp 2>/dev/null || echo "$MDATP_BIN")"

    # Verify mdatp health
    if ! mdatp health --field healthy 2>/dev/null | grep -qi "true"; then
        log_warn "mdatp health check reports unhealthy status. Proceeding anyway."
    else
        log_info "mdatp health check passed."
    fi

    # Verify cron daemon
    local cron_services=("cron" "crond" "cronie")
    local cron_found=false
    for svc in "${cron_services[@]}"; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            cron_found=true
            log_verbose "Cron service '$svc' is active."
            break
        fi
    done

    if [[ "$cron_found" == false ]]; then
        log_warn "No active cron service detected. Ensure cron is running for scheduled tasks."
    fi

    # Validate scan type
    if [[ "$SCAN_TYPE" != "quick" && "$SCAN_TYPE" != "full" ]]; then
        die "Invalid scan type: '$SCAN_TYPE'. Use 'quick' or 'full'."
    fi

    # Validate cron expressions (basic check: 5 fields)
    local field_count
    field_count=$(echo "$SCAN_SCHEDULE" | awk '{print NF}')
    if [[ "$field_count" -ne 5 ]]; then
        die "Invalid scan cron expression: '$SCAN_SCHEDULE'. Must have exactly 5 fields."
    fi

    if [[ "$INSTALL_UPDATE" == true ]]; then
        field_count=$(echo "$UPDATE_SCHEDULE" | awk '{print NF}')
        if [[ "$field_count" -ne 5 ]]; then
            die "Invalid update cron expression: '$UPDATE_SCHEDULE'. Must have exactly 5 fields."
        fi
    fi

    log_info "Pre-flight checks completed successfully."
}

# ── Create log directory ─────────────────────────────────────────────────────
setup_logging() {
    log_step "Configuring logging..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would create log directory: $LOG_DIR"
        return
    fi

    mkdir -p "$LOG_DIR"
    chmod 750 "$LOG_DIR"
    log_info "Log directory ready: $LOG_DIR"
}

# ── Build the scan wrapper script ────────────────────────────────────────────
create_scan_script() {
    local scan_script="${LOG_DIR}/run-mde-scan.sh"
    log_step "Creating scan wrapper script..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would create scan script: $scan_script"
        return
    fi

    cat > "$scan_script" <<'WRAPPER'
#!/usr/bin/env bash
# MDE Scheduled Scan Wrapper — Auto-generated by deploy-mde-cron.sh
set -euo pipefail

SCAN_TYPE="${1:-quick}"
LOG_FILE="${2:-/var/log/mde-scheduler/mde-scan.log}"
MAX_LOG_SIZE_MB="${3:-50}"
RETENTION_DAYS="${4:-90}"

# Rotate logs if over size limit
if [[ -f "$LOG_FILE" ]]; then
    current_size_mb=$(du -m "$LOG_FILE" 2>/dev/null | awk '{print $1}')
    if [[ "$current_size_mb" -ge "$MAX_LOG_SIZE_MB" ]]; then
        mv "$LOG_FILE" "${LOG_FILE}.$(date '+%Y%m%d%H%M%S').bak"
    fi
fi

# Purge old log backups
find "$(dirname "$LOG_FILE")" -name "*.bak" -mtime +"$RETENTION_DAYS" -delete 2>/dev/null || true

# Run scan
{
    echo "========================================"
    echo "MDE Scan — $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Type: ${SCAN_TYPE}"
    echo "Host: $(hostname)"
    echo "========================================"

    start_time=$(date +%s)

    if mdatp scan "$SCAN_TYPE" 2>&1; then
        echo "[RESULT] Scan completed successfully."
    else
        echo "[RESULT] Scan exited with non-zero status ($?)."
    fi

    end_time=$(date +%s)
    elapsed=$((end_time - start_time))
    echo "[TIMING] Duration: ${elapsed}s"
    echo ""
} >> "$LOG_FILE" 2>&1
WRAPPER

    chmod 700 "$scan_script"
    log_info "Scan wrapper script created: $scan_script"
}

# ── Build the update wrapper script ──────────────────────────────────────────
create_update_script() {
    local update_script="${LOG_DIR}/run-mde-update.sh"
    log_step "Creating MDE definition update script..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would create update script: $update_script"
        return
    fi

    cat > "$update_script" <<'WRAPPER'
#!/usr/bin/env bash
# MDE Definition Update Wrapper — Auto-generated by deploy-mde-cron.sh
set -euo pipefail

LOG_FILE="${1:-/var/log/mde-scheduler/mde-update.log}"
MAX_LOG_SIZE_MB="${2:-50}"
RETENTION_DAYS="${3:-90}"

# Rotate logs if over size limit
if [[ -f "$LOG_FILE" ]]; then
    current_size_mb=$(du -m "$LOG_FILE" 2>/dev/null | awk '{print $1}')
    if [[ "$current_size_mb" -ge "$MAX_LOG_SIZE_MB" ]]; then
        mv "$LOG_FILE" "${LOG_FILE}.$(date '+%Y%m%d%H%M%S').bak"
    fi
fi

# Purge old log backups
find "$(dirname "$LOG_FILE")" -name "*.bak" -mtime +"$RETENTION_DAYS" -delete 2>/dev/null || true

# Get current definition state before update
{
    echo "========================================"
    echo "MDE Definition Update — $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Host: $(hostname)"
    echo "========================================"

    # Show current definition info
    current_version=$(mdatp health --field definitions_version 2>/dev/null || echo "unknown")
    last_updated=$(mdatp health --field definitions_updated_time 2>/dev/null || echo "unknown")
    echo "[BEFORE] Definition version : ${current_version}"
    echo "[BEFORE] Last updated       : ${last_updated}"

    start_time=$(date +%s)

    # Update security intelligence / definitions
    echo "[ACTION] Running: mdatp definitions update"
    if mdatp definitions update 2>&1; then
        echo "[RESULT] Definition update completed successfully."
    else
        exit_code=$?
        echo "[RESULT] Definition update exited with status ${exit_code}."
        if [[ $exit_code -eq 2 ]]; then
            echo "[NOTE]   Exit code 2 typically means definitions are already current."
        fi
    fi

    # Attempt engine/platform update via package manager
    echo "[ACTION] Checking for MDE package updates..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq 2>&1 || true
        if apt-get install --only-upgrade -y -qq mdatp 2>&1; then
            echo "[RESULT] Package update check completed (apt)."
        else
            echo "[RESULT] No package updates available or update failed (apt)."
        fi
    elif command -v dnf &>/dev/null; then
        if dnf update -y -q mdatp 2>&1; then
            echo "[RESULT] Package update check completed (dnf)."
        else
            echo "[RESULT] No package updates available or update failed (dnf)."
        fi
    elif command -v yum &>/dev/null; then
        if yum update -y -q mdatp 2>&1; then
            echo "[RESULT] Package update check completed (yum)."
        else
            echo "[RESULT] No package updates available or update failed (yum)."
        fi
    elif command -v zypper &>/dev/null; then
        if zypper update -y mdatp 2>&1; then
            echo "[RESULT] Package update check completed (zypper)."
        else
            echo "[RESULT] No package updates available or update failed (zypper)."
        fi
    else
        echo "[WARN]   No supported package manager found. Skipping engine update."
    fi

    # Show updated definition info
    new_version=$(mdatp health --field definitions_version 2>/dev/null || echo "unknown")
    new_updated=$(mdatp health --field definitions_updated_time 2>/dev/null || echo "unknown")
    echo "[AFTER]  Definition version : ${new_version}"
    echo "[AFTER]  Last updated       : ${new_updated}"

    if [[ "$current_version" != "$new_version" ]]; then
        echo "[CHANGE] Definitions updated: ${current_version} → ${new_version}"
    else
        echo "[CHANGE] No definition version change detected."
    fi

    end_time=$(date +%s)
    elapsed=$((end_time - start_time))
    echo "[TIMING] Duration: ${elapsed}s"
    echo ""
} >> "$LOG_FILE" 2>&1
WRAPPER

    chmod 700 "$update_script"
    log_info "Update wrapper script created: $update_script"
}

# ── Install scan cron job ────────────────────────────────────────────────────
install_scan_cron_job() {
    log_step "Installing scan cron job..."

    local scan_script="${LOG_DIR}/run-mde-scan.sh"
    local cron_line="${SCAN_SCHEDULE} root ${scan_script} ${SCAN_TYPE} ${LOG_FILE} ${MAX_LOG_SIZE_MB} ${RETENTION_DAYS}"

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would write to ${CRON_JOB_FILE}:"
        echo "  $cron_line"
        return
    fi

    cat > "$CRON_JOB_FILE" <<EOF
# MDE Scheduled Scan — Managed by deploy-mde-cron.sh v1.2
# Installed: $(date '+%Y-%m-%d %H:%M:%S')
# Scan type: ${SCAN_TYPE}
# Schedule: Tuesday & Saturday at midnight
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

${cron_line}
EOF

    chmod 644 "$CRON_JOB_FILE"
    log_info "Scan cron job installed: $CRON_JOB_FILE"
    log_info "Schedule: ${SCAN_SCHEDULE} | Type: ${SCAN_TYPE}"
}

# ── Install update cron job ──────────────────────────────────────────────────
install_update_cron_job() {
    log_step "Installing definition update cron job..."

    local update_script="${LOG_DIR}/run-mde-update.sh"
    local cron_line="${UPDATE_SCHEDULE} root ${update_script} ${UPDATE_LOG_FILE} ${MAX_LOG_SIZE_MB} ${RETENTION_DAYS}"

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would write to ${CRON_UPDATE_FILE}:"
        echo "  $cron_line"
        return
    fi

    cat > "$CRON_UPDATE_FILE" <<EOF
# MDE Definition Update — Managed by deploy-mde-cron.sh v1.2
# Installed: $(date '+%Y-%m-%d %H:%M:%S')
# Schedule: Every ~15 days (1st and 16th of each month)
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

${cron_line}
EOF

    chmod 644 "$CRON_UPDATE_FILE"
    log_info "Update cron job installed: $CRON_UPDATE_FILE"
    log_info "Update schedule: ${UPDATE_SCHEDULE}"
}

# ── Uninstall ────────────────────────────────────────────────────────────────
uninstall() {
    log_step "Uninstalling all MDE scheduled tasks (cron)..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would remove: $CRON_JOB_FILE"
        log_info "[DRY RUN] Would remove: $CRON_UPDATE_FILE"
        log_info "[DRY RUN] Would remove scripts from: $LOG_DIR"
        return
    fi

    for f in "$CRON_JOB_FILE" "$CRON_UPDATE_FILE"; do
        if [[ -f "$f" ]]; then
            rm -f "$f"
            log_info "Removed: $f"
        else
            log_warn "Not found: $f"
        fi
    done

    for script in "run-mde-scan.sh" "run-mde-update.sh"; do
        local path="${LOG_DIR}/${script}"
        if [[ -f "$path" ]]; then
            rm -f "$path"
            log_info "Removed: $path"
        fi
    done

    log_info "Uninstall complete. Log files retained in $LOG_DIR."
    exit 0
}

# ── Verification ─────────────────────────────────────────────────────────────
verify_installation() {
    log_step "Verifying installation..."

    local ok=true

    # Scan components
    echo ""
    echo -e "${BOLD}── Scan Cron Job ───────────────────────────────────────────${NC}"

    if [[ ! -f "$CRON_JOB_FILE" ]]; then
        log_error "Scan cron job file missing: $CRON_JOB_FILE"
        ok=false
    else
        log_info "Scan cron job file exists: $CRON_JOB_FILE"
    fi

    local scan_script="${LOG_DIR}/run-mde-scan.sh"
    if [[ ! -x "$scan_script" ]]; then
        log_error "Scan wrapper script missing or not executable: $scan_script"
        ok=false
    else
        log_info "Scan wrapper script ready."
    fi

    # Update components
    if [[ "$INSTALL_UPDATE" == true ]]; then
        echo ""
        echo -e "${BOLD}── Update Cron Job ─────────────────────────────────────────${NC}"

        if [[ ! -f "$CRON_UPDATE_FILE" ]]; then
            log_error "Update cron job file missing: $CRON_UPDATE_FILE"
            ok=false
        else
            log_info "Update cron job file exists: $CRON_UPDATE_FILE"
        fi

        local update_script="${LOG_DIR}/run-mde-update.sh"
        if [[ ! -x "$update_script" ]]; then
            log_error "Update wrapper script missing or not executable: $update_script"
            ok=false
        else
            log_info "Update wrapper script ready."
        fi
    fi

    # Summary
    echo ""
    if [[ "$ok" == true ]]; then
        log_info "Verification passed — all components installed correctly."
    else
        log_error "Verification FAILED — review errors above."
    fi

    echo ""
    echo -e "${BOLD}━━━ Deployment Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  Version         : ${CYAN}1.2${NC}"
    echo -e "  Scan type       : ${CYAN}${SCAN_TYPE}${NC}"
    echo -e "  Scan schedule   : ${CYAN}${SCAN_SCHEDULE}${NC}"
    echo -e "  Scan cron file  : ${CYAN}${CRON_JOB_FILE}${NC}"
    if [[ "$INSTALL_UPDATE" == true ]]; then
        echo -e "  Update schedule : ${CYAN}${UPDATE_SCHEDULE}${NC}"
        echo -e "  Update cron file: ${CYAN}${CRON_UPDATE_FILE}${NC}"
    else
        echo -e "  Auto-update     : ${YELLOW}disabled${NC}"
    fi
    echo -e "  Scan log        : ${CYAN}${LOG_FILE}${NC}"
    if [[ "$INSTALL_UPDATE" == true ]]; then
        echo -e "  Update log      : ${CYAN}${UPDATE_LOG_FILE}${NC}"
    fi
    echo -e "  Log retention   : ${CYAN}${RETENTION_DAYS} days${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    echo -e "  ${BOLD}Useful commands:${NC}"
    echo -e "    cat ${CRON_JOB_FILE}                   # View scan schedule"
    if [[ "$INSTALL_UPDATE" == true ]]; then
        echo -e "    cat ${CRON_UPDATE_FILE}            # View update schedule"
    fi
    echo -e "    tail -50 ${LOG_FILE}                              # Recent scan results"
    if [[ "$INSTALL_UPDATE" == true ]]; then
        echo -e "    tail -50 ${UPDATE_LOG_FILE}                       # Recent update results"
    fi
    echo -e "    sudo ${LOG_DIR}/run-mde-scan.sh ${SCAN_TYPE}  # Trigger scan now"
    if [[ "$INSTALL_UPDATE" == true ]]; then
        echo -e "    sudo ${LOG_DIR}/run-mde-update.sh             # Trigger update now"
    fi
    echo ""

    if [[ "$ok" != true ]]; then
        die "Deployment completed with errors — see above."
    fi
}

# ── Parse arguments ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--type)              SCAN_TYPE="$2"; shift 2 ;;
        -s|--schedule)          SCAN_SCHEDULE="$2"; shift 2 ;;
        --update-schedule)      UPDATE_SCHEDULE="$2"; shift 2 ;;
        --no-update)            INSTALL_UPDATE=false; shift ;;
        -l|--log-dir)           LOG_DIR="$2"; LOG_FILE="${LOG_DIR}/mde-scan.log"; UPDATE_LOG_FILE="${LOG_DIR}/mde-update.log"; shift 2 ;;
        -r|--retention)         RETENTION_DAYS="$2"; shift 2 ;;
        -n|--dry-run)           DRY_RUN=true; shift ;;
        -u|--uninstall)         UNINSTALL=true; shift ;;
        -v|--verbose)           VERBOSE=true; shift ;;
        -h|--help)              usage ;;
        *)                      die "Unknown option: $1 (use -h for help)" ;;
    esac
done

# ── Main ─────────────────────────────────────────────────────────────────────
echo -e "${BOLD}MDE Linux Scheduler — Cron Deployment (v1.2)${NC}"
echo -e "──────────────────────────────────────────────"

preflight_checks

if [[ "$UNINSTALL" == true ]]; then
    uninstall
fi

setup_logging

# Scan components
create_scan_script
install_scan_cron_job

# Update components (optional)
if [[ "$INSTALL_UPDATE" == true ]]; then
    create_update_script
    install_update_cron_job
else
    log_info "Auto-update cron job skipped (--no-update)."
fi

verify_installation

log_info "Deployment complete."
