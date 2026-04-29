#!/usr/bin/env bash
# ==============================================================================
# deploy-mde-cron.sh — Microsoft Defender for Endpoint (MDE) Cron Scheduler
# ==============================================================================
# Deploys a cron-based scheduled scan for MDE on Linux endpoints.
#
# Copyright (c) 2026 SOS Group Limited — Cyber Security Unit
# Licensed under the MIT License. See LICENSE for details.
# ==============================================================================

set -euo pipefail
IFS=$'\n\t'

# ── Defaults ──────────────────────────────────────────────────────────────────
SCAN_TYPE="quick"
SCAN_SCHEDULE="0 2 * * *"        # Daily at 02:00
LOG_DIR="/var/log/mde-scheduler"
LOG_FILE="${LOG_DIR}/mde-scan.log"
CRON_JOB_FILE="/etc/cron.d/mde-scheduled-scan"
MDATP_BIN="/usr/bin/mdatp"
MAX_LOG_SIZE_MB=50
RETENTION_DAYS=90
DRY_RUN=false
UNINSTALL=false
VERBOSE=false

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

Deploy a cron-based scheduled scan for Microsoft Defender for Endpoint on Linux.

${BOLD}Options:${NC}
  -t, --type TYPE         Scan type: quick | full (default: quick)
  -s, --schedule CRON     Cron expression (default: "0 2 * * *")
  -l, --log-dir DIR       Log directory (default: /var/log/mde-scheduler)
  -r, --retention DAYS    Log retention in days (default: 90)
  -n, --dry-run           Show what would be done without making changes
  -u, --uninstall         Remove the cron job and clean up
  -v, --verbose           Enable verbose output
  -h, --help              Show this help message

${BOLD}Examples:${NC}
  sudo ./deploy-mde-cron.sh                           # Quick scan daily at 02:00
  sudo ./deploy-mde-cron.sh -t full -s "0 3 * * 0"   # Full scan every Sunday at 03:00
  sudo ./deploy-mde-cron.sh -u                        # Remove scheduled scan

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
        log_warn "No active cron service detected. Ensure cron is running for scheduled scans."
    fi

    # Validate scan type
    if [[ "$SCAN_TYPE" != "quick" && "$SCAN_TYPE" != "full" ]]; then
        die "Invalid scan type: '$SCAN_TYPE'. Use 'quick' or 'full'."
    fi

    # Validate cron expression (basic check: 5 fields)
    local field_count
    field_count=$(echo "$SCAN_SCHEDULE" | awk '{print NF}')
    if [[ "$field_count" -ne 5 ]]; then
        die "Invalid cron expression: '$SCAN_SCHEDULE'. Must have exactly 5 fields."
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
    echo "========================================"

    if mdatp scan "$SCAN_TYPE" 2>&1; then
        echo "[RESULT] Scan completed successfully."
    else
        echo "[RESULT] Scan exited with non-zero status ($?)."
    fi

    echo ""
} >> "$LOG_FILE" 2>&1
WRAPPER

    chmod 700 "$scan_script"
    log_info "Scan wrapper script created: $scan_script"
}

# ── Install cron job ─────────────────────────────────────────────────────────
install_cron_job() {
    log_step "Installing cron job..."

    local scan_script="${LOG_DIR}/run-mde-scan.sh"
    local cron_line="${SCAN_SCHEDULE} root ${scan_script} ${SCAN_TYPE} ${LOG_FILE} ${MAX_LOG_SIZE_MB} ${RETENTION_DAYS}"

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would write to ${CRON_JOB_FILE}:"
        echo "  $cron_line"
        return
    fi

    cat > "$CRON_JOB_FILE" <<EOF
# MDE Scheduled Scan — Managed by deploy-mde-cron.sh
# Installed: $(date '+%Y-%m-%d %H:%M:%S')
# Scan type: ${SCAN_TYPE}
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

${cron_line}
EOF

    chmod 644 "$CRON_JOB_FILE"
    log_info "Cron job installed: $CRON_JOB_FILE"
    log_info "Schedule: ${SCAN_SCHEDULE} | Type: ${SCAN_TYPE}"
}

# ── Uninstall ────────────────────────────────────────────────────────────────
uninstall() {
    log_step "Uninstalling MDE scheduled scan..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would remove: $CRON_JOB_FILE"
        log_info "[DRY RUN] Would remove scan script from: $LOG_DIR"
        return
    fi

    if [[ -f "$CRON_JOB_FILE" ]]; then
        rm -f "$CRON_JOB_FILE"
        log_info "Removed cron job: $CRON_JOB_FILE"
    else
        log_warn "Cron job not found at $CRON_JOB_FILE"
    fi

    local scan_script="${LOG_DIR}/run-mde-scan.sh"
    if [[ -f "$scan_script" ]]; then
        rm -f "$scan_script"
        log_info "Removed scan wrapper script."
    fi

    log_info "Uninstall complete. Log files retained in $LOG_DIR."
    exit 0
}

# ── Verification ─────────────────────────────────────────────────────────────
verify_installation() {
    log_step "Verifying installation..."

    local ok=true

    if [[ ! -f "$CRON_JOB_FILE" ]]; then
        log_error "Cron job file missing: $CRON_JOB_FILE"
        ok=false
    fi

    local scan_script="${LOG_DIR}/run-mde-scan.sh"
    if [[ ! -x "$scan_script" ]]; then
        log_error "Scan wrapper script missing or not executable: $scan_script"
        ok=false
    fi

    if [[ "$ok" == true ]]; then
        log_info "Verification passed — all components installed correctly."
        echo ""
        echo -e "${BOLD}━━━ Deployment Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "  Scan type     : ${CYAN}${SCAN_TYPE}${NC}"
        echo -e "  Schedule      : ${CYAN}${SCAN_SCHEDULE}${NC}"
        echo -e "  Cron file     : ${CYAN}${CRON_JOB_FILE}${NC}"
        echo -e "  Log file      : ${CYAN}${LOG_FILE}${NC}"
        echo -e "  Log retention : ${CYAN}${RETENTION_DAYS} days${NC}"
        echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    else
        die "Verification failed — review errors above."
    fi
}

# ── Parse arguments ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--type)      SCAN_TYPE="$2"; shift 2 ;;
        -s|--schedule)  SCAN_SCHEDULE="$2"; shift 2 ;;
        -l|--log-dir)   LOG_DIR="$2"; LOG_FILE="${LOG_DIR}/mde-scan.log"; shift 2 ;;
        -r|--retention) RETENTION_DAYS="$2"; shift 2 ;;
        -n|--dry-run)   DRY_RUN=true; shift ;;
        -u|--uninstall) UNINSTALL=true; shift ;;
        -v|--verbose)   VERBOSE=true; shift ;;
        -h|--help)      usage ;;
        *)              die "Unknown option: $1 (use -h for help)" ;;
    esac
done

# ── Main ─────────────────────────────────────────────────────────────────────
echo -e "${BOLD}MDE Linux Scheduler — Cron Deployment${NC}"
echo -e "────────────────────────────────────────"

preflight_checks

if [[ "$UNINSTALL" == true ]]; then
    uninstall
fi

setup_logging
create_scan_script
install_cron_job
verify_installation

log_info "Deployment complete."
