#!/usr/bin/env bash
# ==============================================================================
# deploy-mde-systemd.sh — Microsoft Defender for Endpoint (MDE) Systemd Scheduler
# ==============================================================================
# Deploys systemd timer-based scheduled scans AND automatic definition updates
# for MDE on Linux endpoints.
#
# Version: 1.2
# Changelog:
#   v1.2 — Default scan schedule changed to Tuesday & Saturday at 00:00.
#           Added MDE definition auto-update timer (every 15 days + daily check).
#           New flags: --update-calendar, --update-delay, --no-update.
#   v1.1 — Fixed silent exit bug in enable_timer() caused by set -euo pipefail.
#           Enhanced verify_installation() with actionable diagnostics.
#   v1.0 — Initial release.
#
# Copyright (c) 2026 SOS Group Limited — Cyber Security Unit
# Licensed under the MIT License. See LICENSE for details.
# ==============================================================================

set -euo pipefail
IFS=$'\n\t'

# ── Defaults ──────────────────────────────────────────────────────────────────
SCAN_TYPE="quick"
SCAN_CALENDAR="Tue,Sat *-*-* 00:00:00"       # Every Tuesday & Saturday at midnight
RANDOMIZED_DELAY="15m"
LOG_DIR="/var/log/mde-scheduler"
LOG_FILE="${LOG_DIR}/mde-scan.log"
UPDATE_LOG_FILE="${LOG_DIR}/mde-update.log"
SERVICE_NAME="mde-scheduled-scan"
UPDATE_SERVICE_NAME="mde-definition-update"
MDATP_BIN="/usr/bin/mdatp"
MAX_LOG_SIZE_MB=50
RETENTION_DAYS=90
DRY_RUN=false
UNINSTALL=false
VERBOSE=false
INSTALL_UPDATE=true
UPDATE_CALENDAR="*-1,16 00:30:00"             # 1st and 16th of every month at 00:30 (≈15 days)
UPDATE_RANDOMIZED_DELAY="30m"

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

Deploy systemd timer-based scheduled scans and automatic definition updates
for Microsoft Defender for Endpoint on Linux.

${BOLD}Scan Options:${NC}
  -t, --type TYPE             Scan type: quick | full (default: quick)
  -c, --calendar CALENDAR     Systemd OnCalendar expression for scans
                              (default: "Tue,Sat *-*-* 00:00:00")
  -d, --delay DELAY           RandomizedDelaySec for scans (default: 15m)

${BOLD}Update Options:${NC}
  --update-calendar CALENDAR  OnCalendar for definition updates
                              (default: "*-1,16 00:30:00" — every 15 days)
  --update-delay DELAY        RandomizedDelaySec for updates (default: 30m)
  --no-update                 Skip installing the definition update timer

${BOLD}General Options:${NC}
  -l, --log-dir DIR           Log directory (default: /var/log/mde-scheduler)
  -r, --retention DAYS        Log retention in days (default: 90)
  -n, --dry-run               Show what would be done without making changes
  -u, --uninstall             Remove all systemd units and clean up
  -v, --verbose               Enable verbose output
  -h, --help                  Show this help message

${BOLD}Examples:${NC}
  sudo ./deploy-mde-systemd.sh                    # Scans Tue/Sat 00:00 + updates every 15 days
  sudo ./deploy-mde-systemd.sh -t full             # Full scans Tue/Sat at midnight
  sudo ./deploy-mde-systemd.sh --no-update         # Scans only, no auto-update
  sudo ./deploy-mde-systemd.sh -u                  # Remove all scheduled tasks

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

    # Verify systemd
    if ! command -v systemctl &>/dev/null; then
        die "systemctl not found. This script requires systemd."
    fi
    log_verbose "systemd detected: $(systemctl --version | head -1)"

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

    # Validate scan type
    if [[ "$SCAN_TYPE" != "quick" && "$SCAN_TYPE" != "full" ]]; then
        die "Invalid scan type: '$SCAN_TYPE'. Use 'quick' or 'full'."
    fi

    # Validate OnCalendar expressions
    if ! systemd-analyze calendar "$SCAN_CALENDAR" &>/dev/null; then
        die "Invalid scan OnCalendar expression: '$SCAN_CALENDAR'. Check systemd.time(7)."
    fi
    log_verbose "Scan calendar validated: $(systemd-analyze calendar "$SCAN_CALENDAR" 2>/dev/null | grep 'Next elapse' || echo 'OK')"

    if [[ "$INSTALL_UPDATE" == true ]]; then
        if ! systemd-analyze calendar "$UPDATE_CALENDAR" &>/dev/null; then
            die "Invalid update OnCalendar expression: '$UPDATE_CALENDAR'. Check systemd.time(7)."
        fi
        log_verbose "Update calendar validated: $(systemd-analyze calendar "$UPDATE_CALENDAR" 2>/dev/null | grep 'Next elapse' || echo 'OK')"
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

# ── Create the scan wrapper script ──────────────────────────────────────────
create_scan_script() {
    local scan_script="${LOG_DIR}/run-mde-scan.sh"
    log_step "Creating scan wrapper script..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would create scan script: $scan_script"
        return
    fi

    cat > "$scan_script" <<'WRAPPER'
#!/usr/bin/env bash
# MDE Scheduled Scan Wrapper — Auto-generated by deploy-mde-systemd.sh
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

# ── Create the update wrapper script ─────────────────────────────────────────
create_update_script() {
    local update_script="${LOG_DIR}/run-mde-update.sh"
    log_step "Creating MDE definition update script..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would create update script: $update_script"
        return
    fi

    cat > "$update_script" <<'WRAPPER'
#!/usr/bin/env bash
# MDE Definition Update Wrapper — Auto-generated by deploy-mde-systemd.sh
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
        # Non-zero may mean "already up to date" on some versions
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

# ── Create systemd service unit (scan) ───────────────────────────────────────
create_service_unit() {
    local unit_file="/etc/systemd/system/${SERVICE_NAME}.service"
    local scan_script="${LOG_DIR}/run-mde-scan.sh"
    log_step "Creating systemd scan service unit..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would create service unit: $unit_file"
        return
    fi

    cat > "$unit_file" <<EOF
# MDE Scheduled Scan Service — Managed by deploy-mde-systemd.sh v1.2
# Installed: $(date '+%Y-%m-%d %H:%M:%S')
[Unit]
Description=Microsoft Defender for Endpoint — Scheduled ${SCAN_TYPE} scan
Documentation=https://learn.microsoft.com/en-us/defender-endpoint/linux-schedule-scan-mde
After=network-online.target mdatp.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${scan_script} ${SCAN_TYPE} ${LOG_FILE} ${MAX_LOG_SIZE_MB} ${RETENTION_DAYS}
Nice=19
IOSchedulingClass=idle
CPUSchedulingPolicy=idle
TimeoutStartSec=3600
KillMode=process

# Sandboxing
ProtectHome=read-only
ProtectSystem=strict
ReadWritePaths=${LOG_DIR}
PrivateTmp=true
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 "$unit_file"
    log_info "Scan service unit created: $unit_file"
}

# ── Create systemd timer unit (scan) ─────────────────────────────────────────
create_timer_unit() {
    local unit_file="/etc/systemd/system/${SERVICE_NAME}.timer"
    log_step "Creating systemd scan timer unit..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would create timer unit: $unit_file"
        return
    fi

    cat > "$unit_file" <<EOF
# MDE Scheduled Scan Timer — Managed by deploy-mde-systemd.sh v1.2
# Installed: $(date '+%Y-%m-%d %H:%M:%S')
# Schedule: ${SCAN_CALENDAR}
[Unit]
Description=Microsoft Defender for Endpoint — Scan timer (${SCAN_TYPE}, Tue/Sat midnight)
Documentation=https://learn.microsoft.com/en-us/defender-endpoint/linux-schedule-scan-mde

[Timer]
OnCalendar=${SCAN_CALENDAR}
RandomizedDelaySec=${RANDOMIZED_DELAY}
Persistent=true
AccuracySec=1m

[Install]
WantedBy=timers.target
EOF

    chmod 644 "$unit_file"
    log_info "Scan timer unit created: $unit_file"
}

# ── Create systemd service unit (update) ─────────────────────────────────────
create_update_service_unit() {
    local unit_file="/etc/systemd/system/${UPDATE_SERVICE_NAME}.service"
    local update_script="${LOG_DIR}/run-mde-update.sh"
    log_step "Creating systemd update service unit..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would create update service unit: $unit_file"
        return
    fi

    cat > "$unit_file" <<EOF
# MDE Definition Update Service — Managed by deploy-mde-systemd.sh v1.2
# Installed: $(date '+%Y-%m-%d %H:%M:%S')
[Unit]
Description=Microsoft Defender for Endpoint — Definition & engine update
Documentation=https://learn.microsoft.com/en-us/defender-endpoint/linux-updates
After=network-online.target mdatp.service
Wants=network-online.target
Requires=network-online.target

[Service]
Type=oneshot
ExecStart=${update_script} ${UPDATE_LOG_FILE} ${MAX_LOG_SIZE_MB} ${RETENTION_DAYS}
Nice=10
IOSchedulingClass=best-effort
TimeoutStartSec=1800
KillMode=process

# Sandboxing
ProtectHome=read-only
ProtectSystem=strict
ReadWritePaths=${LOG_DIR} /var/lib/dpkg /var/cache/apt /var/lib/apt /var/lib/rpm /var/cache/dnf /var/cache/yum
PrivateTmp=true
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 "$unit_file"
    log_info "Update service unit created: $unit_file"
}

# ── Create systemd timer unit (update) ───────────────────────────────────────
create_update_timer_unit() {
    local unit_file="/etc/systemd/system/${UPDATE_SERVICE_NAME}.timer"
    log_step "Creating systemd update timer unit..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would create update timer unit: $unit_file"
        return
    fi

    cat > "$unit_file" <<EOF
# MDE Definition Update Timer — Managed by deploy-mde-systemd.sh v1.2
# Installed: $(date '+%Y-%m-%d %H:%M:%S')
# Schedule: Every ~15 days (1st and 16th of each month)
[Unit]
Description=Microsoft Defender for Endpoint — Definition update timer (~15 days)
Documentation=https://learn.microsoft.com/en-us/defender-endpoint/linux-updates

[Timer]
OnCalendar=${UPDATE_CALENDAR}
RandomizedDelaySec=${UPDATE_RANDOMIZED_DELAY}
Persistent=true
AccuracySec=1m

[Install]
WantedBy=timers.target
EOF

    chmod 644 "$unit_file"
    log_info "Update timer unit created: $unit_file"
}

# ── Enable & start (v1.1+ — graceful error handling) ────────────────────────
enable_timer() {
    local timer_name="$1"
    local label="$2"
    log_step "Enabling and starting ${label} timer..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would reload systemd and enable ${timer_name}.timer"
        return 0
    fi

    # daemon-reload: apply new/changed unit files
    if ! systemctl daemon-reload 2>&1; then
        log_warn "daemon-reload returned non-zero (may be harmless)."
    fi

    # Enable the timer to start on boot
    if ! systemctl enable "${timer_name}.timer" 2>&1; then
        log_error "Failed to enable ${timer_name}.timer."
        log_error "Debug with: systemctl status ${timer_name}.timer"
        log_error "            cat /etc/systemd/system/${timer_name}.timer"
        log_warn "Continuing to verification step..."
        return 0
    fi

    # Start the timer now
    if ! systemctl start "${timer_name}.timer" 2>&1; then
        log_error "Failed to start ${timer_name}.timer."
        log_error "Debug with: journalctl -xe --unit=${timer_name}.timer"
        log_error "            systemctl status ${timer_name}.timer"
        log_warn "Continuing to verification step..."
        return 0
    fi

    log_info "${label} timer enabled and started."
}

# ── Uninstall ────────────────────────────────────────────────────────────────
uninstall() {
    log_step "Uninstalling all MDE scheduled tasks (systemd)..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] Would stop and disable ${SERVICE_NAME}.timer"
        log_info "[DRY RUN] Would stop and disable ${UPDATE_SERVICE_NAME}.timer"
        log_info "[DRY RUN] Would remove all service/timer units and scripts"
        return
    fi

    # Stop and disable scan timer
    for svc in "${SERVICE_NAME}" "${UPDATE_SERVICE_NAME}"; do
        if systemctl is-active --quiet "${svc}.timer" 2>/dev/null; then
            systemctl stop "${svc}.timer"
            log_info "Stopped ${svc}.timer"
        fi
        if systemctl is-enabled --quiet "${svc}.timer" 2>/dev/null; then
            systemctl disable "${svc}.timer"
            log_info "Disabled ${svc}.timer"
        fi
    done

    # Remove all unit files
    local units=(
        "/etc/systemd/system/${SERVICE_NAME}.timer"
        "/etc/systemd/system/${SERVICE_NAME}.service"
        "/etc/systemd/system/${UPDATE_SERVICE_NAME}.timer"
        "/etc/systemd/system/${UPDATE_SERVICE_NAME}.service"
    )

    for f in "${units[@]}"; do
        if [[ -f "$f" ]]; then
            rm -f "$f"
            log_info "Removed: $f"
        fi
    done

    systemctl daemon-reload
    log_info "Systemd daemon reloaded."

    # Remove wrapper scripts
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

# ── Verification (v1.1+ — enhanced diagnostics) ─────────────────────────────
verify_installation() {
    log_step "Verifying installation..."

    local ok=true

    # ── Verify scan components ───────────────────────────────────────────
    echo ""
    echo -e "${BOLD}── Scan Timer ──────────────────────────────────────────────${NC}"

    local timer_file="/etc/systemd/system/${SERVICE_NAME}.timer"
    local service_file="/etc/systemd/system/${SERVICE_NAME}.service"
    local scan_script="${LOG_DIR}/run-mde-scan.sh"

    if [[ ! -f "$timer_file" ]]; then
        log_error "Timer unit file missing: $timer_file"; ok=false
    else
        log_verbose "Timer unit file exists: $timer_file"
    fi

    if [[ ! -f "$service_file" ]]; then
        log_error "Service unit file missing: $service_file"; ok=false
    else
        log_verbose "Service unit file exists: $service_file"
    fi

    if ! systemctl is-active --quiet "${SERVICE_NAME}.timer" 2>/dev/null; then
        log_error "Scan timer is NOT active."
        log_error "  Fix: sudo systemctl start ${SERVICE_NAME}.timer"
        ok=false
    else
        log_info "Scan timer is active."
    fi

    if ! systemctl is-enabled --quiet "${SERVICE_NAME}.timer" 2>/dev/null; then
        log_error "Scan timer is NOT enabled (won't survive reboot)."
        log_error "  Fix: sudo systemctl enable ${SERVICE_NAME}.timer"
        ok=false
    else
        log_info "Scan timer is enabled."
    fi

    if [[ ! -x "$scan_script" ]]; then
        log_error "Scan wrapper script missing or not executable: $scan_script"
        ok=false
    else
        log_info "Scan wrapper script ready."
    fi

    # ── Verify update components (if installed) ──────────────────────────
    if [[ "$INSTALL_UPDATE" == true ]]; then
        echo ""
        echo -e "${BOLD}── Update Timer ────────────────────────────────────────────${NC}"

        local update_timer_file="/etc/systemd/system/${UPDATE_SERVICE_NAME}.timer"
        local update_service_file="/etc/systemd/system/${UPDATE_SERVICE_NAME}.service"
        local update_script="${LOG_DIR}/run-mde-update.sh"

        if [[ ! -f "$update_timer_file" ]]; then
            log_error "Update timer unit file missing: $update_timer_file"; ok=false
        fi

        if [[ ! -f "$update_service_file" ]]; then
            log_error "Update service unit file missing: $update_service_file"; ok=false
        fi

        if ! systemctl is-active --quiet "${UPDATE_SERVICE_NAME}.timer" 2>/dev/null; then
            log_error "Update timer is NOT active."
            log_error "  Fix: sudo systemctl start ${UPDATE_SERVICE_NAME}.timer"
            ok=false
        else
            log_info "Update timer is active."
        fi

        if ! systemctl is-enabled --quiet "${UPDATE_SERVICE_NAME}.timer" 2>/dev/null; then
            log_error "Update timer is NOT enabled."
            log_error "  Fix: sudo systemctl enable ${UPDATE_SERVICE_NAME}.timer"
            ok=false
        else
            log_info "Update timer is enabled."
        fi

        if [[ ! -x "$update_script" ]]; then
            log_error "Update wrapper script missing or not executable: $update_script"
            ok=false
        else
            log_info "Update wrapper script ready."
        fi
    fi

    # ── Summary ──────────────────────────────────────────────────────────
    echo ""
    if [[ "$ok" == true ]]; then
        log_info "Verification passed — all components installed correctly."
    else
        log_error "Verification FAILED — review errors above and apply fixes."
    fi

    echo ""
    echo -e "${BOLD}━━━ Deployment Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  Version         : ${CYAN}1.2${NC}"
    echo -e "  Scan type       : ${CYAN}${SCAN_TYPE}${NC}"
    echo -e "  Scan schedule   : ${CYAN}${SCAN_CALENDAR}${NC}"
    echo -e "  Scan jitter     : ${CYAN}${RANDOMIZED_DELAY}${NC}"
    echo -e "  Scan timer      : ${CYAN}${SERVICE_NAME}.timer${NC}"
    if [[ "$INSTALL_UPDATE" == true ]]; then
        echo -e "  Update schedule : ${CYAN}${UPDATE_CALENDAR}${NC}"
        echo -e "  Update jitter   : ${CYAN}${UPDATE_RANDOMIZED_DELAY}${NC}"
        echo -e "  Update timer    : ${CYAN}${UPDATE_SERVICE_NAME}.timer${NC}"
    else
        echo -e "  Auto-update     : ${YELLOW}disabled${NC}"
    fi
    echo -e "  Log directory   : ${CYAN}${LOG_DIR}${NC}"
    echo -e "  Log retention   : ${CYAN}${RETENTION_DAYS} days${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    # Show next trigger times
    echo -e "  ${BOLD}Next scheduled runs:${NC}"
    if systemctl is-active --quiet "${SERVICE_NAME}.timer" 2>/dev/null; then
        echo -e "  ${CYAN}Scan:${NC}"
        systemctl list-timers "${SERVICE_NAME}.timer" --no-pager 2>/dev/null | head -3 || true
    fi
    if [[ "$INSTALL_UPDATE" == true ]] && systemctl is-active --quiet "${UPDATE_SERVICE_NAME}.timer" 2>/dev/null; then
        echo -e "  ${CYAN}Update:${NC}"
        systemctl list-timers "${UPDATE_SERVICE_NAME}.timer" --no-pager 2>/dev/null | head -3 || true
    fi
    echo ""

    echo -e "  ${BOLD}Useful commands:${NC}"
    echo -e "    systemctl status ${SERVICE_NAME}.timer            # Scan timer status"
    echo -e "    systemctl list-timers ${SERVICE_NAME}.timer        # Next scan run"
    if [[ "$INSTALL_UPDATE" == true ]]; then
        echo -e "    systemctl status ${UPDATE_SERVICE_NAME}.timer     # Update timer status"
        echo -e "    systemctl list-timers ${UPDATE_SERVICE_NAME}.timer # Next update run"
    fi
    echo -e "    journalctl -u ${SERVICE_NAME}.service             # Scan logs"
    if [[ "$INSTALL_UPDATE" == true ]]; then
        echo -e "    journalctl -u ${UPDATE_SERVICE_NAME}.service      # Update logs"
    fi
    echo -e "    sudo systemctl start ${SERVICE_NAME}.service      # Trigger scan now"
    if [[ "$INSTALL_UPDATE" == true ]]; then
        echo -e "    sudo systemctl start ${UPDATE_SERVICE_NAME}.service # Trigger update now"
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
        -c|--calendar)          SCAN_CALENDAR="$2"; shift 2 ;;
        -d|--delay)             RANDOMIZED_DELAY="$2"; shift 2 ;;
        --update-calendar)      UPDATE_CALENDAR="$2"; shift 2 ;;
        --update-delay)         UPDATE_RANDOMIZED_DELAY="$2"; shift 2 ;;
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
echo -e "${BOLD}MDE Linux Scheduler — Systemd Deployment (v1.2)${NC}"
echo -e "──────────────────────────────────────────────────"

preflight_checks

if [[ "$UNINSTALL" == true ]]; then
    uninstall
fi

setup_logging

# Scan components
create_scan_script
create_service_unit
create_timer_unit
enable_timer "${SERVICE_NAME}" "Scan"

# Update components (optional)
if [[ "$INSTALL_UPDATE" == true ]]; then
    create_update_script
    create_update_service_unit
    create_update_timer_unit
    enable_timer "${UPDATE_SERVICE_NAME}" "Update"
else
    log_info "Auto-update timer skipped (--no-update)."
fi

verify_installation

log_info "Deployment complete."
