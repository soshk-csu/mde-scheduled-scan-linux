# MDE Linux Scheduler

**Automated scan scheduling for Microsoft Defender for Endpoint on Linux**

[![CI Tests](https://github.com/sos-group/mde-linux-scheduler/actions/workflows/test.yml/badge.svg)](https://github.com/sos-group/mde-linux-scheduler/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Synopsis

MDE Linux Scheduler provides production-ready deployment scripts for scheduling Microsoft Defender for Endpoint (MDE) scans on Linux endpoints. It supports two scheduling backends — **cron** and **systemd timers** — allowing you to choose the method that best fits your environment.

Each script handles the full lifecycle: pre-flight validation, scan wrapper creation, scheduler installation, log rotation, and clean uninstall. Designed for enterprise environments where consistent, auditable endpoint scanning is required.

### Key Features

- **Dual scheduler support** — cron (`/etc/cron.d`) or systemd timer, your choice
- **Pre-flight validation** — checks for root, mdatp binary, health status, and scheduler availability
- **Configurable scan types** — quick or full scans on your schedule
- **Built-in log management** — automatic rotation by size and retention by age
- **Dry-run mode** — preview all changes before applying
- **Clean uninstall** — fully reversible deployment
- **Systemd hardening** — sandboxing, CPU/IO scheduling, and timeout controls
- **Randomized delay** — (systemd) prevents scan storms across fleet deployments

---

## Project Structure

```
mde-linux-scheduler/
├── scripts/
│   ├── deploy-mde-cron.sh        # Cron-based deployment
│   └── deploy-mde-systemd.sh     # Systemd timer-based deployment
├── .github/
│   └── workflows/
│       └── test.yml              # CI pipeline (shellcheck + syntax)
├── README.md                     # This file
├── LICENSE                       # MIT License
└── .gitignore
```

---

## Requirements

| Requirement | Details |
|---|---|
| **OS** | Linux (see supported distributions below) |
| **MDE** | Microsoft Defender for Endpoint installed and onboarded |
| **Privileges** | Root / sudo access |
| **Scheduler** | cron **or** systemd (depending on chosen script) |
| **Shell** | Bash 4.0+ |

---

## Supported Distributions

| Distribution | Versions | Notes |
|---|---|---|
| RHEL / CentOS | 7.2+ | Includes CentOS Stream 8/9 |
| Ubuntu | 18.04, 20.04, 22.04, 24.04 | LTS releases |
| Debian | 10 (Buster), 11 (Bullseye), 12 (Bookworm) | Stable releases |
| SUSE Linux Enterprise Server | 12 SP1+, 15+ | |
| Oracle Linux | 7.2+, 8+ | RHCK and UEK kernels |
| Amazon Linux | 2, 2023 | |
| Fedora | 33+ | |
| Rocky Linux | 8+, 9+ | |
| AlmaLinux | 8+, 9+ | |

> **Note:** Distribution support aligns with [Microsoft's official MDE Linux requirements](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-endpoint-linux).

---

## Usage

### Quick Start

```bash
# Clone the repository
git clone https://github.com/sos-group/mde-linux-scheduler.git
cd mde-linux-scheduler

# Make scripts executable
chmod +x scripts/*.sh

# Deploy with cron (quick scan daily at 02:00)
sudo ./scripts/deploy-mde-cron.sh

# — OR — deploy with systemd timer
sudo ./scripts/deploy-mde-systemd.sh
```

### Cron Deployment

```bash
# Default: quick scan daily at 02:00
sudo ./scripts/deploy-mde-cron.sh

# Full scan every Sunday at 03:00
sudo ./scripts/deploy-mde-cron.sh --type full --schedule "0 3 * * 0"

# Quick scan at midnight with custom log directory
sudo ./scripts/deploy-mde-cron.sh --schedule "0 0 * * *" --log-dir /opt/mde/logs

# Preview changes without applying
sudo ./scripts/deploy-mde-cron.sh --dry-run --verbose

# Remove the scheduled scan
sudo ./scripts/deploy-mde-cron.sh --uninstall
```

#### Cron Options

| Flag | Description | Default |
|---|---|---|
| `-t, --type` | Scan type: `quick` or `full` | `quick` |
| `-s, --schedule` | Cron expression (5 fields) | `0 2 * * *` |
| `-l, --log-dir` | Log directory path | `/var/log/mde-scheduler` |
| `-r, --retention` | Log retention in days | `90` |
| `-n, --dry-run` | Preview changes only | — |
| `-u, --uninstall` | Remove scheduled scan | — |
| `-v, --verbose` | Verbose output | — |
| `-h, --help` | Show help | — |

### Systemd Deployment

```bash
# Default: quick scan daily at 02:00 with 15m jitter
sudo ./scripts/deploy-mde-systemd.sh

# Full scan every Sunday at 03:00
sudo ./scripts/deploy-mde-systemd.sh --type full --calendar "Sun *-*-* 03:00:00"

# Weekday scans at noon with 30-minute jitter
sudo ./scripts/deploy-mde-systemd.sh --calendar "Mon..Fri *-*-* 12:00:00" --delay 30m

# Preview changes without applying
sudo ./scripts/deploy-mde-systemd.sh --dry-run --verbose

# Remove the scheduled scan
sudo ./scripts/deploy-mde-systemd.sh --uninstall
```

#### Systemd Options

| Flag | Description | Default |
|---|---|---|
| `-t, --type` | Scan type: `quick` or `full` | `quick` |
| `-c, --calendar` | systemd OnCalendar expression | `*-*-* 02:00:00` |
| `-d, --delay` | RandomizedDelaySec value | `15m` |
| `-l, --log-dir` | Log directory path | `/var/log/mde-scheduler` |
| `-r, --retention` | Log retention in days | `90` |
| `-n, --dry-run` | Preview changes only | — |
| `-u, --uninstall` | Remove scheduled scan | — |
| `-v, --verbose` | Verbose output | — |
| `-h, --help` | Show help | — |

---

## Cron vs. Systemd — Which to Choose?

| Feature | Cron | Systemd Timer |
|---|---|---|
| **Availability** | Nearly all Linux systems | systemd-based systems only |
| **Missed scans** | Lost if system was off | `Persistent=true` catches up |
| **Fleet jitter** | Manual (sleep/random) | Built-in `RandomizedDelaySec` |
| **Resource control** | None | CPU/IO scheduling, sandboxing |
| **Logging** | Script-managed | Script-managed + journalctl |
| **Dependencies** | None | Can wait for network/mdatp |
| **Best for** | Legacy systems, minimal setups | Modern distros, enterprise fleets |

**Recommendation:** Use **systemd** on modern distributions for better reliability and resource control. Use **cron** on legacy systems or minimal environments without systemd.

---

## Log Management

Both scripts create a scan wrapper that manages its own log rotation:

- **Location:** `/var/log/mde-scheduler/mde-scan.log` (configurable)
- **Rotation:** Automatic when log exceeds 50 MB
- **Retention:** Backups older than 90 days are purged (configurable)
- **Format:** Timestamped entries with scan type, result, and duration

View recent scan results:

```bash
# Tail the scan log
tail -50 /var/log/mde-scheduler/mde-scan.log

# (Systemd only) Check via journalctl
journalctl -u mde-scheduled-scan.service --since today
```

---

## Verification

### Cron

```bash
# Check the cron job exists
cat /etc/cron.d/mde-scheduled-scan

# List cron jobs for root
sudo crontab -l 2>/dev/null; ls -la /etc/cron.d/mde-*
```

### Systemd

```bash
# Check timer status
systemctl status mde-scheduled-scan.timer

# View next scheduled run
systemctl list-timers mde-scheduled-scan.timer

# Manually trigger a scan (for testing)
sudo systemctl start mde-scheduled-scan.service

# Check service result
systemctl status mde-scheduled-scan.service
```

---

## Troubleshooting

| Issue | Resolution |
|---|---|
| `mdatp binary not found` | Install MDE: [Microsoft docs](https://learn.microsoft.com/en-us/defender-endpoint/linux-install-manually) |
| `mdatp health reports unhealthy` | Run `mdatp health` to diagnose; check onboarding and connectivity |
| Scan not running on schedule | Verify cron/systemd is active; check logs for errors |
| `Invalid cron expression` | Ensure exactly 5 fields (min hour dom mon dow) |
| `Invalid OnCalendar expression` | Test with `systemd-analyze calendar "your expression"` |
| Permission denied | Run with `sudo` or as root |
| Timer shows `inactive` | Run `sudo systemctl enable --now mde-scheduled-scan.timer` |

---

## Security Considerations

- Scripts must be run as **root** to install system-level schedulers
- The systemd service includes **sandboxing** directives (`ProtectSystem`, `PrivateTmp`, etc.)
- Scan wrapper scripts are created with **mode 700** (root-only execution)
- Log directories are created with **mode 750**
- All file paths are validated before use
- The `set -euo pipefail` ensures scripts fail fast on errors

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Run shellcheck: `shellcheck scripts/*.sh`
4. Commit your changes
5. Open a Pull Request

---

## License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

**Copyright (c) 2026 SOS Group Limited — Cyber Security Unit**
