# IP Address Scanner

A multi-threaded IP scanner that pings IP ranges/CIDRs and generates a categorized C-segment utilization report.

## Features

- **Fast Scanning**: Uses `fping` (one process for the whole list, ~1000 probes/s; ~150k addresses in about 6 minutes). Without `fping` it falls back to one `ping` per address on 100 threads (about an hour).
- **Categorized Reporting**: Groups results by C-segments into three categories:
  - Category 1: No active IPs.
  - Category 2: Exactly one active IP.
  - Category 3: Two or more active IPs.
- **Improved Accuracy**: Pings each IP up to 3 times with a 1 s timeout (stops on first success) to handle packet loss.
- **Full Range Scanning**: Scans all IPs in a CIDR, including network and broadcast addresses.
- **CSV & Text Export**: Generates `scan_summary.txt` and `scan_results.csv`.
- **Email Integration**: Sends a summary report with the CSV attached via Gmail SMTP.
- **BCC Support**: Supports sending hidden copies to a list of recipients.
- **Automated Scheduling**: Includes systemd service and timer for daily scans at 2:00 AM.
- **Fails Loudly**: if `ips.txt` is missing or has no valid entries, a "FAILED" email goes out and the service exits non-zero (it used to scan 127.0.0.1/8.8.8.8/8.8.4.4 and send a normal-looking report). A failed email send also exits non-zero, so `systemctl status ip-scanner` shows it. The service has a 3 h timeout so a hung run can't block the next day's.
- **Root-only Files**: the service runs with `UMask=0077`; `.env`, `ips.txt` and the results are 600.

## Installation

1. Clone the repository to `/opt/project/ip-address-scanner` and install `fping` (EPEL on RHEL/CentOS: `dnf install fping`).
2. Create a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
3. Configure your environment variables in `.env`:
   ```env
   SMTP_USER=your-email@gmail.com
   SMTP_PASSWORD=your-app-password
   REPORT_RECIPIENT=recipient@example.com
   BCC_LIST=admin@example.com,manager@example.com
   ```

## Usage

### Manual Run
```bash
./.venv/bin/python scanner.py ips.txt
```

### Automation (Systemd)
The scanner is set to run daily at 2:00 AM via systemd.
- **Check timer status**: `systemctl status ip-scanner.timer`
- **View logs**: `journalctl -u ip-scanner.service`
- **Run immediately**: `systemctl start ip-scanner.service`

## Files
- `ips.txt`: List of IP addresses or CIDR ranges to scan.
- `scanner.py`: Main Python script.
- `scan_results.csv`: Detailed report in CSV format.
- `scan_summary.txt`: Condensed summary report.
- `run_scanner.sh`: Wrapper script for automation.
