# IP Address Scanner

A multi-threaded IP scanner that pings IP ranges/CIDRs and generates a categorized C-segment utilization report.

## Features

- **Multi-threaded Scanning**: Uses `ThreadPoolExecutor` for high-speed scanning (default 100 workers).
- **Categorized Reporting**: Groups results by C-segments into three categories:
  - Category 1: No active IPs.
  - Category 2: Exactly one active IP.
  - Category 3: Two or more active IPs.
- **Improved Accuracy**: Pings each IP up to 3 times (stops on first success) to handle packet loss.
- **Full Range Scanning**: Scans all IPs in a CIDR, including network and broadcast addresses.
- **CSV & Text Export**: Generates `scan_summary.txt` and `scan_results.csv`.
- **Email Integration**: Sends a summary report with the CSV attached via Gmail SMTP.
- **BCC Support**: Supports sending hidden copies to a list of recipients.
- **Automated Scheduling**: Includes systemd service and timer for daily scans at 2:00 AM.

## Installation

1. Clone the repository to `/opt/project/ip-address-scanner`.
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
