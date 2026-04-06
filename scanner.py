import subprocess
import os
import smtplib
import ipaddress
import csv
import time
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from collections import defaultdict
from dotenv import load_dotenv

# Load configuration from .env file
load_dotenv()

def ping_ip(ip):
    """
    Pings an IP address and returns True if reachable, False otherwise.
    Tries up to 3 times, stops immediately on first success.
    """
    ip_str = str(ip)
    for _ in range(3):
        try:
            # -c 1: send 1 packet
            # -W 1: wait 1 second for reply
            response = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip_str],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            if response.returncode == 0:
                return True
        except Exception:
            pass
    return False

def get_c_segment(ip):
    """
    Returns the C-class segment (first three octets) of an IP.
    """
    ip_str = str(ip)
    return ".".join(ip_str.split(".")[:3])

def run_scanner(ip_list, max_workers=50):
    results = {}
    c_segments = defaultdict(lambda: {"total": 0, "active": 0, "ips": []})

    print(f"Starting scan for {len(ip_list)} IPs using {max_workers} threads...")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Map ping_ip to the list of IPs
        ping_results = list(executor.map(ping_ip, ip_list))

    for ip, is_alive in zip(ip_list, ping_results):
        ip_str = str(ip)
        results[ip_str] = is_alive
        
        c_seg = get_c_segment(ip_str)
        c_segments[c_seg]["total"] += 1
        if is_alive:
            c_segments[c_seg]["active"] += 1
        c_segments[c_seg]["ips"].append((ip_str, is_alive))

    return results, c_segments

def parse_ips_from_file(file_path):
    """
    Parses IP addresses and CIDR notations from a file.
    """
    ip_list = []
    if not os.path.exists(file_path):
        return ip_list

    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                # Handle CIDR notation or single IP
                if "/" in line:
                    network = ipaddress.ip_network(line, strict=False)
                    # Scan ALL IPs in the network including network and broadcast addresses
                    ip_list.extend(list(network))
                else:
                    ip_list.append(ipaddress.ip_address(line))
            except ValueError as e:
                print(f"Skipping invalid IP/CIDR: {line} ({e})")
    
    return ip_list

def generate_report(c_segments):
    report = "IP Scanner Report - C-Segment Summary\n"
    report += "=" * 50 + "\n\n"
    
    # Categories
    no_active = []
    one_active = []
    multiple_active = []
    
    # Sort segments logically
    sorted_segments = sorted(c_segments.keys(), key=lambda x: [int(octet) for octet in x.split(".")])
    
    for c_seg in sorted_segments:
        data = c_segments[c_seg]
        active_count = data["active"]
        utilization = (active_count / data["total"]) * 100
        info = f"Segment: {c_seg}.0/24 | Total: {data['total']} | Active: {active_count} | Utilization: {utilization:.2f}%"
        
        if active_count == 0:
            no_active.append(info)
        elif active_count == 1:
            one_active.append(info)
        else:
            multiple_active.append(info)
    
    report += "### Category 1: No Active IPs (Empty Segments) ###\n"
    report += "\n".join(no_active) if no_active else "None"
    report += "\n\n"
    
    report += "### Category 2: Exactly One Active IP ###\n"
    report += "\n".join(one_active) if one_active else "None"
    report += "\n\n"
    
    report += "### Category 3: Two or More Active IPs ###\n"
    report += "\n".join(multiple_active) if multiple_active else "None"
    report += "\n"
    
    return report

def save_report_to_file(report, filename="scan_summary.txt"):
    try:
        with open(filename, "w") as f:
            f.write(report)
        print(f"Summary report saved to {filename}")
    except Exception as e:
        print(f"Failed to save report: {e}")

def save_to_csv(c_segments, filename="scan_results.csv"):
    try:
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["C-Segment", "Total IPs", "Active IPs", "Utilization (%)", "Category"])
            
            sorted_segments = sorted(c_segments.keys(), key=lambda x: [int(octet) for octet in x.split(".")])
            for c_seg in sorted_segments:
                data = c_segments[c_seg]
                active_count = data["active"]
                total_count = data["total"]
                utilization = (active_count / total_count) * 100
                
                category = "Empty"
                if active_count == 1:
                    category = "Single Active"
                elif active_count > 1:
                    category = "Multiple Active"
                
                writer.writerow([f"{c_seg}.0/24", total_count, active_count, f"{utilization:.2f}", category])
        print(f"CSV report saved to {filename}")
    except Exception as e:
        print(f"Failed to save CSV: {e}")

def is_ip_in_supernet(ip_str, supernet_str):
    """Check if an IP (C-segment) is within a supernet"""
    try:
        ip = ipaddress.ip_address(ip_str)
        supernet = ipaddress.ip_network(supernet_str, strict=False)
        return ip in supernet
    except:
        return False

def categorize_by_active_count(active_count):
    """Categorize C-segment based on number of active IPs"""
    active_count = int(active_count)
    if active_count == 0:
        return 'Empty'
    elif active_count == 1:
        return '1-Active'
    elif active_count == 2:
        return '2-Active'
    elif active_count == 3:
        return '3-Active'
    elif active_count == 4:
        return '4-Active'
    elif active_count == 5:
        return '5-Active'
    else:
        return 'Multiple'

def read_supernets(filename="ips.txt"):
    """Read supernets from ips.txt"""
    supernets = []
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line and '/' in line:
                    supernets.append(line)
    return supernets

def analyze_by_supernet(c_segments, supernets):
    """Analyze C-segments grouped by supernet"""
    results_by_supernet = defaultdict(lambda: defaultdict(int))
    results_by_supernet['__TOTAL__'] = defaultdict(int)
    
    categories = ['Empty', '1-Active', '2-Active', '3-Active', '4-Active', '5-Active', 'Multiple']
    
    for c_seg in c_segments:
        active_count = c_segments[c_seg]["active"]
        category = categorize_by_active_count(active_count)
        
        # c_seg is like "38.77.232", need to convert to IP address like "38.77.232.0"
        c_net = c_seg + ".0"
        found = False
        for supernet in supernets:
            if is_ip_in_supernet(c_net, supernet):
                results_by_supernet[supernet][category] += 1
                results_by_supernet['__TOTAL__'][category] += 1
                found = True
                break
        
        if not found and supernets:
            # If not found in any supernet, still count in total
            results_by_supernet['__TOTAL__'][category] += 1
    
    return results_by_supernet, categories

def generate_supernet_report(c_segments):
    """Generate report with supernet analysis"""
    supernets = read_supernets()
    
    if not supernets:
        return ""
    
    results_by_supernet, categories = analyze_by_supernet(c_segments, supernets)
    
    report = "\n" + "=" * 140 + "\n"
    report += "SUPERNET ANALYSIS - C-SEGMENT DISTRIBUTION BY ACTIVE IP COUNT\n"
    report += "=" * 140 + "\n\n"
    
    # Build table header
    header = f"{'Supernet':<20}"
    for cat in categories:
        header += f" {cat:<12}"
    header += f" {'Total':<6}"
    report += header + "\n"
    report += "-" * 140 + "\n"
    
    # Build table rows for each supernet
    for supernet in supernets:
        if supernet in results_by_supernet:
            stats = results_by_supernet[supernet]
            total = sum(stats.values())
            
            if total > 0:
                line = f"{supernet:<20}"
                for cat in categories:
                    count = stats[cat]
                    pct = (count / total * 100) if total > 0 else 0
                    line += f" {count:>2}({pct:>5.1f}%)"
                line += f" {total:>4}"
                report += line + "\n"
    
    report += "-" * 140 + "\n"
    
    # Overall statistics
    total_stats = results_by_supernet['__TOTAL__']
    total_all = sum(total_stats.values())
    if total_all > 0:
        line = f"{'TOTAL':<20}"
        for cat in categories:
            count = total_stats[cat]
            pct = (count / total_all * 100) if total_all > 0 else 0
            line += f" {count:>2}({pct:>5.1f}%)"
        line += f" {total_all:>4}"
        report += line + "\n"
    
    report += "=" * 140 + "\n"
    
    return report

def generate_html_supernet_report(c_segments):
    """Generate HTML report with supernet analysis"""
    supernets = read_supernets()
    if not supernets:
        return ""
    
    results_by_supernet, categories = analyze_by_supernet(c_segments, supernets)
    
    html = """
    <h3 style="font-family: Arial, sans-serif;">Supernet Analysis - C-Segment Distribution by Active IP Count</h3>
    <table border="1" cellpadding="8" style="border-collapse: collapse; font-family: Arial, sans-serif; font-size: 14px; width: 100%;">
        <thead>
            <tr style="background-color: #f2f2f2; text-align: left;">
                <th>Supernet</th>
    """
    for cat in categories:
        html += f"                <th>{cat}</th>\n"
    html += "                <th>Total</th>\n            </tr>\n        </thead>\n        <tbody>"
    
    for supernet in supernets:
        if supernet in results_by_supernet:
            stats = results_by_supernet[supernet]
            total = sum(stats.values())
            if total > 0:
                html += f"\n            <tr>\n                <td>{supernet}</td>"
                for cat in categories:
                    count = stats[cat]
                    pct = (count / total * 100) if total > 0 else 0
                    html += f"<td>{count} ({pct:.1f}%)</td>"
                html += f"<td><strong>{total}</strong></td>\n            </tr>"
    
    # TOTAL row
    total_stats = results_by_supernet['__TOTAL__']
    total_all = sum(total_stats.values())
    if total_all > 0:
        html += '\n            <tr style="background-color: #e6f7ff; font-weight: bold;">\n                <td>TOTAL</td>'
        for cat in categories:
            count = total_stats[cat]
            pct = (count / total_all * 100) if total_all > 0 else 0
            html += f"<td>{count} ({pct:.1f}%)</td>"
        html += f"<td>{total_all}</td>\n            </tr>"
    
    html += "\n        </tbody>\n    </table>"
    return html

def send_email(subject, body_text, body_html=None, attachment_path=None):
    smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    smtp_port = os.getenv("SMTP_PORT", "587")
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD") # Use Gmail App Password
    recipient = os.getenv("REPORT_RECIPIENT")
    bcc_list = os.getenv("BCC_LIST", "").split(",")
    bcc_list = [email.strip() for email in bcc_list if email.strip()]

    if not all([smtp_user, smtp_password, recipient]):
        print("Skipping email: Gmail credentials or recipient not configured in .env file.")
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = smtp_user
    msg["To"] = recipient
    
    # Attach plain text version
    msg.attach(MIMEText(body_text, "plain"))
    
    # Attach HTML version if provided
    if body_html:
        msg.attach(MIMEText(body_html, "html"))

    if attachment_path and os.path.exists(attachment_path):
        try:
            with open(attachment_path, "rb") as attachment:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f"attachment; filename={os.path.basename(attachment_path)}")
            msg.attach(part)
        except Exception as e:
            print(f"Failed to attach file: {e}")
    try:
        all_recipients = [recipient] + bcc_list
        with smtplib.SMTP(smtp_server, int(smtp_port)) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(msg, to_addrs=all_recipients)
        
        bcc_msg = f" (BCC: {', '.join(bcc_list)})" if bcc_list else ""
        print(f"Email sent successfully to {recipient}{bcc_msg} with attachment.")
    except Exception as e:
        print(f"Failed to send email: {e}")

if __name__ == "__main__":
    import sys
    start_time = time.time()
    
    input_file = sys.argv[1] if len(sys.argv) > 1 else "ips.txt"
    # Parse IPs and CIDRs from file
    ip_list = parse_ips_from_file(input_file)
    
    if not ip_list:
        print(f"No valid IPs found in {input_file}. Using default fallback for testing.")
        ip_list = [ipaddress.ip_address(ip) for ip in ["127.0.0.1", "8.8.8.8", "8.8.4.4"]]

    # Run scanner with multi-threading
    results, c_segments = run_scanner(ip_list, max_workers=100)
    report = generate_report(c_segments)
    
    end_time = time.time()
    duration = str(timedelta(seconds=int(end_time - start_time)))
    
    print("\n--- Scan Summary ---")
    active_segments = len([s for s in c_segments.values() if s["active"] > 0])
    print(f"Total C-segments scanned: {len(c_segments)}")
    print(f"Segments with active IPs: {active_segments}")
    print(f"Scan Duration: {duration}")
    
    save_report_to_file(report)
    save_to_csv(c_segments)
    
    # Generate reports
    supernet_report_text = generate_supernet_report(c_segments)
    supernet_report_html = generate_html_supernet_report(c_segments)
    
    # Create email body content
    summary_text = (
        f"IP Scan completed.\n"
        f"Total C-segments: {len(c_segments)}\n"
        f"Active segments: {active_segments}\n"
        f"Scan Duration: {duration}\n\n"
    )
    if supernet_report_text:
        summary_text += supernet_report_text
    summary_text += "\n\nPlease find the detailed CSV attachment for results."

    summary_html = f"""
    <html>
    <body style="font-family: Arial, sans-serif;">
        <h2>IP Scan Daily Report</h2>
        <p><strong>Scan Status:</strong> Completed</p>
        <ul>
            <li><strong>Total C-segments:</strong> {len(c_segments)}</li>
            <li><strong>Active segments:</strong> {active_segments}</li>
            <li><strong>Scan Duration:</strong> {duration}</li>
        </ul>
        {supernet_report_html}
        <p><br>Please find the detailed CSV attachment for results.</p>
    </body>
    </html>
    """
    
    send_email("IP Scanner Daily Report", summary_text, body_html=summary_html, attachment_path="scan_results.csv")
