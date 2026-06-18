import ssl
import socket
import csv
import smtplib
import yaml
import os
from datetime import datetime, timezone
from urllib.parse import urlparse
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv()


def load_urls_from_yaml(file_path):
    with open(file_path, 'r') as file:
        data = yaml.safe_load(file)
        return data.get('urls', [])


def get_ssl_expiry(hostname, port=443):
    context = ssl.create_default_context()
    # Increased timeout to 10s to avoid false passes on slow hosts
    with socket.create_connection((hostname, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            # Parse with explicit UTC timezone so comparisons are always correct
            expiry_naive = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
            return expiry_naive.replace(tzinfo=timezone.utc)


def check_ssl_for_urls(urls, threshold_days=14):
    results = []
    seen = set()

    for url in urls:
        # Skip http:// URLs — they have no SSL cert to check
        parsed = urlparse(url)
        if parsed.scheme != 'https':
            print(f"⚠️  Skipping non-HTTPS URL: {url}")
            continue

        hostname = parsed.hostname
        if not hostname:
            print(f"⚠️  Could not parse hostname from: {url}")
            continue

        # De-duplicate: same hostname checked only once
        if hostname in seen:
            continue
        seen.add(hostname)

        try:
            expiry_date = get_ssl_expiry(hostname)
            now = datetime.now(timezone.utc)
            days_left = (expiry_date - now).days

            # Catch already-expired certs (days_left will be negative)
            if days_left < threshold_days:
                status = "🔴 EXPIRED" if days_left < 0 else "🟡 EXPIRING SOON"
                print(f"{status}: {hostname} — {days_left} days left")
                results.append({
                    'URL': url,
                    'Hostname': hostname,
                    'Expiry Date': expiry_date.strftime("%Y-%m-%d"),
                    'Days Left': days_left,
                    'Status': 'EXPIRED' if days_left < 0 else 'EXPIRING SOON'
                })
            else:
                print(f"✅ OK: {hostname} — {days_left} days left")

        except ssl.SSLCertVerificationError as e:
            print(f"🔴 SSL CERT INVALID for {url}: {e}")
            results.append({
                'URL': url,
                'Hostname': hostname,
                'Expiry Date': 'N/A',
                'Days Left': 'N/A',
                'Status': f'SSL ERROR: {e}'
            })
        except socket.timeout:
            print(f"⏱️  Timeout reaching {url} — skipped")
        except ConnectionRefusedError:
            print(f"🔴 Connection refused for {url}")
        except Exception as e:
            print(f"❌ Error checking {url}: {type(e).__name__}: {e}")

    return results


def write_to_csv(data, filename='ssl_expiry_report.csv'):
    fieldnames = ['URL', 'Hostname', 'Expiry Date', 'Days Left', 'Status']
    with open(filename, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)
    print(f"📄 Report saved to {filename}")


def send_email_with_attachment(sender, password, recipient, subject, body, attachment_path):
    msg = EmailMessage()
    msg['From'] = sender
    msg['To'] = recipient
    msg['Subject'] = subject
    msg.set_content(body)

    with open(attachment_path, 'rb') as f:
        file_data = f.read()
        msg.add_attachment(
            file_data,
            maintype='application',
            subtype='octet-stream',
            filename=attachment_path
        )

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(sender, password)
        smtp.send_message(msg)
        print("📧 Email sent successfully!")


# ----------------------------
# Main script
# ----------------------------
if __name__ == "__main__":
    THRESHOLD_DAYS = 14  # Warn if expiry is within 14 days (or already expired)

    urls = load_urls_from_yaml("url.yaml")
    print(f"\n🔍 Checking {len(urls)} URLs with a {THRESHOLD_DAYS}-day threshold...\n")

    expiring_urls = check_ssl_for_urls(urls, threshold_days=THRESHOLD_DAYS)

    if expiring_urls:
        report_file = "ssl_expiry_report.csv"
        write_to_csv(expiring_urls, report_file)

        print(f"\n⚠️  Found {len(expiring_urls)} domain(s) needing attention.\n")

        # EMAIL CONFIG
        SENDER_EMAIL = os.getenv("SENDER_EMAIL")
        SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
        RECEIVER_EMAIL = os.getenv("RECEIVER_EMAIL")

        send_email_with_attachment(
            sender=SENDER_EMAIL,
            password=SENDER_PASSWORD,
            recipient=RECEIVER_EMAIL,
            subject=f"SSL Certificate Expiry Alert 🚨 — {len(expiring_urls)} domain(s) affected",
            body=(
                f"Hi,\n\n"
                f"The SSL check found {len(expiring_urls)} domain(s) with certificates "
                f"expiring within {THRESHOLD_DAYS} days or already expired.\n\n"
                f"Please find the full report attached.\n\n"
                f"— SSL Monitor"
            ),
            attachment_path=report_file
        )
    else:
        print(f"\n✅ All certificates are valid for more than {THRESHOLD_DAYS} days.")