import ssl
import socket
import csv
import smtplib
import yaml
from datetime import datetime
from urllib.parse import urlparse
from email.message import EmailMessage

def load_urls_from_yaml(file_path):
    with open(file_path, 'r') as file:
        data = yaml.safe_load(file)
        return data.get('urls', [])

def get_ssl_expiry(hostname, port=443):
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            return datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")

def check_ssl_for_urls(urls, threshold_days=12):
    expiring_soon = []

    for url in urls:
        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.path
        try:
            expiry_date = get_ssl_expiry(hostname)
            days_left = (expiry_date - datetime.utcnow()).days
            if days_left <= threshold_days:
                expiring_soon.append({
                    'URL': url,
                    'Expiry Date': expiry_date.strftime("%Y-%m-%d"),
                    'Days Left': days_left
                })
        except Exception as e:
            print(f"❌ Error checking {url}: {e}")
    
    return expiring_soon

def write_to_csv(data, filename='ssl_expiry_report.csv'):
    with open(filename, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=['URL', 'Expiry Date', 'Days Left'])
        writer.writeheader()
        writer.writerows(data)

def send_email_with_attachment(sender, password, recipient, subject, body, attachment_path):
    msg = EmailMessage()
    msg['From'] = sender
    msg['To'] = recipient
    msg['Subject'] = subject
    msg.set_content(body)

    with open(attachment_path, 'rb') as f:
        file_data = f.read()
        msg.add_attachment(file_data, maintype='application', subtype='octet-stream', filename=attachment_path)

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(sender, password)
        smtp.send_message(msg)
        print("📧 Email sent successfully!")

# ----------------------------
# Main script
# ----------------------------
if __name__ == "__main__":
    urls = load_urls_from_yaml("url.yaml")
    expiring_urls = check_ssl_for_urls(urls)

    if expiring_urls:
        report_file = "ssl_expiry_report.csv"
        write_to_csv(expiring_urls, report_file)

        # EMAIL CONFIG - Update these!
        SENDER_EMAIL = "neerajsalehittal3235@gmail.com"
        SENDER_PASSWORD = "kbck eqnp bvvv kpom"
        RECEIVER_EMAIL = "neeraj@certifyme.cc"

        send_email_with_attachment(
            sender=SENDER_EMAIL,
            password=SENDER_PASSWORD,
            recipient=RECEIVER_EMAIL,
            subject="SSL Certificate Expiry Alert 🚨",
            body="Please find attached the list of domains with SSL certificates expiring in 12 days or less.",
            attachment_path=report_file
        )
    else:
        print("✅ All certificates are valid for more than 12 days.")
