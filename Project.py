import subprocess
import re
import smtplib
import ssl
import platform
import datetime
import sqlite3
from flask import Flask, render_template, jsonify
from email.message import EmailMessage

# Initialize Flask app
app = Flask(__name__)

# Patterns of suspicious activity to look for in logs
SUSPICIOUS_PATTERNS = [
    r"authentication failure",  # Failed login attempts
    r"failed password",  # Unsuccessful SSH logins
    r"root access granted",  # Someone got root (admin) access
    r"sudo\[.*\]:.*COMMAND=.*\b(passwd|su|chmod 777|chown root:|setcap|visudo|usermod|groupmod)\b",
    # Windows security events related to privilege escalation
    r"Event ID:\s+(4672|4720|4724|4728|4732|4756|5379)"
]

# Email Configuration (Replace with your own details)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
EMAIL_SENDER = "dskhaikh786@gmail.com"  # Your email address
EMAIL_PASSWORD = "nlohsycbhqpxksel"  # Use an app password for security
EMAIL_RECEIVER = "dskhaikh786@gmail.com"  # Recipient email (can be the same)

# Function to setup the SQLite database
def setup_database():
    """Creates the alerts database if it doesn't exist."""
    conn = sqlite3.connect("alerts.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_id TEXT,
            alert_msg TEXT
        )
    """)
    conn.commit()
    conn.close()

# Function to store alerts in the database
def store_alert_in_db(timestamp, event_id, alert_msg):
    """Saves alerts in the SQLite database."""
    conn = sqlite3.connect("alerts.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO alerts (timestamp, event_id, alert_msg) VALUES (?, ?, ?)", 
                   (timestamp, event_id, alert_msg))
    conn.commit()
    conn.close()


# Function to retrieve and display alerts from the database
def get_alerts():
    """Fetches all stored alerts from the database."""
    conn = sqlite3.connect("alerts.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC")
    alerts = cursor.fetchall()
    conn.close()
    return alerts

# Function to generate a daily security report
def generate_daily_report():
    """Generates and saves a daily security report from stored alerts."""
    conn = sqlite3.connect("alerts.db")
    cursor = conn.cursor()
    today_date = datetime.datetime.today().date()
    cursor.execute("SELECT * FROM alerts WHERE timestamp LIKE ? ORDER BY timestamp DESC", (f"{today_date}%",))
    alerts = cursor.fetchall()
    conn.close()

    report_filename = f"security_report_{today_date}.txt"
    with open(report_filename, "w") as report_file:
        report_file.write(f"Security Report - {today_date}\n\n")
        if alerts:
            for alert in alerts:
                report_file.write(f"ID: {alert[0]}\nTime: {alert[1]}\nEvent ID: {alert[2]}\nMessage: {alert[3]}\n{'-'*30}\n")
        else:
            report_file.write("No security alerts recorded today.\n")
    print(f"[+] Daily security report saved as {report_filename}")

# Flask route to display alerts in a web dashboard
@app.route('/')
def dashboard():
    alerts = get_alerts()
    return render_template('dashboard.html', alerts=alerts)

# Flask route to fetch alerts as JSON (for real-time updates)
@app.route('/alerts')
def fetch_alerts():
    alerts = get_alerts()
    return jsonify(alerts)

# Function to send an email when suspicious activity is detected
def send_email_alert(alert_msg):
    """Send an email notification with the alert message."""
    try:
        msg = EmailMessage()
        msg.set_content(alert_msg)
        msg["Subject"] = "🚨 Security Alert: Suspicious Activity Detected"
        msg["From"] = EMAIL_SENDER
        msg["To"] = EMAIL_RECEIVER

        # Secure connection with SMTP Server
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)

        print("[+] Email alert sent successfully!")
    except Exception as e:
        print(f"[-] Failed to send email: {e}")

# Function to get logs based on the operating system
def get_logs():
    """Fetch logs based on whether the system is Windows or Linux."""
    system = platform.system()
    if system == "Linux":
        return read_linux_logs()
    elif system == "Windows":
        return read_windows_logs()
    else:
        print("Unsupported OS")
        return []

# Fetch Linux system logs
def read_linux_logs():
    """Read logs from Linux journalctl."""
    try:
        output = subprocess.run(["journalctl", "--since", "10 minutes ago", "--no-pager"], capture_output=True, text=True)
        return output.stdout.splitlines()
    except Exception as e:
        print(f"Error reading Linux logs: {e}")
        return []

# Fetch Windows Event Logs
def read_windows_logs():
    """Read security event logs on Windows."""
    try:
        output = subprocess.run(["wevtutil", "qe", "Security", "/c:50", "/rd:true", "/f:text"], capture_output=True, text=True, errors="ignore")
        logs = output.stdout.split("\n")

        filtered_logs = []
        temp_log = ""

        for line in logs:
            if "Event ID:" in line and re.search(r"4672|4720|4724|4728|4732|4756|5379", line):
                if temp_log:
                    filtered_logs.append(temp_log.strip())
                temp_log = line
            elif temp_log:
                temp_log += f"\n{line}"

        if temp_log:
            filtered_logs.append(temp_log.strip())

        return filtered_logs
    except Exception as e:
        print(f"Error reading Windows logs: {e}")
        return []

LAST_DETECTED_EVENTS = {}

def check_logs():
    """Check logs for suspicious activity and avoid duplicate alerts."""
    logs = get_logs()
    global LAST_DETECTED_EVENTS

    for log_entry in logs:
        event_id_match = re.search(r"Event ID:\s+(\d+)", log_entry)

        if event_id_match:
            event_id = event_id_match.group(1)
            current_time = datetime.datetime.now()

            if event_id in LAST_DETECTED_EVENTS:
                last_alert_time = LAST_DETECTED_EVENTS[event_id]
                time_diff = (current_time - last_alert_time).total_seconds()

                if time_diff < 600:  # Avoid duplicate alerts within 10 minutes
                    continue

            LAST_DETECTED_EVENTS[event_id] = current_time

        timestamp = current_time.strftime("%Y-%m-%d %H:%M:%S")
        alert_msg = f"[{timestamp}] [ALERT] Suspicious activity detected:\n{log_entry.strip()}\n"

        print(alert_msg)  # Show alert in console
        store_alert_in_db(timestamp, event_id, alert_msg)  # Store in database
        send_email_alert(alert_msg)

if __name__ == "__main__":
    setup_database()  # Ensure database exists
    check_logs()
    generate_daily_report()
    app.run(host='0.0.0.0', port=5000, debug=True)
