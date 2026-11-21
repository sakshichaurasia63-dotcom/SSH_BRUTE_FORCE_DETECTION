
from collections import defaultdict
from log_reader import read_logs
from log_parser import parse_log
from database import create_database, save_alerts

FAILED_LOGIN_THRESHOLD = 5


def detect_brute_force(logs):

    ip_attempts = defaultdict(int)

    for line in logs:
        event = parse_log(line)

        if event and event["status"] == "FAILED":
            ip_attempts[event["ip_address"]] += 1

    alerts = []

    for ip, attempts in ip_attempts.items():

        if attempts >= FAILED_LOGIN_THRESHOLD:

            alerts.append({
                "ip_address": ip,
                "failed_attempts": attempts,
                "risk_level": "HIGH",
                "alert": "Possible SSH brute-force activity"
            })

    return alerts


def main():

    print("=" * 50)
    print("       SSH SENTINEL SECURITY SYSTEM")
    print("=" * 50)

    create_database()

    logs = read_logs()
    alerts = detect_brute_force(logs)

    if alerts:
        print("\nSECURITY ALERTS DETECTED!\n")

        for alert in alerts:
            print("IP Address:", alert["ip_address"])
            print("Failed Attempts:", alert["failed_attempts"])
            print("Risk Level:", alert["risk_level"])
            print("Alert:", alert["alert"])
            print("-" * 40)

        save_alerts(alerts)

    else:
        print("\nNo suspicious activity detected.")

    print("\nDetection completed successfully!")


if __name__ == "__main__":
    main()
