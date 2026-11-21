
import re
from log_reader import read_logs


def parse_log(line):

    ip_match = re.search(r'\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\b', line)

    if not ip_match:
        return None

    ip_address = ip_match.group(1)

    failed_match = re.search(
        r'Failed password for (\S+) from',
        line
    )

    accepted_match = re.search(
        r'Accepted (?:password|publickey) for (\S+) from',
        line
    )

    invalid_match = re.search(
        r'Invalid user (\S+) from',
        line
    )

    if failed_match:
        username = failed_match.group(1)
        status = "FAILED"

    elif accepted_match:
        username = accepted_match.group(1)
        status = "SUCCESS"

    elif invalid_match:
        username = invalid_match.group(1)
        status = "INVALID_USER"

    else:
        return None

    timestamp = " ".join(line.split()[:3])

    return {
        "timestamp": timestamp,
        "username": username,
        "ip_address": ip_address,
        "status": status
    }


def main():

    print("=" * 60)
    print("          SSH SENTINEL - LOG PARSER")
    print("=" * 60)

    logs = read_logs()
    parsed_logs = []

    for log in logs:
        result = parse_log(log)

        if result:
            parsed_logs.append(result)

    print(f"\nTotal parsed events: {len(parsed_logs)}")

    for event in parsed_logs:
        print("\n------------------------------")
        print("Timestamp:", event["timestamp"])
        print("Username:", event["username"])
        print("IP Address:", event["ip_address"])
        print("Status:", event["status"])

    print("\nLOG PARSING COMPLETED")


if __name__ == "__main__":
    main()
