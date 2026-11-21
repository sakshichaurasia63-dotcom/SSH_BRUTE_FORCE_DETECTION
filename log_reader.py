
from pathlib import Path

# Locate the SSH authentication log
LOG_FILE = Path(__file__).parent / "data" / "sample_auth.log"


def read_logs():
    """Read SSH authentication logs."""

    if not LOG_FILE.exists():
        print("Error: Log file not found!")
        return []

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        logs = file.readlines()

    return logs


def main():
    print("=" * 50)
    print("       SSH SENTINEL - LOG READER")
    print("=" * 50)

    logs = read_logs()

    print(f"\nTotal log entries: {len(logs)}")
    print("\nAuthentication Logs:\n")

    for log in logs:
        print(log.strip())
        

    print("\n" + "=" * 50)
    print("LOG READING COMPLETED")
    print("=" * 50)


if __name__ == "__main__":
    main()

