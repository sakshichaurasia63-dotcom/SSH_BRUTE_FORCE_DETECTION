
import sqlite3
from pathlib import Path

DB_FILE = Path(__file__).parent / "ssh_sentinel.db"


def create_database():

    connection = sqlite3.connect(DB_FILE)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            failed_attempts INTEGER,
            risk_level TEXT,
            alert TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()

    print("Database created successfully!")



def save_alerts(alerts):
    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()

    new_alerts = 0

    for alert in alerts:
        cursor.execute("""
            SELECT id FROM alerts
            WHERE ip_address = ?
            AND failed_attempts = ?
            AND risk_level = ?
            AND alert = ?
        """, (
            alert["ip_address"],
            alert["failed_attempts"],
            alert["risk_level"],
            alert["alert"]
        ))

        existing = cursor.fetchone()

        if existing is None:
            cursor.execute("""
                INSERT INTO alerts
                (ip_address, failed_attempts, risk_level, alert)
                VALUES (?, ?, ?, ?)
            """, (
                alert["ip_address"],
                alert["failed_attempts"],
                alert["risk_level"],
                alert["alert"]
            ))

            new_alerts += 1

    connection.commit()
    connection.close()

    print(f"{new_alerts} new alerts saved.")


    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()

    for alert in alerts:

        cursor.execute("""
            INSERT INTO alerts
            (ip_address, failed_attempts, risk_level, alert)
            VALUES (?, ?, ?, ?)
        """, (
            alert["ip_address"],
            alert["failed_attempts"],
            alert["risk_level"],
            alert["alert"]
        ))

    connection.commit()
    connection.close()

    print(f"{len(alerts)} alerts saved to database.")


def get_alerts():

    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()

    cursor.execute("SELECT * FROM alerts ORDER BY id DESC")

    results = cursor.fetchall()

    connection.close()

    return results


if __name__ == "__main__":
    create_database()
