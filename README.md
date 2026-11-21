# SSH Sentinel – SSH Brute-Force Detection System

**A Python-based security monitoring system that analyses SSH authentication logs and detects suspicious login activity.**

## About the Project

SSH Sentinel is a cybersecurity project designed to detect potential SSH brute-force login attempts by analysing authentication log files.

It identifies suspicious IP addresses based on repeated failed login attempts and generates security alerts with risk levels.

The project includes a Flask-based web dashboard where users can upload log files, run detection, monitor alerts, and export security reports.

## Features

- **SSH Log Analysis:** Reads and analyses SSH authentication logs.
- **Brute-Force Detection:** Identifies IP addresses with repeated failed login attempts.
- **Risk Classification:** Generates HIGH-risk alerts when the configured threshold is reached.
- **Interactive Dashboard:** Displays security metrics and detected alerts.
- **Log File Upload:** Allows users to upload `.log` files for analysis.
- **SQLite Database:** Stores detected security alerts.
- **CSV Export:** Exports security alerts as a CSV report.

## Technologies Used

- Python
- Flask
- SQLite
- HTML
- CSS
- JavaScript
- PowerShell
- Visual Studio Code

## Project Structure

```text
SSH BRUTE FORCE DETECTOR/
│
├── app.py
├── web_app.py
├── detector.py
├── database.py
├── log_parser.py
├── log_reader.py
│
├── data/
│   └── sample_auth.log
│
├── web/
│   ├── templates/
│   │   ├── index.html
│   │   └── dashboard.html
│   │
│   └── static/
│       ├── css/
│       │   └── style.css
│       └── js/
│
├── .venv/
└── README.md
```

## How It Works

1. The system reads SSH authentication log entries.
2. The log parser extracts relevant login information.
3. The detection module counts failed login attempts by IP address.
4. When an IP reaches the configured threshold of 5 failed attempts, the system generates a HIGH-risk alert.
5. Alerts are stored in the SQLite database.
6. Users can view the results on the web dashboard and export reports.

## Installation and Setup

### 1. Clone the Repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

### 2. Open the Project Folder

```bash
cd "SSH BRUTE FORCE DETECTOR"
```

### 3. Create a Virtual Environment

```bash
python -m venv .venv
```

### 4. Activate the Virtual Environment (Windows PowerShell)

```powershell
.\.venv\Scripts\Activate.ps1
```

### 5. Install Flask

```bash
pip install flask
```

### 6. Run the Web Application

```bash
python web_app.py
```

### 7. Open the Website

Open your browser and visit:

```text
http://127.0.0.1:5000/
```

If you start the application on another port, use that port in the browser address.

## Dashboard

The dashboard provides access to:

- Total security alerts
- Suspicious IP addresses
- Failed login attempts
- Log file analysis
- Security alert records
- CSV report export

## API Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/` | GET | Homepage |
| `/dashboard` | GET | Security dashboard |
| `/api/alerts` | GET | Retrieve security alerts |
| `/api/run-detection` | POST | Run detection on sample logs |
| `/upload-log` | POST | Upload and analyse a log file |
| `/export-alerts` | GET | Export alerts as CSV |

## Testing

The project can be tested using sample SSH authentication logs containing fictional IP addresses and login events.

Example:

```text
Failed password for admin from 203.0.113.10
Failed password for root from 203.0.113.10
```

The system analyses the entries and generates alerts when the configured failed-attempt threshold is reached.

## Future Improvements

- Real-time log monitoring
- Advanced anomaly detection
- IP reputation checking
- Email notifications for security alerts
- Improved analytics and visualisations
- User authentication and access control

## Disclaimer

SSH Sentinel is an educational cybersecurity project intended for defensive security monitoring and learning. Test it using sample logs or systems you are authorised to monitor.

## Author

**Developed as a Cybersecurity Project**

Project Name: SSH Sentinel  
Domain: Cybersecurity / Network Security  
Language: Python
