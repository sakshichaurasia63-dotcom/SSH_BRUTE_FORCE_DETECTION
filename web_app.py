from flask import Flask, render_template, jsonify , Response, request
from werkzeug.utils import secure_filename
import csv
import io
import os
from database import create_database, get_alerts, save_alerts
from log_reader import read_logs
from detector import detect_brute_force

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "web", "templates"),
    static_folder=os.path.join(BASE_DIR, "web", "static")
)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.jinja_env.cache.clear()

# Initialize database
create_database()

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/features")
def features():
    return render_template("index.html")


@app.route("/about")
def about():
    return render_template("index.html")


# Get security alerts from database
@app.route("/export-alerts")
def export_alerts():
    records = get_alerts()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "ID",
        "IP Address",
        "Failed Attempts",
        "Risk Level",
        "Alert",
        "Created At"
    ])

    for row in records:
        writer.writerow(row)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
            "attachment; filename=ssh_security_report.csv"
        }
    )

@app.route("/api/alerts")
def alerts():
    records = get_alerts()

    result = []

    for row in records:
        result.append({
            "id": row[0],
            "ip_address": row[1],
            "failed_attempts": row[2],
            "risk_level": row[3],
            "alert": row[4],
            "created_at": str(row[5])
        })

    return jsonify(result)


# Run detection on sample authentication logs
@app.route("/api/run-detection", methods=["POST"])
def run_detection():

    logs = read_logs()

    alerts_found = detect_brute_force(logs)

    if alerts_found:
        save_alerts(alerts_found)

    return jsonify({
        "status": "success",
        "message": "Detection completed",
        "alerts_detected": len(alerts_found),
        "alerts": alerts_found
    })
@app.route("/upload-log", methods=["POST"])
def upload_log():
    if "file" not in request.files:
        return jsonify({"error": "No file selected"}), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify({"error": "Please select a file"}), 400

    filename = secure_filename(file.filename)

    if not filename.lower().endswith(".log"):
        return jsonify({"error": "Only .log files are allowed"}), 400

    content = file.read(2 * 1024 * 1024 + 1)

    if len(content) > 2 * 1024 * 1024:
        return jsonify({"error": "File exceeds 2 MB limit"}), 400

    try:
        logs = content.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return jsonify({"error": "File must be UTF-8 text"}), 400

    alerts_found = detect_brute_force(logs)

    if alerts_found:
        save_alerts(alerts_found)

    return jsonify({
        "status": "success",
        "filename": filename,
        "lines_analysed": len(logs),
        "alerts_detected": len(alerts_found),
        "alerts": alerts_found
    })

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

if __name__ == "__main__":
    app.run(debug=True, port=5000)

