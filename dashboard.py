from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO
import pandas as pd
import os
from collections import Counter
import plotly.express as px
import matplotlib.pyplot as plt
import io
import base64

# Initialize Flask app and SocketIO
app = Flask(__name__)
socketio = SocketIO(app)

# File paths
SSH_LOG_FILE = "audits.log"
HTTP_LOG_FILE = "http_audits.log"

# Routes
@app.route("/")
def index():
    return render_template("dashboard.html")

@app.route("/logs")
def get_logs():
    # Load SSH logs
    ssh_logs = []
    if os.path.exists(SSH_LOG_FILE):
        with open(SSH_LOG_FILE, "r") as f:
            ssh_logs = f.readlines()

    # Load HTTP logs
    http_logs = []
    if os.path.exists(HTTP_LOG_FILE):
        with open(HTTP_LOG_FILE, "r") as f:
            http_logs = f.readlines()

    # Combine and sort logs
    all_logs = ssh_logs + http_logs
    return jsonify({"logs": all_logs[-100:]})  # Return the latest 100 logs

@app.route("/stats")
def get_stats():
    # Analyze logs
    if os.path.exists(SSH_LOG_FILE):
        ssh_df = pd.read_csv(SSH_LOG_FILE, sep=",", names=["IP", "Username", "Password"], engine="python")
    else:
        ssh_df = pd.DataFrame(columns=["IP", "Username", "Password"])

    if os.path.exists(HTTP_LOG_FILE):
        http_df = pd.read_csv(HTTP_LOG_FILE, sep=",", names=["IP", "Details"], engine="python")
    else:
        http_df = pd.DataFrame(columns=["IP", "Details"])

    # Total attempts
    total_attempts = len(ssh_df) + len(http_df)

    # IP breakdown
    ip_counts = Counter(ssh_df["IP"].tolist() + http_df["IP"].tolist())

    # Generate Plotly pie chart for IP breakdown
    fig = px.pie(names=list(ip_counts.keys()), values=list(ip_counts.values()), title="Attempts by IP")
    graph_html = fig.to_html(full_html=False)

    # Generate Matplotlib bar chart for attempts by IP
    ip_bar_fig = plt.figure(figsize=(8, 6))
    plt.bar(ip_counts.keys(), ip_counts.values(), color='skyblue')
    plt.xlabel('IP Address')
    plt.ylabel('Attempts')
    plt.title('Attempts by IP (Bar Chart)')
    plt.xticks(rotation=45, ha="right")
    
    # Convert Matplotlib figure to PNG and then to base64 for embedding
    img_io = io.BytesIO()
    ip_bar_fig.savefig(img_io, format='png')
    img_io.seek(0)
    img_base64 = base64.b64encode(img_io.getvalue()).decode('utf8')
    bar_chart_html = f'<img src="data:image/png;base64,{img_base64}" alt="Bar Chart">'

    # Generate Matplotlib histogram for password attempts (successful vs failed)
    password_attempts = ssh_df["Password"].value_counts()
    hist_fig = plt.figure(figsize=(8, 6))
    plt.hist(password_attempts.values, bins=10, color='lightgreen')
    plt.xlabel('Number of Attempts')
    plt.ylabel('Frequency')
    plt.title('Password Attempt Frequency (Histogram)')
    
    # Convert histogram to PNG and then to base64
    img_io = io.BytesIO()
    hist_fig.savefig(img_io, format='png')
    img_io.seek(0)
    img_base64_hist = base64.b64encode(img_io.getvalue()).decode('utf8')
    hist_chart_html = f'<img src="data:image/png;base64,{img_base64_hist}" alt="Histogram">'

    return jsonify({
        "total_attempts": total_attempts,
        "ip_counts": dict(ip_counts),
        "graph_html": graph_html,
        "bar_chart_html": bar_chart_html,
        "hist_chart_html": hist_chart_html,
    })

# WebSocket for real-time updates
@socketio.on("connect")
def handle_connect():
    print("Client connected!")

if __name__ == "__main__":
    # Run on all interfaces (0.0.0.0) and default port 5000 for public access
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
