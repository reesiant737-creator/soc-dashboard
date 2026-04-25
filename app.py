import os
import json
import uuid
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, session
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

load_dotenv()

from modules.nmap_parser import parse_nmap_xml, parse_nmap_text
from modules.mitre_attack import map_ports_to_techniques, build_attack_chain
from modules.cve_lookup import enrich_hosts_with_cves
from modules.alert_correlator import correlate_alerts
from modules.graph_builder import build_attack_graph
from modules.wireshark_parser import parse_pcap_json
from modules.pcap_parser import parse_pcap_bytes
from modules.report_exporter import export_json_siem, export_pdf_report
from modules.ai_analyst import analyze_scan_results, ask_analyst_question, generate_threat_hunt_queries

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "soc-dashboard-dev-key-change-in-prod")
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["EXPORT_FOLDER"] = "exports"
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

_session_store: dict = {}


def get_session_data() -> dict:
    sid = session.get("sid")
    if sid and sid in _session_store:
        return _session_store[sid]
    return {}


def set_session_data(data: dict):
    sid = session.get("sid")
    if not sid:
        sid = str(uuid.uuid4())
        session["sid"] = sid
    _session_store[sid] = data


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/upload/nmap", methods=["POST"])
def upload_nmap():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    f = request.files["file"]
    content = f.read().decode("utf-8", errors="replace")
    filename = secure_filename(f.filename or "upload")

    if filename.endswith(".xml") or content.strip().startswith("<?xml") or content.strip().startswith("<nmaprun"):
        scan_data = parse_nmap_xml(content)
    else:
        scan_data = parse_nmap_text(content)

    if scan_data.get("error"):
        return jsonify({"error": scan_data["error"]}), 400

    hosts = scan_data.get("hosts", [])
    hosts = enrich_hosts_with_cves(hosts)
    scan_data["hosts"] = hosts

    techniques = build_attack_chain(hosts)
    alert_result = correlate_alerts(hosts)
    alerts = alert_result["alerts"]
    graph = build_attack_graph(hosts, techniques, alerts)

    payload = {
        "scan_data": scan_data,
        "techniques": techniques,
        "alerts": alerts,
        "alert_summary": alert_result,
        "graph": graph,
        "ai_report": "",
        "wireshark": {},
    }
    set_session_data(payload)

    return jsonify({
        "success": True,
        "hosts": hosts,
        "techniques": techniques,
        "alerts": alerts,
        "alert_summary": alert_result,
        "graph": graph,
        "scan_meta": {
            "total_hosts": scan_data.get("total_hosts", 0),
            "scan_time": scan_data.get("scan_time", ""),
        }
    })


@app.route("/api/upload/wireshark", methods=["POST"])
def upload_wireshark():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    f = request.files["file"]
    filename = secure_filename(f.filename or "upload")
    raw = f.read()

    # Route to correct parser based on file type
    if filename.endswith((".pcap", ".pcapng", ".cap")):
        result = parse_pcap_bytes(raw)
    else:
        result = parse_pcap_json(raw.decode("utf-8", errors="replace"))

    if result.get("error"):
        return jsonify({"error": result["error"]}), 400

    data = get_session_data()
    data["wireshark"] = result
    set_session_data(data)

    return jsonify(result)


@app.route("/api/load/sample", methods=["POST"])
def load_sample():
    """Load the bundled sample files for demo purposes."""
    sample_type = request.get_json(silent=True) or {}
    kind = sample_type.get("type", "wireshark")

    base = os.path.dirname(os.path.abspath(__file__))

    if kind == "nmap":
        path = os.path.join(base, "sample_scan.xml")
        if not os.path.exists(path):
            return jsonify({"error": "sample_scan.xml not found"}), 404
        with open(path, "r") as f:
            content = f.read()
        scan_data = parse_nmap_xml(content)
        hosts = enrich_hosts_with_cves(scan_data.get("hosts", []))
        scan_data["hosts"] = hosts
        techniques = build_attack_chain(hosts)
        alert_result = correlate_alerts(hosts)
        alerts = alert_result["alerts"]
        graph = build_attack_graph(hosts, techniques, alerts)
        payload = {"scan_data": scan_data, "techniques": techniques, "alerts": alerts,
                   "alert_summary": alert_result, "graph": graph, "ai_report": "", "wireshark": {}}
        set_session_data(payload)
        return jsonify({"success": True, "hosts": hosts, "techniques": techniques,
                        "alerts": alerts, "alert_summary": alert_result, "graph": graph,
                        "scan_meta": {"total_hosts": scan_data.get("total_hosts", 0),
                                      "scan_time": scan_data.get("scan_time", "")}})

    if kind == "wireshark":
        path = os.path.join(base, "sample_capture.json")
        if not os.path.exists(path):
            return jsonify({"error": "sample_capture.json not found"}), 404
        with open(path, "r") as f:
            content = f.read()
        result = parse_pcap_json(content)
        data = get_session_data()
        data["wireshark"] = result
        set_session_data(data)
        return jsonify(result)

    return jsonify({"error": "unknown sample type"}), 400


@app.route("/api/ai/analyze", methods=["POST"])
def ai_analyze():
    data = get_session_data()
    if not data:
        return jsonify({"error": "No scan data loaded. Upload a scan first."}), 400

    if not os.getenv("ANTHROPIC_API_KEY"):
        return jsonify({"error": "ANTHROPIC_API_KEY not set in .env file"}), 400

    try:
        report = analyze_scan_results(
            data["scan_data"], data["alerts"], data["techniques"]
        )
        data["ai_report"] = report
        set_session_data(data)
        return jsonify({"report": report})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ai/ask", methods=["POST"])
def ai_ask():
    body = request.get_json()
    question = body.get("question", "").strip()
    if not question:
        return jsonify({"error": "No question provided"}), 400

    if not os.getenv("ANTHROPIC_API_KEY"):
        return jsonify({"error": "ANTHROPIC_API_KEY not set in .env file"}), 400

    data = get_session_data()
    context = {
        "hosts": data.get("scan_data", {}).get("hosts", []),
        "alerts": data.get("alerts", []),
        "techniques": data.get("techniques", []),
    }

    try:
        answer = ask_analyst_question(question, context)
        return jsonify({"answer": answer})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ai/hunt", methods=["POST"])
def ai_hunt():
    data = get_session_data()
    if not data:
        return jsonify({"error": "No scan data loaded"}), 400

    if not os.getenv("ANTHROPIC_API_KEY"):
        return jsonify({"error": "ANTHROPIC_API_KEY not set in .env file"}), 400

    try:
        queries = generate_threat_hunt_queries(
            data.get("scan_data", {}).get("hosts", []),
            data.get("techniques", [])
        )
        return jsonify({"queries": queries})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/export/json", methods=["GET"])
def export_json():
    data = get_session_data()
    if not data:
        return jsonify({"error": "No scan data"}), 400

    siem_json = export_json_siem(
        data.get("scan_data", {}),
        data.get("alerts", []),
        data.get("techniques", []),
        data.get("ai_report", ""),
    )
    filename = f"soc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    path = os.path.join(app.config["EXPORT_FOLDER"], filename)
    with open(path, "w") as fh:
        fh.write(siem_json)

    return send_file(path, as_attachment=True, download_name=filename, mimetype="application/json")


@app.route("/api/export/pdf", methods=["GET"])
def export_pdf():
    data = get_session_data()
    if not data:
        return jsonify({"error": "No scan data"}), 400

    filename = f"soc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    path = os.path.join(app.config["EXPORT_FOLDER"], filename)

    try:
        export_pdf_report(
            data.get("scan_data", {}),
            data.get("alerts", []),
            data.get("techniques", []),
            data.get("ai_report", "No AI analysis run yet."),
            path,
        )
        return send_file(path, as_attachment=True, download_name=filename, mimetype="application/pdf")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/session/clear", methods=["POST"])
def clear_session():
    sid = session.get("sid")
    if sid and sid in _session_store:
        del _session_store[sid]
    return jsonify({"success": True})


if __name__ == "__main__":
    os.makedirs("uploads", exist_ok=True)
    os.makedirs("exports", exist_ok=True)
    app.run(debug=False, host="0.0.0.0", port=5000)
