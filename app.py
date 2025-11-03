from flask import Flask, request, render_template, jsonify
import asyncio
from scanner import scan_domains

app = Flask(__name__)

SCAN_RESULTS = []

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        file = request.files.get("domains_file")
        if not file:
            return render_template("index.html", error="Please upload a domains file.")
        domains = file.read().decode().splitlines()
        # Clean empty lines
        domains = [d.strip() for d in domains if d.strip()]

        global SCAN_RESULTS
        SCAN_RESULTS = asyncio.run(scan_domains(domains))

        return render_template("results.html", results=SCAN_RESULTS)

    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.json
    domains = data.get("domains", [])
    if not domains:
        return jsonify({"error": "No domains provided"}), 400

    results = asyncio.run(scan_domains(domains))
    return jsonify(results)


@app.route("/results/json")
def results_json():
    return jsonify(SCAN_RESULTS)


if __name__ == "__main__":
    app.run(debug=True) 