from flask import Flask, render_template, request, send_file
import requests, csv, os, json
from dotenv import load_dotenv
from fpdf import FPDF

load_dotenv()
app = Flask(__name__)

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")
VT_KEY = os.getenv("VT_KEY")
CACHE_FILE = "ip_cache.json"

if os.path.exists(CACHE_FILE):
    with open(CACHE_FILE, "r") as f:
        cache = json.load(f)
else:
    cache = {}

def get_ipinfo(ip):
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json").json()
        org = r.get("org", "Unknown")
        city = r.get("city", "Unknown")
        country = r.get("country", "Unknown")
        verdict = "Suspicious (Cloud)" if any(x in org for x in ["Amazon", "Google", "Azure", "DigitalOcean"]) else "Clean"
        return org, f"{city}, {country}", verdict
    except Exception as e:
        print("IPInfo Error:", e)
        return "Unknown", "Unknown", "Error"

def get_abuse_score(ip):
    if not ABUSEIPDB_KEY:
        return "N/A"
    try:
        headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
        r = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", headers=headers)
        return r.json()["data"]["abuseConfidenceScore"]
    except:
        return "N/A"

def get_vt_score(ip):
    if not VT_KEY:
        return "N/A"
    try:
        headers = {"x-apikey": VT_KEY}
        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers)
        return r.json()["data"]["attributes"]["last_analysis_stats"]["malicious"]
    except:
        return "N/A"

@app.route("/", methods=["GET", "POST"])
def index():
    data = None
    if request.method == "POST":
        ip = request.form["ip"].strip()
        if ip in cache:
            d = cache[ip]
            d["cached"] = True
        else:
            org, loc, verdict = get_ipinfo(ip)
            abuse = get_abuse_score(ip)
            vt = get_vt_score(ip)
            d = {
                "ip": ip,
                "org": org,
                "location": loc,
                "verdict": verdict,
                "abuse_score": abuse,
                "vt_malicious": vt,
                "cached": False,
                "advice": "Monitor and enrich (DNS, whois). Consider blocking if confirmed malicious.",
            }
            cache[ip] = d
            with open(CACHE_FILE, "w") as f:
                json.dump(cache, f, indent=2)
            with open("report.csv", "a", newline="") as f:
                csv.writer(f).writerow(d.values())

        d["color"] = "red" if "Suspicious" in d["verdict"] else "green"
        data = d
    return render_template("index.html", data=data)

@app.route("/download_csv")
def download_csv():
    return send_file("report.csv", as_attachment=True)

@app.route("/download_pdf/<ip>")
def download_pdf(ip):
    if ip not in cache:
        return "IP not found", 404
    data = cache[ip]
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(200, 10, f"SOC-Eye Report for {data['ip']}", ln=True, align="C")
    pdf.set_font("Arial", "", 12)
    for k, v in data.items():
        pdf.cell(200, 10, f"{k.capitalize()}: {v}", ln=True)
    filename = f"report_{ip}.pdf"
    pdf.output(filename)
    return send_file(filename, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
