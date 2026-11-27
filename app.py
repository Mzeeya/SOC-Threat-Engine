#!/usr/bin/env python3
"""
SOC Threat Engine - Interactive EDR Dashboard
"""
import csv, io, time, os, threading, hashlib, random, getpass, socket, statistics
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from ipaddress import ip_address
from flask import Flask, jsonify, render_template, request, send_file
import requests
from dotenv import load_dotenv
load_dotenv()

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

# --- CONFIGURATION ---
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")

# --- MILO AI ASSISTANT CONFIGURATION ---
# Milo answers using a real LLM instead of keyword matching, so it can hold
# an open-ended conversation — dashboard questions, general cybersecurity or
# networking questions, or anything else — rather than only the handful of
# phrases a regex could recognize.
#
# Uses Groq's free tier (https://console.groq.com) — no payment required,
# just a free account and an API key, and it's fast (purpose-built inference
# hardware, not a CPU running an 8B model) and doesn't have the "spends its
# whole budget reasoning and never answers" problem local qwen3 hit.
#
# Setup:
#   1. Sign up free at https://console.groq.com and create an API key.
#   2. Set it as an environment variable before running the app (don't paste
#      a real key directly into this file, especially if this project is
#      ever pushed to GitHub):
#        Windows PowerShell:  $env:GROQ_API_KEY = "gsk_..."
#        macOS/Linux:          export GROQ_API_KEY="gsk_..."
# If GROQ_MODEL ever errors as "model not found", Groq occasionally retires
# older hosted models — check the current list at
# https://console.groq.com/docs/models and update the default below.
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
SCAN_DIRECTORY = os.path.join(os.path.expanduser("~"), "Downloads")

# ⚠️ DEMO MODE: Set to True to simulate a malware hit on any downloaded file.
# Set to False for real VirusTotal API scanning.
DEMO_MODE = True

realtime_alerts = []
scanned_files = set()

# --- ALERT LIFECYCLE / CASE MANAGEMENT ---
ALERT_STATES = ["new", "acknowledged", "in_progress", "resolved"]

def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _add_history(alert, state, note=None):
    alert["state"] = state
    alert.setdefault("history", []).append({
        "state": state,
        "time": _now(),
        "note": (note or "").strip() or f"Marked as {state.replace('_', ' ')}."
    })

# Holds the most recent analysis so /report/pdf can regenerate it on demand
last_analysis = {"findings": [], "stats": {}, "geo": [], "generated": None}

# --- MITRE ATT&CK MAPPING ---
# Maps each detection rule to its real-world ATT&CK technique for reporting.
MITRE_MAP = {
    "Brute Force": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "Password Spraying": {"id": "T1110.003", "name": "Password Spraying", "tactic": "Credential Access"},
    "Port Scan": {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
}

# --- BACKGROUND MALWARE SCANNER ---
def scan_folder_for_malware():
    print(f"🛡️  Monitoring Folder: {SCAN_DIRECTORY}")

    try:
        for existing_file in os.listdir(SCAN_DIRECTORY):
            if os.path.isfile(os.path.join(SCAN_DIRECTORY, existing_file)):
                scanned_files.add(existing_file)
        print(f"✅ Ignored {len(scanned_files)} existing files. Waiting for new downloads...\n")
    except Exception as e:
        print(f"Error reading directory: {e}")

    while True:
        try:
            for filename in os.listdir(SCAN_DIRECTORY):
                filepath = os.path.join(SCAN_DIRECTORY, filename)

                if os.path.isfile(filepath) and filename not in scanned_files:
                    if filename.endswith(('.tmp', '.crdownload', '.part', '.py', '.html', '.db')):
                        scanned_files.add(filename)
                        continue

                    print(f"\n[!] New file detected: {filename}")
                    time.sleep(2)

                    try:
                        if DEMO_MODE:
                            print(f"[*] DEMO MODE ACTIVE - Simulating VirusTotal Detection...")
                            malicious_count = 55
                        else:
                            hasher = hashlib.sha256()
                            with open(filepath, 'rb') as f:
                                hasher.update(f.read())
                            file_hash = hasher.hexdigest()

                            print(f"[*] Checking VirusTotal API...")
                            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
                            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
                            response = requests.get(url, headers=headers)

                            if response.status_code == 200:
                                data = response.json()
                                stats = data['data']['attributes']['last_analysis_stats']
                                malicious_count = stats.get('malicious', 0)
                            else:
                                malicious_count = 0

                        if malicious_count > 0:
                            alert_id = f"ALT-{int(time.time())}"
                            opened = _now()
                            alert = {
                                "id": alert_id,
                                "time": opened,
                                "file": filename,
                                "path": filepath,
                                "hostname": socket.gethostname(),
                                "username": getpass.getuser(),
                                "threat": f"VirusTotal: {malicious_count}/70 engines flagged this file.",
                                "severity": "CRITICAL" if malicious_count > 10 else "HIGH",
                                "status": "Quarantined (Simulated)",
                                "state": "new",
                                "history": [{"state": "new", "time": opened, "note": "Alert generated by background scanner."}],
                            }
                            realtime_alerts.append(alert)
                            print(f"🚨 [CRITICAL] Alert Triggered for {filename}!")
                        else:
                            print(f"✅ {filename} is clean (0 detections).")

                    except Exception as e:
                        print(f"❌ Error scanning file: {e}")

                    scanned_files.add(filename)

        except Exception as e:
            pass
        time.sleep(3)

#threading.Thread(target=scan_folder_for_malware, daemon=True).start()

# --- FORENSIC TELEMETRY SIMULATOR ---
def generate_forensics(alert):
    executed = random.choice([True, False])
    forensics = {
        "host_info": {
            "hostname": alert["hostname"], "username": alert["username"],
            "os": "Windows 11 Pro (22H2)", "ip_address": "192.168.1.105 (Internal)"
        },
        "file_info": {
            "filename": alert["file"], "file_path": alert["path"],
            "file_type": "Win32 Executable (.exe)" if alert["file"].endswith(".exe") else "Unknown Binary",
            "action_taken": alert["status"], "was_executed": executed
        },
        "process_tree": [
            {"process": "explorer.exe", "pid": 1024, "parent": "None"},
            {"process": alert["file"], "pid": 4492, "parent": "explorer.exe"}
        ],
        "network_activity": [], "powershell_child": None
    }
    if executed:
        if random.choice([True, False]):
            forensics["powershell_child"] = {
                "command": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand [Base64 Obfuscated Payload]",
                "pid": 5104
            }
            forensics["process_tree"].append({"process": "powershell.exe", "pid": 5104, "parent": alert["file"]})
        if random.choice([True, False]):
            forensics["network_activity"].append({
                "destination_ip": f"185.15.{random.randint(10,250)}.{random.randint(10,250)}",
                "port": 443, "protocol": "TCP (HTTPS)", "bytes_sent": "45 KB", "bytes_received": "1.2 MB"
            })
    return forensics

def build_wazuh_forensics(alert):
    """Builds the investigation view from a REAL Wazuh alert's actual data —
    no random process trees or invented network activity. Used instead of
    generate_forensics() for any alert that genuinely came from Wazuh, since
    showing fabricated forensic details for a real detection would be
    actively misleading."""
    raw = alert.get("raw") or {}
    rule = raw.get("rule") or {}
    agent = raw.get("agent") or {}
    win = ((raw.get("data") or {}).get("win")) or {}
    eventdata = win.get("eventdata") or {}
    system = win.get("system") or {}
    mitre = rule.get("mitre") or {}

    return {
        "host_info": {
            "hostname": agent.get("name", alert.get("hostname", "Unknown Host")),
            "username": eventdata.get("targetUserName") or eventdata.get("user") or alert.get("username", "Unknown"),
            "os": "See Wazuh agent record for OS details",
            "ip_address": agent.get("ip", eventdata.get("ipAddress", "Unknown")),
        },
        "file_info": {
            "filename": f"Wazuh rule {rule.get('id', '-')}",
            "file_path": rule.get("description", "-"),
            "file_type": "N/A — SIEM rule detection, not a file-based alert",
            "action_taken": "Logged by Wazuh", "was_executed": None,
        },
        "process_tree": [], "network_activity": [], "powershell_child": None,
        "wazuh_detail": {
            "rule_id": rule.get("id", "-"), "rule_description": rule.get("description", "-"),
            "rule_level": rule.get("level", "-"),
            "mitre_ids": mitre.get("id") or [], "mitre_techniques": mitre.get("technique") or [],
            "event_channel": system.get("channel", "-"), "event_id": system.get("eventID", "-"),
            "raw_eventdata": eventdata,
        },
    }

# --- LOG ANALYSIS LOGIC ---
REQUIRED_COLUMNS = {"timestamp", "source_ip", "event_type", "username", "status", "destination_port"}
def validate_row(row, line_no):
    try: datetime.fromisoformat(row["timestamp"])
    except: return False, f"Line {line_no}: invalid timestamp"
    try: ip_address(row["source_ip"])
    except: return False, f"Line {line_no}: invalid source_ip"
    try:
        port = int(row["destination_port"])
        if port < 0 or port > 65535: raise ValueError
    except: return False, f"Line {line_no}: invalid destination_port"
    return True, None

def load_logs_from_stream(stream):
    warnings, rows = [], []
    reader = csv.DictReader(stream)
    for line_no, row in enumerate(reader, start=2):
        row = {k: (v.strip() if isinstance(v, str) else v) for k, v in row.items()}
        ok, msg = validate_row(row, line_no)
        if ok: rows.append(row)
        else: warnings.append(msg)
    return rows, warnings

def detect_anomalies(rows, z_threshold=2.5):
    """
    Behavioral anomaly detection. Unlike the fixed-threshold rules above
    (e.g. '5 failed logins = alert'), this compares each source IP's activity
    against the statistical baseline formed by every OTHER IP seen in this
    log batch — a population z-score. An IP is flagged when one of its
    metrics (failed-login rate, distinct usernames targeted, distinct ports
    touched) sits more than `z_threshold` standard deviations above the
    population mean, regardless of whether it crossed any fixed threshold.

    This is a simplified, single-session version of the baselining that
    UEBA/SIEM platforms normally build from a rolling multi-day history;
    with only one log file to work from, the "normal" population is this
    batch's other IPs rather than that IP's own historical behavior.
    """
    findings = []
    per_ip = defaultdict(lambda: {"failed_logins": 0, "users": set(), "ports": set()})
    timestamps = []

    for r in rows:
        ip = r["source_ip"]
        try:
            timestamps.append(datetime.fromisoformat(r["timestamp"]))
        except Exception:
            pass
        if r["event_type"].lower() == "login" and r["status"].lower() == "failed":
            per_ip[ip]["failed_logins"] += 1
            per_ip[ip]["users"].add(r["username"])
        if r["event_type"].lower() == "network":
            try:
                per_ip[ip]["ports"].add(int(r["destination_port"]))
            except Exception:
                pass

    ips = list(per_ip.keys())
    if len(ips) < 3:
        return findings  # not enough distinct IPs to build a meaningful population baseline

    span_minutes = 1.0
    if len(timestamps) >= 2:
        span_minutes = max((max(timestamps) - min(timestamps)).total_seconds() / 60.0, 1.0)

    metrics = {
        "failed_login_rate": ({ip: per_ip[ip]["failed_logins"] / span_minutes for ip in ips}, "failed-login rate (per minute)"),
        "unique_users": ({ip: len(per_ip[ip]["users"]) for ip in ips}, "distinct usernames targeted"),
        "unique_ports": ({ip: len(per_ip[ip]["ports"]) for ip in ips}, "distinct destination ports touched"),
    }

    hits = defaultdict(list)
    for metric, (values, label) in metrics.items():
        vals = list(values.values())
        if len(set(vals)) < 2:
            continue  # no variance across IPs for this metric, nothing to compare against
        mean = statistics.mean(vals)
        try:
            std = statistics.stdev(vals)
        except statistics.StatisticsError:
            continue
        if std == 0:
            continue
        for ip, v in values.items():
            z = (v - mean) / std
            if z >= z_threshold:
                hits[ip].append((metric, label, z, mean, std, v))

    for ip, ip_hits in hits.items():
        metric, label, z, mean, std, v = max(ip_hits, key=lambda h: h[2])
        severity = "HIGH" if z >= 4 else "MEDIUM"
        findings.append({
            "source_ip": ip,
            "rule": "Statistical Anomaly",
            "severity": severity,
            "evidence": f"{label} is {v:.1f} vs. this session's baseline mean {mean:.1f} (σ={std:.1f}).",
            "recommendation": "Confirm against the IP's own historical baseline before escalating — a single-session population baseline can false-positive on naturally high-traffic hosts.",
            "anomaly": {"metric": metric, "z_score": round(z, 2), "mean": round(mean, 2), "std": round(std, 2), "value": round(v, 2)},
        })
    return findings

def analyze_logs(rows, failed_thr, port_thr, spray_thr, anomaly_z=2.5):
    findings = []
    ip_scores = defaultdict(int)
    ip_details = defaultdict(list)

    failed_logins_by_ip = defaultdict(list)
    for r in rows:
        if r["event_type"].lower() == "login" and r["status"].lower() == "failed":
            failed_logins_by_ip[r["source_ip"]].append({"dt": datetime.fromisoformat(r["timestamp"]), "user": r["username"]})

    for ip, events in failed_logins_by_ip.items():
        events.sort(key=lambda x: x["dt"])
        max_in_window = 0
        for i in range(len(events)):
            window = [e for e in events[i:] if e["dt"] - events[i]["dt"] <= timedelta(minutes=5)]
            max_in_window = max(max_in_window, len(window))
        if max_in_window >= failed_thr:
            findings.append({"source_ip": ip, "rule": "Brute Force", "severity": "HIGH", "evidence": f"{max_in_window} attempts in 5m.", "recommendation": "Lockout/MFA."})
            ip_scores[ip] += 50; ip_details[ip].append("Brute Force")

    for ip, events in failed_logins_by_ip.items():
        if len(set(e["user"] for e in events)) >= spray_thr:
            findings.append({"source_ip": ip, "rule": "Password Spraying", "severity": "HIGH", "evidence": f"{len(set(e['user'] for e in events))} users.", "recommendation": "Check accounts."})
            ip_scores[ip] += 40; ip_details[ip].append("Spraying")

    port_map = defaultdict(set)
    for r in rows:
        if r["event_type"].lower() == "network":
            try: port_map[r["source_ip"]].add(int(r["destination_port"]))
            except: continue

    for ip, ports in port_map.items():
        if len(ports) >= port_thr:
            findings.append({"source_ip": ip, "rule": "Port Scan", "severity": "MEDIUM", "evidence": f"{len(ports)} ports.", "recommendation": "Check firewall."})
            ip_scores[ip] += 30; ip_details[ip].append("Port Scan")

    for af in detect_anomalies(rows, z_threshold=anomaly_z):
        findings.append(af)
        ip_scores[af["source_ip"]] += 35 if af["severity"] == "HIGH" else 20
        ip_details[af["source_ip"]].append("Anomaly")

    if not findings:
        findings.append({"source_ip": "-", "rule": "None", "severity": "INFO", "evidence": "No thresholds reached.", "recommendation": "Monitor."})

    for ip, score in ip_scores.items():
        risk = "CRITICAL" if score >= 80 else ("HIGH" if score >= 50 else "MEDIUM")
        for f in findings:
            if f["source_ip"] == ip and f["rule"] != "None":
                f["threat_score"] = score; f["risk_level"] = risk; f["tactics"] = ", ".join(ip_details[ip])

    # Attach MITRE ATT&CK technique to each finding that matched a rule
    for f in findings:
        mitre = MITRE_MAP.get(f["rule"])
        if mitre:
            f["mitre"] = mitre

    severity_counts = Counter(f["severity"] for f in findings)
    stats = {
        "total_rows": len(rows), "total_findings": len(findings),
        "high": severity_counts.get("HIGH", 0), "medium": severity_counts.get("MEDIUM", 0),
        "info": severity_counts.get("INFO", 0),
        "top_failed_ips": [{"ip": ip, "count": len(e)} for ip, e in sorted(failed_logins_by_ip.items(), key=lambda x: len(x[1]), reverse=True)[:5]],
    }
    return findings, stats

def findings_to_csv(findings):
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["source_ip", "rule", "severity", "threat_score", "risk_level", "tactics", "evidence", "recommendation"], extrasaction="ignore")
    writer.writeheader(); writer.writerows(findings)
    return buf.getvalue()

# --- GEOIP LOOKUP ---
# Private/internal IPs can never be geolocated by any API, so they're mapped
# to a fixed "internal network" marker. Public IPs use the free ip-api.com
# lookup (no key required); if there's no internet access, a deterministic
# offline estimate is used instead so the map still populates for a demo.
_geo_cache = {}

# True RFC1918 / loopback / link-local ranges only — these are genuinely
# internal network addresses with no public location, so no API could ever
# geolocate them and plotting a pin would be meaningless.
import ipaddress as _ipaddress
_INTERNAL_NETS = [_ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
)]
# RFC5737 documentation/test-net ranges: not routable on the real internet,
# so a geolocation API will never resolve them, but they're commonly used in
# sample/demo log data to represent "external" attacker traffic. These get
# the deterministic offline estimate instead of being treated as internal.
_DOC_NETS = [_ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
)]

def _is_internal_ip(ip):
    try:
        addr = _ipaddress.ip_address(ip)
        return any(addr in net for net in _INTERNAL_NETS)
    except Exception:
        return True

def _is_doc_range_ip(ip):
    try:
        addr = _ipaddress.ip_address(ip)
        return any(addr in net for net in _DOC_NETS)
    except Exception:
        return False

def _offline_estimate(ip):
    h = int(hashlib.sha256(ip.encode()).hexdigest(), 16)
    lat = (h % 140) - 60
    lon = (h // 140 % 340) - 170
    return {"ip": ip, "lat": lat, "lon": lon, "city": "Unresolved (offline estimate)",
            "country": "-", "internal": False, "estimated": True}

def geolocate_ip(ip):
    if ip in _geo_cache:
        return _geo_cache[ip]

    if ip == "-" or _is_internal_ip(ip):
        loc = {"ip": ip, "lat": None, "lon": None, "city": "Internal network", "country": "Private range", "internal": True}
        _geo_cache[ip] = loc
        return loc

    if _is_doc_range_ip(ip):
        loc = _offline_estimate(ip)
        _geo_cache[ip] = loc
        return loc

    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        data = resp.json()
        if data.get("status") == "success":
            loc = {"ip": ip, "lat": data.get("lat"), "lon": data.get("lon"),
                   "city": data.get("city") or "Unknown city", "country": data.get("country") or "Unknown",
                   "internal": False, "estimated": False}
        else:
            raise ValueError("lookup failed")
    except Exception:
        loc = _offline_estimate(ip)

    _geo_cache[ip] = loc
    return loc

# --- ROUTES ---
@app.route("/")
def index(): return render_template("index.html")

@app.route("/api/malware")
def get_malware():
    # The live feed only shows open cases; resolved ones move to case history.
    active_alerts = [a for a in realtime_alerts if a["state"] != "resolved"]
    return jsonify({"alerts": active_alerts})

@app.route("/api/cases")
def list_cases():
    # Full case list (every state, newest first) for the case management panel.
    cases = sorted(realtime_alerts, key=lambda a: a["time"], reverse=True)
    return jsonify({"cases": cases})

@app.route("/api/malware/<alert_id>/transition", methods=["POST"])
def transition_alert(alert_id):
    data = request.get_json(silent=True) or {}
    new_state = data.get("state")
    note = data.get("note")
    if new_state not in ALERT_STATES:
        return jsonify({"error": f"Invalid state. Must be one of {ALERT_STATES}."}), 400
    for a in realtime_alerts:
        if a["id"] == alert_id:
            _add_history(a, new_state, note)
            return jsonify(a)
    return jsonify({"error": "Not found"}), 404

@app.route("/api/malware/<alert_id>/investigate")
def investigate_alert(alert_id):
    for a in realtime_alerts:
        if a["id"] == alert_id:
            if a["state"] in ("new", "acknowledged"):
                _add_history(a, "in_progress", "Investigation opened.")
            forensics = build_wazuh_forensics(a) if a.get("source") == "wazuh" else generate_forensics(a)
            forensics["case"] = {"id": a["id"], "state": a["state"], "history": a["history"], "simulated": a.get("simulated", False)}
            return jsonify(forensics)
    return jsonify({"error": "Not found"}), 404

def run_full_analysis(rows, failed_thr, port_thr, spray_thr, anomaly_z):
    """Shared pipeline used by both a manual CSV upload and the attack
    simulation engine: run detection, geolocate the resulting source IPs,
    cache the result for the PDF report, and return the API response shape."""
    findings, stats = analyze_logs(rows, failed_thr, port_thr, spray_thr, anomaly_z)

    severity_rank = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "INFO": 0}
    worst_severity = {}
    for f in findings:
        ip = f["source_ip"]
        if ip == "-": continue
        if severity_rank.get(f["severity"], 0) >= severity_rank.get(worst_severity.get(ip, "INFO"), 0):
            worst_severity[ip] = f["severity"]

    geo = []
    for ip in worst_severity:
        loc = dict(geolocate_ip(ip))
        loc["severity"] = worst_severity[ip]
        geo.append(loc)

    last_analysis["findings"] = findings
    last_analysis["stats"] = stats
    last_analysis["geo"] = geo
    last_analysis["generated"] = _now()

    return {"findings": findings, "stats": stats, "warnings": [], "geo": geo, "findings_csv": findings_to_csv(findings)}

# --- LIVE ATTACK SIMULATION ---
# A "breach and attack simulation" style demo: generates a realistic
# multi-stage attack chain (recon -> credential access -> payload delivery)
# as synthetic log data, feeds it through the SAME detection engine used for
# a real uploaded file, and drops a matching malware alert into the live
# feed so the full New -> Acknowledged -> In Progress -> Resolved lifecycle
# can be demonstrated end to end. Everything generated this way is tagged
# "simulated": true wherever it surfaces, so it's never presented as a real
# incident.
simulation_lock = threading.Lock()
simulation_state = {
    "running": False, "phase": "idle", "phase_label": "", "progress": 0,
    "counts": {"port_events": 0, "failed_logins": 0, "spray_users": 0},
    "rows": [], "result": None, "alert_id": None,
}

SIM_ATTACKER_IP = "203.0.113.77"  # RFC5737 documentation range: safe, non-routable demo IP
# 10 simulated "normal" internal IPs. The statistical anomaly detector compares
# the attacker's metrics against this population's mean/stdev, and a z-score
# computed from too small a sample is mathematically capped (with only 3-4
# points, no single outlier can reach z >= 2) regardless of how extreme it
# really is — so enough comparison points are needed for the math to work, not
# just for visual realism.
SIM_NORMAL_IPS = [f"10.0.4.{n}" for n in (11, 14, 19, 22, 28, 33, 41, 47, 52, 58)]
SIM_TARGET_USERS = ["jsmith", "mreyes", "a.khan", "svc_backup", "r.patel"]

def _sim_row(ts, event_type, username="-", status="-", port=0, ip=SIM_ATTACKER_IP):
    return {"timestamp": ts.isoformat(), "source_ip": ip, "event_type": event_type,
            "username": username, "status": status, "destination_port": str(port)}

def _seed_normal_traffic(start):
    """Light, varied baseline traffic from ordinary internal hosts so the
    statistical anomaly detector has a real population to compare the
    attacker IP against — without this, there'd be nothing for it to be
    anomalous relative to, and too few points would cap the z-score
    mathematically regardless of how extreme the attacker's activity is."""
    rows = []
    for i, ip in enumerate(SIM_NORMAL_IPS):
        for j in range(random.randint(1, 2)):
            ts = start - timedelta(seconds=50) + timedelta(seconds=(i * 2 + j) * 3)
            rows.append(_sim_row(ts, "login", username=random.choice(SIM_TARGET_USERS[:3]), status="success", ip=ip))
        if random.random() < 0.2:  # the occasional realistic mistyped password
            rows.append(_sim_row(start - timedelta(seconds=45), "login", username=random.choice(SIM_TARGET_USERS[:3]), status="failed", ip=ip))
        for p in random.sample([80, 443, 3389, 22, 53], k=random.randint(1, 3)):
            rows.append(_sim_row(start - timedelta(seconds=15), "network", port=p, ip=ip))
    return rows

def run_attack_simulation(thresholds):
    with simulation_lock:
        simulation_state.update({
            "running": True, "phase": "recon", "progress": 2,
            "phase_label": "Reconnaissance — port scanning target host",
            "counts": {"port_events": 0, "failed_logins": 0, "spray_users": 0},
            "rows": [], "result": None, "alert_id": None,
        })

    start = datetime.now()
    with simulation_lock:
        simulation_state["rows"].extend(_seed_normal_traffic(start))

    # Phase 1: reconnaissance / port scan (~12s)
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 5900]
    for i, p in enumerate(ports):
        time.sleep(0.8)
        ts = start + timedelta(seconds=i * 2)
        with simulation_lock:
            simulation_state["rows"].append(_sim_row(ts, "network", port=p))
            simulation_state["counts"]["port_events"] += 1
            simulation_state["progress"] = 5 + int(30 * (i + 1) / len(ports))

    # Phase 2: credential access — brute force against one account (~7s)
    with simulation_lock:
        simulation_state["phase"] = "credential_attack"
        simulation_state["phase_label"] = "Credential access — brute force against a single account"
    bf_start = start + timedelta(seconds=35)
    for i in range(7):
        time.sleep(1.0)
        ts = bf_start + timedelta(seconds=i * 8)
        with simulation_lock:
            simulation_state["rows"].append(_sim_row(ts, "login", username="svc_backup", status="failed"))
            simulation_state["counts"]["failed_logins"] += 1
            simulation_state["progress"] = 35 + int(25 * (i + 1) / 7)

    # Phase 2b: credential access — password spraying across accounts (~4s)
    with simulation_lock:
        simulation_state["phase_label"] = "Credential access — password spraying across multiple accounts"
    spray_start = bf_start + timedelta(seconds=90)
    for i, user in enumerate(SIM_TARGET_USERS):
        time.sleep(0.8)
        ts = spray_start + timedelta(seconds=i * 5)
        with simulation_lock:
            simulation_state["rows"].append(_sim_row(ts, "login", username=user, status="failed"))
            simulation_state["counts"]["spray_users"] += 1
            simulation_state["progress"] = 60 + int(20 * (i + 1) / len(SIM_TARGET_USERS))

    # Phase 3: payload delivery -> drop straight into the live malware feed
    with simulation_lock:
        simulation_state["phase"] = "payload_delivery"
        simulation_state["phase_label"] = "Execution — payload delivered to endpoint"
        simulation_state["progress"] = 88
    time.sleep(2)

    alert_id = f"SIM-{int(time.time())}"
    opened = _now()
    alert = {
        "id": alert_id, "time": opened,
        "file": "invoice_Q4_statement.exe",
        "path": os.path.join(SCAN_DIRECTORY, "invoice_Q4_statement.exe"),
        "hostname": socket.gethostname(), "username": getpass.getuser(),
        "threat": "VirusTotal: 55/70 engines flagged this file.",
        "severity": "CRITICAL", "status": "Quarantined (Simulated)",
        "state": "new", "simulated": True,
        "history": [{"state": "new", "time": opened, "note": "Simulated payload delivery — Attack Simulation engine."}],
    }
    realtime_alerts.append(alert)

    with simulation_lock:
        rows_snapshot = list(simulation_state["rows"])

    result = run_full_analysis(rows_snapshot, thresholds["failed"], thresholds["port"], thresholds["spray"], thresholds["anomaly"])
    result["simulated"] = True

    with simulation_lock:
        simulation_state["result"] = result
        simulation_state["phase"] = "complete"
        simulation_state["phase_label"] = "Simulation complete — full attack chain detected"
        simulation_state["progress"] = 100
        simulation_state["running"] = False
        simulation_state["alert_id"] = alert_id

@app.route("/simulate/start", methods=["POST"])
def simulate_start():
    if simulation_state["running"]:
        return jsonify({"error": "A simulation is already running."}), 409
    thresholds = {
        "failed": int(request.form.get("failed_threshold", 5)),
        "port": int(request.form.get("port_threshold", 8)),
        "spray": int(request.form.get("spray_threshold", 4)),
        "anomaly": float(request.form.get("anomaly_zscore", 2.5)),
    }
    threading.Thread(target=run_attack_simulation, args=(thresholds,), daemon=True).start()
    return jsonify({"started": True})

@app.route("/simulate/status")
def simulate_status():
    with simulation_lock:
        return jsonify({
            "running": simulation_state["running"],
            "phase": simulation_state["phase"],
            "phase_label": simulation_state["phase_label"],
            "progress": simulation_state["progress"],
            "counts": simulation_state["counts"],
            "complete": simulation_state["phase"] == "complete",
        })

@app.route("/simulate/result")
def simulate_result():
    if not simulation_state["result"]:
        return jsonify({"error": "No simulation result available yet."}), 400
    return jsonify(simulation_state["result"])

def build_milo_context():
    """A short, plain-text snapshot of the dashboard's live state, handed to
    the LLM as grounding so it can answer questions about the real data
    instead of guessing or hallucinating numbers."""
    lines = []
    stats = last_analysis.get("stats")
    if stats:
        lines.append(
            f"Last analysis: {stats.get('total_rows', 0)} log rows, "
            f"{stats.get('total_findings', 0)} findings "
            f"({stats.get('high', 0)} high/critical, {stats.get('medium', 0)} medium)."
        )
        rule_counts = Counter(f["rule"] for f in last_analysis.get("findings", []) if f.get("rule") and f["rule"] != "None")
        if rule_counts:
            lines.append("Detections by type: " + ", ".join(f"{c} {r}" for r, c in rule_counts.most_common()) + ".")
        if last_analysis.get("generated"):
            lines.append(f"That analysis was generated at {last_analysis['generated']}.")
    else:
        lines.append("No log analysis has been run yet this session.")

    case_counts = Counter(a["state"] for a in realtime_alerts)
    lines.append(
        f"Malware cases: {case_counts.get('new', 0)} new, {case_counts.get('acknowledged', 0)} acknowledged, "
        f"{case_counts.get('in_progress', 0)} in progress, {case_counts.get('resolved', 0)} resolved "
        f"({len(realtime_alerts)} total)."
    )
    active = [a for a in realtime_alerts if a["state"] != "resolved"]
    if active:
        lines.append("Active alerts: " + "; ".join(f"{a['severity']} — {a['file']} (case {a['id']}, state {a['state']})" for a in active[:5]) + ".")
    return "\n".join(lines)

MILO_SYSTEM_PROMPT = """You are Milo, a voice assistant built into a student cybersecurity project called \
"SOC Threat Engine" — a Security Operations Center dashboard with log-based threat detection, MITRE ATT&CK \
tagging, a geolocation map, case management, and an attack simulation mode.

You are a genuinely helpful, well-rounded assistant, not a scripted command parser. You can:
- Answer questions about the dashboard's current live state, using the context block given below
- Answer general cybersecurity, networking, and IT questions knowledgeably and accurately
- Answer other reasonable general-knowledge questions a user might ask in conversation
- Have a natural back-and-forth; you don't need to force every answer to be about the dashboard

Your response will be read aloud via text-to-speech, not displayed as long text, so:
- Keep answers short and conversational — normally 1 to 3 sentences
- Never use markdown, bullet points, headers, or special formatting
- Spell things out in a way that sounds natural when spoken (e.g. say "ten" not "10/100" style scores unless it reads naturally)

If asked something that would require real-time internet lookup you don't have (e.g. today's news), say so plainly rather than guessing. If asked something genuinely harmful or inappropriate, decline briefly and kindly, then move on.

Current dashboard state:
{context}"""

def call_milo_llm(question):
    if not GROQ_API_KEY:
        return None, "No Groq API key is configured. Set the GROQ_API_KEY environment variable (get a free one at console.groq.com) and restart the app."
    system_prompt = MILO_SYSTEM_PROMPT.format(context=build_milo_context())
    try:
        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
            json={
                "model": GROQ_MODEL,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": question},
                ],
                "max_tokens": 250,
                "temperature": 0.4,
            },
            timeout=20,
        )
        if resp.status_code == 401:
            return None, "Groq rejected the API key — double check GROQ_API_KEY is set correctly."
        if resp.status_code == 429:
            return None, "Groq's free-tier rate limit was hit — wait a few seconds and try again."
        if resp.status_code != 200:
            detail = resp.text[:200]
            print(f"[Milo] Groq returned status {resp.status_code}: {detail}")
            return None, f"Groq returned an error: {detail}"
        payload = resp.json()
        answer = payload["choices"][0]["message"]["content"].strip()
        if not answer:
            print(f"[Milo] Groq returned no usable answer. Raw payload was:\n{payload!r}\n")
            return "I didn't get a usable response back — try asking again.", None
        return answer, None
    except requests.exceptions.ConnectionError:
        return None, "Could not reach Groq — check your internet connection."
    except requests.exceptions.Timeout:
        return None, "Groq took too long to respond — try again."
    except requests.exceptions.RequestException as exc:
        return None, f"Could not reach Groq: {exc}"

@app.route("/api/milo/ask", methods=["POST"])
def milo_ask():
    data = request.get_json(silent=True) or {}
    question = (data.get("question") or "").strip()
    if not question:
        return jsonify({"error": "No question provided."}), 400
    answer, error = call_milo_llm(question)
    if error:
        return jsonify({"error": error}), 502
    return jsonify({"answer": answer})

@app.route("/analyze", methods=["POST"])
def analyze_route():
    if "file" not in request.files: return jsonify({"error": "No file."}), 400
    try:
        text = request.files["file"].read().decode("utf-8", errors="replace")
        rows, warnings = load_logs_from_stream(io.StringIO(text))
    except Exception as exc: return jsonify({"error": str(exc)}), 400

    result = run_full_analysis(
        rows,
        int(request.form.get("failed_threshold", 5)),
        int(request.form.get("port_threshold", 8)),
        int(request.form.get("spray_threshold", 4)),
        float(request.form.get("anomaly_zscore", 2.5)),
    )
    result["warnings"] = warnings
    return jsonify(result)

@app.route("/report/pdf")
def report_pdf():
    if not last_analysis["findings"]:
        return jsonify({"error": "Run an analysis before generating a report."}), 400

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, topMargin=0.6 * inch, bottomMargin=0.6 * inch,
                             leftMargin=0.6 * inch, rightMargin=0.6 * inch)
    styles = getSampleStyleSheet()
    navy = colors.HexColor("#0a1222")
    cyan = colors.HexColor("#0e7490")

    title_style = ParagraphStyle("TitleX", parent=styles["Title"], textColor=navy, fontSize=22, spaceAfter=4)
    sub_style = ParagraphStyle("SubX", parent=styles["Normal"], textColor=colors.HexColor("#475569"), fontSize=10)
    section_style = ParagraphStyle("SectionX", parent=styles["Heading2"], textColor=navy, spaceBefore=18, spaceAfter=8)

    story = [
        Paragraph("SOC Threat Engine — Incident Report", title_style),
        Paragraph(f"Generated {last_analysis['generated']}", sub_style),
        Spacer(1, 16),
    ]

    stats = last_analysis["stats"]
    summary_data = [
        ["Rows analyzed", "Total findings", "High / Critical", "Medium"],
        [str(stats.get("total_rows", 0)), str(stats.get("total_findings", 0)),
         str(stats.get("high", 0)), str(stats.get("medium", 0))],
    ]
    summary = Table(summary_data, hAlign="LEFT", colWidths=[1.4 * inch] * 4)
    summary.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), navy),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(summary)

    story.append(Paragraph("Findings", section_style))
    header = ["Severity", "Source IP", "Rule", "MITRE ATT&CK", "Score", "Evidence"]
    body = []
    sev_colors = {"CRITICAL": colors.HexColor("#ff4d5e"), "HIGH": colors.HexColor("#e11d48"),
                  "MEDIUM": colors.HexColor("#b45309"), "INFO": colors.HexColor("#64748b")}
    for f in last_analysis["findings"]:
        mitre = f.get("mitre")
        mitre_str = f"{mitre['id']} - {mitre['name']}" if mitre else "-"
        body.append([f.get("severity", "-"), f.get("source_ip", "-"), f.get("rule", "-"),
                     mitre_str, str(f.get("threat_score", "-")), f.get("evidence", "-")])

    table = Table([header] + body, repeatRows=1, colWidths=[0.75 * inch, 0.95 * inch, 0.85 * inch, 1.55 * inch, 0.5 * inch, 1.6 * inch])
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), navy),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    for i, f in enumerate(last_analysis["findings"], start=1):
        c = sev_colors.get(f.get("severity"))
        if c:
            style_cmds.append(("TEXTCOLOR", (0, i), (0, i), c))
    table.setStyle(TableStyle(style_cmds))
    story.append(table)

    if last_analysis["geo"]:
        story.append(Paragraph("Geolocated source IPs", section_style))
        geo_header = ["Source IP", "Severity", "City", "Country"]
        geo_body = [[g["ip"], g["severity"], g.get("city", "-"), g.get("country", "-")] for g in last_analysis["geo"]]
        geo_table = Table([geo_header] + geo_body, repeatRows=1, colWidths=[1.3 * inch, 0.9 * inch, 2 * inch, 2 * inch])
        geo_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), cyan),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ]))
        story.append(geo_table)

    doc.build(story)
    buf.seek(0)
    return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name="soc_incident_report.pdf")

# ==============================================================================
# WAZUH SIEM WEBHOOK RECEIVER (Appended without touching existing code)
# ==============================================================================
WAZUH_CSV_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wazuh_alerts")
os.makedirs(WAZUH_CSV_DIR, exist_ok=True)
WAZUH_CSV_FIELDS = ["time", "alert_id", "dashboard", "category", "severity", "rule_id", "rule_description", "hostname", "username", "mitre_id"]

def _append_wazuh_csv(row):
    """Persists every incoming Wazuh alert to a dated CSV on disk — the
    literal 'automatic CSV save' the project asked for, done on receipt
    rather than on a polling timer."""
    path = os.path.join(WAZUH_CSV_DIR, f"wazuh_{datetime.now().strftime('%Y%m%d')}.csv")
    write_header = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=WAZUH_CSV_FIELDS)
        if write_header:
            writer.writeheader()
        writer.writerow(row)

# ==============================================================================
# WAZUH ALERT TRIAGE: classify, name, and filter alerts
# ==============================================================================
# EDIT THESE for your machine:
AUTHORIZED_USERS = {"zee"}            # Windows usernames that are allowed to log in (lowercase)
ALLOWED_REMOTE_IPS = set()            # e.g. {"192.168.1.50"}: IPs allowed to log in over network/RDP
DEDUP_WINDOW_SECONDS = 300            # identical alerts within 5 min become one card with a counter

REMOTE_LOGON_TYPES = {"3", "10"}      # 3 = network, 10 = RDP
LOCAL_SOURCES = {"", "-", "::1", "127.0.0.1"}
SENSITIVE_PATH_HINTS = ("\\windows\\system32", "\\startup", "\\drivers\\etc", "\\users\\public")
SPECIAL_EVENTS = {
    "4720": ("Account Change", "New user account created", "HIGH"),
    "4728": ("Privilege Change", "User added to privileged group", "HIGH"),
    "4732": ("Privilege Change", "User added to local group", "HIGH"),
    "4719": ("Defense Evasion", "Audit policy changed", "HIGH"),
    "1102": ("Defense Evasion", "Security audit log cleared", "CRITICAL"),
}

def _is_system_account(user):
    u = (user or "").lower()
    return (not u) or u.endswith("$") or u in {
        "system", "local service", "network service", "anonymous logon"
    } or u.startswith(("dwm-", "umfd-"))

def _level_to_severity(level):
    return "CRITICAL" if level >= 10 else ("HIGH" if level >= 7 else "MEDIUM")

def triage_wazuh_alert(w):
    """Returns dict: show (bool), category, title, severity, reason."""
    rule = w.get("rule") or {}
    rid = str(rule.get("id", ""))
    level = int(rule.get("level", 0) or 0)
    desc = rule.get("description", "Unknown event")
    groups = set(rule.get("groups") or [])
    win = ((w.get("data") or {}).get("win")) or {}
    ed = win.get("eventdata") or {}
    event_id = str((win.get("system") or {}).get("eventID", ""))
    user = ed.get("targetUserName") or ed.get("subjectUserName") or ""
    src_ip = ed.get("ipAddress") or "-"
    logon_type = str(ed.get("logonType", ""))

    def verdict(show, category, title, severity, reason):
        return {"show": show, "category": category, "title": title,
                "severity": severity, "reason": reason}

    # 1) Real malware detections
    if groups & {"malware", "virustotal", "yara"}:
        return verdict(True, "malware", "Malware detected", _level_to_severity(max(level, 10)), desc)

    # 2) Failed logons = someone guessing passwords
    if event_id == "4625" or groups & {"authentication_failed", "win_authentication_failed",
                                       "authentication_failures"} or rid in {"60122", "60204"}:
        who = f"user '{user or 'unknown'}' from {src_ip}"
        if "authentication_failures" in groups or rid == "60204":
            return verdict(True, "brute_force", "Possible brute-force attack", "HIGH", f"{desc}: {who}")
        return verdict(True, "failed_logon", "Failed logon attempt", "MEDIUM", f"{desc}: {who}")

    # 3) Successful logons: only alert if NOT authorized
    if event_id == "4624" or "authentication_success" in groups or rid in {"60106", "60118"}:
        if _is_system_account(user):
            return verdict(False, "logon", "System logon", "INFO", "Normal system/service logon")
        if user.lower() not in AUTHORIZED_USERS:
            return verdict(True, "unauthorized_logon", "Logon by unauthorized account", "HIGH",
                           f"User '{user}' logged in from {src_ip} (not in authorized list)")
        if logon_type in REMOTE_LOGON_TYPES and src_ip not in LOCAL_SOURCES and src_ip not in ALLOWED_REMOTE_IPS:
            return verdict(True, "suspicious_remote_logon", "Remote logon from unexpected source", "HIGH",
                           f"Authorized user '{user}' logged in remotely from {src_ip}")
        return verdict(False, "logon", "Authorized logon", "INFO", f"Authorized logon by '{user}'")

    # 4) Specific security-relevant Windows events
    if event_id in SPECIAL_EVENTS:
        cat, title, sev = SPECIAL_EVENTS[event_id]
        return verdict(True, cat.lower().replace(" ", "_"), title, sev, desc)

    # 5) File integrity (FIM): only matters in sensitive locations
    if "syscheck" in groups:
        path = str((w.get("syscheck") or {}).get("path", "")).lower()
        if any(h in path for h in SENSITIVE_PATH_HINTS):
            return verdict(True, "file_integrity", "File changed in sensitive location", "MEDIUM", f"{desc}: {path}")
        return verdict(False, "file_integrity", "File integrity change", "INFO", desc)

    # 6) Everything else: only show if Wazuh itself rates it level 7+
    if level >= 7:
        return verdict(True, "security_event", "Security event", _level_to_severity(level), desc)
    return verdict(False, "other", "Informational event", "INFO", desc)

def _find_recent_duplicate(key):
    now = time.time()
    for a in reversed(realtime_alerts):
        if a.get("dedup_key") == key and a["state"] != "resolved" and now - a.get("last_ts", 0) <= DEDUP_WINDOW_SECONDS:
            return a
    return None

@app.route("/webhook", methods=["POST"])
def wazuh_webhook():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid or empty JSON"}), 400
    alerts = data if isinstance(data, list) else [data]

    for w_alert in alerts:
        rule = w_alert.get("rule", {})
        agent = w_alert.get("agent", {})
        mitre = rule.get("mitre", {})
        mitre_id = mitre.get("id", ["N/A"])[0] if mitre.get("id") else "N/A"
        hostname = agent.get("name", "Unknown Host")
        username = w_alert.get("data", {}).get("win", {}).get("eventdata", {}).get("targetUserName", "System")

        v = triage_wazuh_alert(w_alert)
        alert_id = f"WAZ-{int(time.time())}-{random.randint(100,999)}"
        opened = _now()

        _append_wazuh_csv({
            "time": opened, "alert_id": alert_id, "dashboard": "shown" if v["show"] else "suppressed",
            "category": v["category"], "severity": v["severity"], "rule_id": rule.get("id", "-"),
            "rule_description": rule.get("description", "-"), "hostname": hostname,
            "username": username, "mitre_id": mitre_id,
        })

        if not v["show"]:
            continue  # saved to CSV only, no dashboard alert

        dedup_key = f"{v['category']}|{hostname}|{username}|{rule.get('id')}"
        dup = _find_recent_duplicate(dedup_key)
        if dup:
            dup["count"] = dup.get("count", 1) + 1
            dup["last_ts"] = time.time()
            continue

        realtime_alerts.append({
            "id": alert_id, "time": opened,
            "file": f"Rule {rule.get('id')}", "path": v["reason"],
            "hostname": hostname, "username": username,
            "title": v["title"], "category": v["category"],
            "threat": v["reason"], "severity": v["severity"],
            "status": f"MITRE: {mitre_id}", "state": "new",
            "history": [{"state": "new", "time": opened, "note": "Alert generated by Wazuh SIEM."}],
            "source": "wazuh", "raw": w_alert,
            "count": 1, "last_ts": time.time(), "dedup_key": dedup_key,
        })
        print(f"🚨 [WAZUH] {v['title']} | {v['severity']}")

    return jsonify({"status": "success"}), 200

if __name__ == "__main__":
    # 0.0.0.0 (not 127.0.0.1) is required so the Ubuntu Wazuh machine can
    # reach this app across the network to POST to /webhook — 127.0.0.1
    # only accepts connections from this same machine.
    app.run(debug=True, host="0.0.0.0", port=5000)