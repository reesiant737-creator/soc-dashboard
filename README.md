# 🛡️ SOC Dashboard — AI-Powered Security Operations Center

A full-stack cybersecurity dashboard that replicates a real Security Operations Center (SOC) environment. Built with Python/Flask and powered by Claude AI (Anthropic), it parses network scans, maps threats to MITRE ATT&CK, scores CVEs, visualizes attack graphs, and generates professional incident reports — all from a browser.

![SOC Dashboard](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-green?style=flat-square&logo=flask)
![Claude AI](https://img.shields.io/badge/Claude_AI-Anthropic-orange?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-lightgrey?style=flat-square)

---

## 🎯 What It Does

This dashboard takes raw network scan data (Nmap XML/text or Wireshark PCAP/JSON) and transforms it into a full SOC-style threat assessment:

| Feature | Description |
|---|---|
| **Nmap Parser** | Ingests `.xml` or `.txt` Nmap output — extracts hosts, ports, services, OS fingerprints |
| **MITRE ATT&CK Mapping** | Maps open ports/services to real ATT&CK techniques and tactics automatically |
| **CVE/CVSS Scoring** | Queries the NVD (National Vulnerability Database) API for CVEs on detected products |
| **Alert Correlation Engine** | Runs 8 detection rules across all hosts — flags cleartext protocols, exposed DBs, C2 ports, and more |
| **Attack Graph** | Interactive node graph showing attacker → host → service → MITRE technique relationships |
| **Wireshark / PCAP Analysis** | Parses `.pcap`, `.pcapng`, or Wireshark JSON exports — detects port scans, C2 beacons, and suspicious URIs |
| **Claude AI Analyst** | Generates professional SOC incident reports, answers analyst questions, and produces Sigma/KQL/SPL threat hunt queries |
| **SIEM JSON Export** | Structured JSON output ready for ingestion into Splunk, Elastic, or Microsoft Sentinel |
| **PDF Report** | Professional incident report PDF with executive summary, findings, and remediation steps |

---

## 🖥️ Dashboard Screenshots

### Main Dashboard — Hosts + Alert Stats
- Dark SOC-style UI with live stat cards (Hosts, Critical, High, Medium, Techniques, CVEs)
- Host inventory table with risk score bars, CVSS scores, and CVE counts
- Click any host to open a full detail modal with ports, CVEs, alerts, and MITRE techniques

### Alerts Panel
- Color-coded alert cards (Critical / High / Medium / Low)
- Each alert shows the rule triggered, affected host, description, and remediation steps
- 8 built-in correlation rules including cleartext protocols, exposed databases, C2 port detection

### Attack Graph
- Interactive vis.js network graph
- Red triangle = attacker node
- Red/orange boxes = high-risk hosts
- Blue ellipses = detected services
- Purple/yellow diamonds = MITRE ATT&CK techniques
- Drag, zoom, and click nodes to explore

### AI Analyst Panel
- One-click full incident report generation via Claude
- Chat interface to ask the AI analyst specific questions
- Threat hunting query generator (Sigma YAML, Splunk SPL, KQL for Sentinel)

---

## 🏗️ How It Was Built

### Architecture

```
soc-dashboard/
├── app.py                    # Flask application — all API routes
├── modules/
│   ├── nmap_parser.py        # Parses Nmap XML and plain text output
│   ├── mitre_attack.py       # Maps ports/services to MITRE ATT&CK techniques
│   ├── cve_lookup.py         # Queries NVD API for CVE/CVSS data
│   ├── alert_correlator.py   # 8 correlation rules — runs across all hosts
│   ├── graph_builder.py      # Builds vis.js-compatible attack graph data
│   ├── wireshark_parser.py   # Parses tshark JSON exports
│   ├── pcap_parser.py        # Parses raw .pcap/.pcapng files via scapy
│   ├── ai_analyst.py         # Claude AI integration — reports, Q&A, hunt queries
│   └── report_exporter.py    # PDF (ReportLab) and SIEM JSON export
├── static/
│   ├── css/dashboard.css     # Full dark SOC UI — custom CSS, no Bootstrap themes
│   └── js/dashboard.js       # All frontend logic — fetch, render, graph, AI chat
├── templates/
│   └── index.html            # Single-page dashboard — Bootstrap 5 + vis.js
├── sample_scan.xml           # Sample Nmap scan with 6 hosts for demo
├── sample_capture.json       # Sample Wireshark capture with C2/port scan activity
├── requirements.txt
└── .env                      # API keys (not committed to git)
```

### Technology Stack

| Layer | Technology | Why |
|---|---|---|
| Backend | Python + Flask | Lightweight, fast API server |
| AI | Anthropic Claude (claude-sonnet-4-6) | Best-in-class threat analysis and report writing |
| PCAP Parsing | Scapy | Pure Python — no external tools required |
| Nmap Parsing | xmltodict | Handles both XML and plain text output |
| CVE Data | NVD REST API v2 | Official NIST vulnerability database |
| PDF Export | ReportLab | Professional PDF generation in Python |
| Frontend | Bootstrap 5 + custom CSS | Dark SOC UI, responsive |
| Graph | vis.js Network | Interactive physics-based attack graph |
| Markdown | marked.js | Renders AI report markdown in the browser |

### How Each Module Works

#### `nmap_parser.py`
Accepts Nmap XML (from `-oX`) or plain text output. Uses `xmltodict` to walk the XML tree, extracting:
- IP address, MAC, hostname
- All ports with state, service name, product, version, CPE
- OS detection results and accuracy
- Calculates a **risk score (0–100)** based on open port count and dangerous port types

#### `mitre_attack.py`
Maintains a local mapping of service names and port numbers to MITRE ATT&CK technique IDs, names, and tactic IDs. For each open port on each host:
- Looks up the service → finds matching techniques
- Returns technique ID (e.g. `T1021.001`), tactic (e.g. `Lateral Movement`), and ATT&CK URL
- `build_attack_chain()` orders techniques by kill-chain phase across all hosts

#### `cve_lookup.py`
For each detected product/version string (e.g. `Apache httpd 2.4.6`):
- Queries the NVD API: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- Parses CVSS v3.1/v3.0/v2 scores and severity
- Returns top CVEs sorted by CVSS score
- Results are cached with `@lru_cache` to avoid redundant API calls

#### `alert_correlator.py`
8 detection rules evaluated against every host using Python lambdas:
1. Multi-Service Exposure (5+ open high-risk ports)
2. Cleartext Protocol Detected (telnet, ftp, rsh, rexec)
3. Database Exposed to Network (MSSQL, Oracle, MySQL, MongoDB, Redis)
4. Remote Desktop / VNC Exposed (RDP port 3389, VNC port 5900)
5. Critical CVE Present (CVSS ≥ 9.0)
6. Windows Admin Shares (SMB port 445)
7. Default/Misconfigured SNMP (port 161)
8. High Risk Score Host (aggregate score ≥ 70)

Each triggered rule generates an alert with severity, description, affected host, and remediation steps.

#### `pcap_parser.py`
Uses Scapy's `rdpcap()` to read binary PCAP files from memory (no temp files). For each packet:
- Extracts IP src/dst, MAC addresses, TCP/UDP ports
- Identifies DNS queries, HTTP methods and URIs
- Falls back to raw payload inspection for HTTP detection
- Feeds into the same summary/suspicious/conversation pipeline as the JSON parser

#### `wireshark_parser.py`
Parses tshark JSON exports (generated with `tshark -r file.pcap -T json`). Detects:
- **Port scans** — source IP hitting 50+ unique destination ports
- **Suspicious ports** — traffic to 4444, 1337, 31337, 6666, 8888, 9999
- **C2 indicators** — shell command patterns in HTTP URIs (`/bin/bash`, `powershell`, `wget`)

#### `graph_builder.py`
Builds a vis.js-compatible `{nodes, edges}` structure:
- Attacker node (triangle) at the root
- Host nodes (boxes) colored by risk score
- Service nodes (ellipses) per host
- Technique nodes (diamonds) colored by tactic
- Edges show scan → host → service → technique flow

#### `ai_analyst.py`
Three Claude-powered functions:
1. **`analyze_scan_results()`** — Sends a structured prompt with host summary, alerts, and techniques. Returns a 5-section SOC report: Executive Summary, Critical Findings, Attack Surface Assessment, Priority Remediation Steps, Risk Rating
2. **`ask_analyst_question()`** — Stateless Q&A with scan context injected as system context
3. **`generate_threat_hunt_queries()`** — Generates Sigma YAML rules, Splunk SPL queries, and KQL for Microsoft Sentinel based on observed techniques

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.10+
- pip
- An Anthropic API key (get one free at [console.anthropic.com](https://console.anthropic.com))
- Optional: Nmap installed for real scans
- Optional: Wireshark/tshark for real PCAP captures

### 1. Clone the repo

```bash
git clone https://github.com/YOUR_USERNAME/soc-dashboard.git
cd soc-dashboard
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure environment

```bash
cp .env.example .env
```

Edit `.env` and add your keys:

```env
ANTHROPIC_API_KEY=sk-ant-api03-your-key-here
FLASK_SECRET_KEY=any-random-string
NVD_API_KEY=optional-for-higher-rate-limits
```

> **Free tier:** Anthropic gives $5 free credit on signup — enough for 200–500 AI report generations.

### 4. Run the server

```bash
python app.py
```

Open **[http://localhost:5000](http://localhost:5000)** in your browser.

---

## 📖 Usage

### Quick Demo (no Nmap required)
1. Open the dashboard at `http://localhost:5000`
2. Scroll to the **Quick Demo** section on the Upload panel
3. Click **Load Both** — loads a sample Nmap scan + Wireshark capture instantly
4. Click through **Alerts**, **Attack Graph**, **MITRE ATT&CK**, **Wireshark**
5. Click **AI Report** → **Run AI Analysis** to generate the incident report

### With Real Nmap Data

Run a scan and save the XML output:

```bash
# Basic version scan
nmap -sV -oX scan.xml 192.168.1.0/24

# Full scan with OS detection, scripts, and vuln detection
nmap -sV -sC -O --script vuln -oX scan.xml 192.168.1.0/24
```

Upload `scan.xml` to the Nmap box on the dashboard.

### With Real Wireshark Data

**Option A — Direct PCAP upload:**
Just drag your `.pcap` or `.pcapng` file onto the Wireshark upload zone. No conversion needed — scapy parses it directly.

**Option B — tshark export:**
```bash
tshark -r capture.pcap -T json > capture.json
```
Upload `capture.json` to the Wireshark upload zone.

### Export Options
- **SIEM JSON** — Click "SIEM JSON" in the sidebar. Downloads structured JSON ready for Splunk, Elastic SIEM, or Microsoft Sentinel ingestion
- **PDF Report** — Click "PDF Report". Downloads a professional incident report with executive summary, findings table, and AI analysis

---

## 🔐 Security Notes

- `.env` is excluded from git (add to `.gitignore`)
- No scan data is stored to disk permanently — all state lives in server memory per session
- NVD API queries are cached to reduce external calls
- This tool is for **authorized testing and educational use only**

---

## 🗺️ MITRE ATT&CK Coverage

The dashboard maps the following tactics:

| Tactic | Example Techniques Detected |
|---|---|
| Initial Access | Exposed web services, FTP |
| Execution | Jupyter Notebook RCE, open shells |
| Persistence | SSH backdoors, web shells |
| Credential Access | Telnet sniffing, Kerberos, LDAP |
| Discovery | SNMP, NetBIOS, DNS enumeration |
| Lateral Movement | SMB, RDP, VNC, SSH |
| Collection | Exposed databases, NFS shares |
| Command & Control | DNS tunneling, HTTP C2, suspicious ports |

---

## 🧰 Alert Correlation Rules

| Rule ID | Name | Severity |
|---|---|---|
| RULE-001 | Multi-Service Exposure | HIGH |
| RULE-002 | Cleartext Protocol Detected | CRITICAL |
| RULE-003 | Database Exposed to Network | HIGH |
| RULE-004 | Remote Desktop / VNC Exposed | HIGH |
| RULE-005 | Critical CVE Present (CVSS ≥ 9.0) | CRITICAL |
| RULE-006 | Windows Admin Shares Accessible | HIGH |
| RULE-007 | Default/Misconfigured SNMP | MEDIUM |
| RULE-008 | High Risk Score Host | HIGH |

---

## 🔮 Roadmap

- [ ] User authentication (login page)
- [ ] Persistent scan history (SQLite)
- [ ] Real-time network monitoring mode
- [ ] Email alerting for critical findings
- [ ] Docker container for one-command deploy
- [ ] Nmap scan launcher (run scans from browser)

---

## 📄 License

MIT License — free to use, modify, and distribute.

---

## 👤 Author

Built as a cybersecurity portfolio project demonstrating:
- Full-stack Python web development (Flask)
- Network security analysis (Nmap, Wireshark, PCAP)
- Threat intelligence (MITRE ATT&CK, CVE/CVSS, NVD)
- AI integration (Anthropic Claude API)
- SOC analyst workflows and tooling
