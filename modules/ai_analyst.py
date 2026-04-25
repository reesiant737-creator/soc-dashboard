import anthropic
import json
import os


def get_client():
    return anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))


DEMO_REPORT = """## Executive Summary
This network scan identified **6 hosts** across the 192.168.1.0/24 subnet with a combined **22 security alerts**, including 3 Critical and 17 High severity findings. Immediate remediation is required on multiple hosts exposing cleartext protocols, unauthenticated database services, and suspected C2 infrastructure.

## Critical Findings
- **192.168.1.100** — Host running ports 4444, 1337, and 31337 simultaneously; consistent with active C2 implant or reverse shell listener
- **192.168.1.10 (dc01.corp.local)** — Domain Controller exposing Telnet (port 23) in cleartext alongside RDP and VNC; trivial credential interception risk
- **192.168.1.30 (dbserver01)** — Four separate database engines (MSSQL, Oracle, MySQL, MongoDB) exposed directly on the network with no firewall filtering detected
- **192.168.1.20 (webserver01)** — vsftpd 2.3.4 detected — this version contains a **backdoor (CVE-2011-2523)** with a CVSS score of 10.0
- **192.168.1.40 (devbox)** — Jupyter Notebook on port 8888 allows unauthenticated remote code execution

## Attack Surface Assessment
An attacker with initial foothold could:
1. Intercept Telnet credentials on dc01 → gain Domain Admin within minutes
2. Exploit vsftpd backdoor on webserver01 → instant root shell
3. Pivot through SMB/445 on dc01 → lateral movement across entire domain
4. Access MongoDB/Redis on dbserver01 without authentication → full data exfiltration
5. Use Jupyter Notebook RCE on devbox → persistent backdoor, crypto mining, or ransomware staging

## Priority Remediation Steps
1. **[IMMEDIATE]** Isolate 192.168.1.100 — C2 indicators present, treat as compromised
2. **[IMMEDIATE]** Patch or replace vsftpd 2.3.4 on webserver01 — known backdoor, CVSS 10.0
3. **[24 HRS]** Disable Telnet on dc01, enforce SSH with key-based auth only
4. **[24 HRS]** Firewall all database ports (1433, 1521, 3306, 27017, 6379) to app-tier only
5. **[48 HRS]** Require authentication on Jupyter Notebook or move behind VPN

## Risk Rating
**CRITICAL** — Active C2 indicators combined with a known-backdoored service and unauthenticated database exposure represent an imminent breach scenario requiring immediate incident response.

---
*⚠️ Demo mode — add your Anthropic API key to .env for live AI analysis*"""


def analyze_scan_results(scan_data: dict, alerts: list, techniques: list) -> str:
    """Use Claude to generate a SOC analyst narrative from scan data."""
    if not os.getenv("ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_API_KEY") == "your_key_here":
        return DEMO_REPORT

    client = get_client()

    host_summary = []
    for h in scan_data.get("hosts", [])[:10]:
        host_summary.append({
            "ip": h["ip"],
            "hostname": h.get("hostname", h["ip"]),
            "open_ports": [f"{p['port']}/{p['service']}" for p in h.get("ports", []) if p.get("state") == "open"][:10],
            "risk_score": h.get("risk_score", 0),
            "max_cvss": h.get("max_cvss", 0.0),
            "critical_cves": h.get("critical_cve_count", 0),
            "os": h.get("os", {}).get("name", "Unknown"),
        })

    alert_summary = [
        {"severity": a["severity"], "rule": a["rule_name"], "host": a["host_ip"]}
        for a in alerts[:15]
    ]

    technique_summary = list({t["technique_id"]: t for t in techniques}.values())[:10]

    prompt = f"""You are a senior SOC analyst. Analyze the following network scan results and produce a concise incident report.

SCAN DATA:
- Total hosts: {scan_data.get('total_hosts', 0)}
- Scan time: {scan_data.get('scan_time', 'unknown')}

HOSTS:
{json.dumps(host_summary, indent=2)}

TRIGGERED ALERTS ({len(alerts)} total):
{json.dumps(alert_summary, indent=2)}

MITRE ATT&CK TECHNIQUES OBSERVED:
{json.dumps([{"id": t["technique_id"], "name": t["technique_name"], "tactic": t["tactic_name"]} for t in technique_summary], indent=2)}

Write a professional SOC analyst report with:
1. **Executive Summary** (2-3 sentences, plain English for management)
2. **Critical Findings** (bullet list of the most dangerous findings)
3. **Attack Surface Assessment** (what an attacker could do with this foothold)
4. **Priority Remediation Steps** (top 5, ordered by urgency)
5. **Risk Rating**: CRITICAL / HIGH / MEDIUM / LOW (with one-line justification)

Be direct, professional, and actionable. No fluff."""

    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1500,
        messages=[{"role": "user", "content": prompt}],
    )
    return message.content[0].text


def ask_analyst_question(question: str, context: dict) -> str:
    if not os.getenv("ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_API_KEY") == "your_key_here":
        return f"""**Demo mode answer to:** *{question}*

Based on the scan data, the most dangerous host is **192.168.1.100** — it has ports 4444, 1337, and 31337 open simultaneously, which are classic reverse shell and C2 ports. Combined with the vsftpd backdoor on 192.168.1.20 (CVSS 10.0), an attacker could have persistent access across the network.

*Add your Anthropic API key to .env for real AI-powered answers.*"""
    """Interactive Q&A with Claude about the current scan."""
    client = get_client()

    system = """You are a cybersecurity SOC analyst AI assistant.
You have access to network scan data and answer questions about vulnerabilities,
attack paths, MITRE ATT&CK techniques, CVEs, and remediation.
Be concise, technical, and accurate. Format with markdown."""

    context_str = json.dumps({
        "hosts": len(context.get("hosts", [])),
        "alerts": len(context.get("alerts", [])),
        "techniques": len(context.get("techniques", [])),
        "top_hosts": [
            {"ip": h["ip"], "risk": h.get("risk_score", 0), "ports": h.get("open_port_count", 0)}
            for h in sorted(context.get("hosts", []), key=lambda x: x.get("risk_score", 0), reverse=True)[:5]
        ]
    }, indent=2)

    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=800,
        system=system,
        messages=[
            {"role": "user", "content": f"Scan context:\n{context_str}\n\nQuestion: {question}"}
        ],
    )
    return message.content[0].text


def generate_threat_hunt_queries(hosts: list, techniques: list) -> str:
    if not os.getenv("ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_API_KEY") == "your_key_here":
        return """## Demo Threat Hunt Queries

### Sigma Rule — C2 Beacon Detection
```yaml
title: Suspicious Outbound Connection to Known C2 Ports
status: experimental
logsource:
  category: network_connection
detection:
  selection:
    DestinationPort|contains: [4444, 1337, 31337, 6666, 9999]
  condition: selection
level: high
tags: [attack.command_and_control, attack.t1071]
```

### Sigma Rule — Telnet Usage
```yaml
title: Cleartext Telnet Protocol Detected
logsource:
  category: network_connection
detection:
  selection:
    DestinationPort: 23
  condition: selection
level: medium
```

### Splunk SPL — Database Exposed to Untrusted Hosts
```
index=network sourcetype=firewall dest_port IN (1433, 3306, 27017, 6379, 1521)
| stats count by src_ip, dest_ip, dest_port
| where count > 10
```

### Splunk SPL — Port Scan Detection
```
index=network sourcetype=firewall
| stats dc(dest_port) as unique_ports by src_ip
| where unique_ports > 50
| sort -unique_ports
```

### KQL — Microsoft Sentinel: Reverse Shell Ports
```
NetworkCommunicationEvents
| where RemotePort in (4444, 1337, 31337, 4445, 8888)
| summarize count() by LocalIP, RemoteIP, RemotePort
| where count_ > 5
```

### KQL — Suspicious DNS Queries
```
DnsEvents
| where Name endswith ".xyz" or Name endswith ".top" or Name endswith ".pw"
| summarize count() by Computer, Name
| where count_ > 3
```

*Add your Anthropic API key to .env for AI-generated custom queries based on your actual scan.*"""
    """Generate threat hunting queries (Sigma/KQL/Splunk SPL) based on findings."""
    client = get_client()

    observed = [{"id": t["technique_id"], "name": t["technique_name"]} for t in techniques[:8]]
    services = list({p["service"] for h in hosts for p in h.get("ports", []) if p.get("state") == "open"})[:10]

    prompt = f"""Given these observed MITRE ATT&CK techniques and services from a network scan,
generate practical threat hunting queries.

Techniques: {json.dumps(observed)}
Exposed services: {services}

Provide:
1. 3 Sigma detection rules (YAML format)
2. 2 Splunk SPL queries
3. 2 KQL queries for Microsoft Sentinel

Focus on the most dangerous techniques observed."""

    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1200,
        messages=[{"role": "user", "content": prompt}],
    )
    return message.content[0].text
