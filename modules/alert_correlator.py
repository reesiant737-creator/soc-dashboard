from datetime import datetime
from collections import defaultdict


CORRELATION_RULES = [
    {
        "id": "RULE-001",
        "name": "Multi-Service Exposure",
        "description": "Host exposes 5+ high-risk services simultaneously",
        "severity": "HIGH",
        "check": lambda host: host.get("open_port_count", 0) >= 5,
    },
    {
        "id": "RULE-002",
        "name": "Cleartext Protocol Detected",
        "description": "Host running unencrypted protocols (telnet, ftp, rsh)",
        "severity": "CRITICAL",
        "check": lambda host: any(
            p.get("service") in ("telnet", "ftp", "rexec", "rsh", "rlogin")
            for p in host.get("ports", []) if p.get("state") == "open"
        ),
    },
    {
        "id": "RULE-003",
        "name": "Database Exposed to Network",
        "description": "Database service accessible on standard port",
        "severity": "HIGH",
        "check": lambda host: any(
            p.get("port") in (1433, 1521, 3306, 5432, 27017, 6379, 9200)
            for p in host.get("ports", []) if p.get("state") == "open"
        ),
    },
    {
        "id": "RULE-004",
        "name": "Remote Desktop / VNC Exposed",
        "description": "Remote access service (RDP/VNC) visible to scanner",
        "severity": "HIGH",
        "check": lambda host: any(
            p.get("port") in (3389, 5900, 5901)
            for p in host.get("ports", []) if p.get("state") == "open"
        ),
    },
    {
        "id": "RULE-005",
        "name": "Critical CVE Present",
        "description": "Host has one or more CVSS 9.0+ vulnerabilities",
        "severity": "CRITICAL",
        "check": lambda host: host.get("max_cvss", 0) >= 9.0,
    },
    {
        "id": "RULE-006",
        "name": "Windows Admin Shares Accessible",
        "description": "SMB port 445 open — potential lateral movement vector",
        "severity": "HIGH",
        "check": lambda host: any(
            p.get("port") == 445 and p.get("state") == "open"
            for p in host.get("ports", [])
        ),
    },
    {
        "id": "RULE-007",
        "name": "Default/Misconfigured SNMP",
        "description": "SNMP open — potential info disclosure via community strings",
        "severity": "MEDIUM",
        "check": lambda host: any(
            p.get("port") == 161 and p.get("state") == "open"
            for p in host.get("ports", [])
        ),
    },
    {
        "id": "RULE-008",
        "name": "High Risk Score Host",
        "description": "Aggregate risk score exceeds threshold",
        "severity": "HIGH",
        "check": lambda host: host.get("risk_score", 0) >= 70,
    },
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def correlate_alerts(hosts: list) -> dict:
    """Run all correlation rules across all hosts and produce alert summary."""
    alerts = []
    host_alert_map = defaultdict(list)

    for host in hosts:
        for rule in CORRELATION_RULES:
            try:
                if rule["check"](host):
                    alert = {
                        "alert_id": f"{rule['id']}-{host['ip'].replace('.', '')}",
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "description": rule["description"],
                        "severity": rule["severity"],
                        "host_ip": host["ip"],
                        "host_hostname": host.get("hostname", host["ip"]),
                        "timestamp": datetime.now().isoformat(),
                        "mitigations": _get_mitigations(rule["id"]),
                    }
                    alerts.append(alert)
                    host_alert_map[host["ip"]].append(alert)
            except Exception:
                pass

    alerts.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))

    severity_counts = defaultdict(int)
    for a in alerts:
        severity_counts[a["severity"]] += 1

    return {
        "alerts": alerts,
        "total": len(alerts),
        "severity_breakdown": dict(severity_counts),
        "host_alert_map": {k: [a["alert_id"] for a in v] for k, v in host_alert_map.items()},
        "most_affected_host": max(host_alert_map.keys(), key=lambda k: len(host_alert_map[k]), default=None),
    }


def _get_mitigations(rule_id: str) -> list:
    mitigations = {
        "RULE-001": ["Firewall segment high-risk services", "Apply least-privilege network access"],
        "RULE-002": ["Replace telnet/ftp with SSH/SFTP", "Enforce encrypted protocols only"],
        "RULE-003": ["Move DB behind internal network", "Restrict DB port via firewall"],
        "RULE-004": ["Enable NLA for RDP", "Place behind VPN", "Use jump host"],
        "RULE-005": ["Apply vendor patches immediately", "Check exploit availability on ExploitDB"],
        "RULE-006": ["Disable SMBv1", "Restrict 445 to needed hosts only"],
        "RULE-007": ["Disable SNMP if unused", "Use SNMPv3 with auth/encryption"],
        "RULE-008": ["Prioritize patching", "Review firewall rules", "Enable IDS monitoring"],
    }
    return mitigations.get(rule_id, ["Review and remediate per security policy"])
