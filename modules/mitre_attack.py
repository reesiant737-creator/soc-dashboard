import requests
import json

MITRE_TECHNIQUES = {
    "ftp": [("T1071.002", "Application Layer Protocol: File Transfer Protocols", "TA0011")],
    "ssh": [("T1021.004", "Remote Services: SSH", "TA0008")],
    "telnet": [("T1021.004", "Remote Services: SSH", "TA0008"), ("T1040", "Network Sniffing", "TA0006")],
    "smtp": [("T1071.003", "Application Layer Protocol: Mail Protocols", "TA0011")],
    "dns": [("T1071.004", "Application Layer Protocol: DNS", "TA0011"), ("T1568", "Dynamic Resolution", "TA0011")],
    "http": [("T1071.001", "Application Layer Protocol: Web Protocols", "TA0011")],
    "https": [("T1071.001", "Application Layer Protocol: Web Protocols", "TA0011")],
    "smb": [("T1021.002", "Remote Services: SMB/Windows Admin Shares", "TA0008"), ("T1570", "Lateral Tool Transfer", "TA0008")],
    "netbios": [("T1135", "Network Share Discovery", "TA0007")],
    "rdp": [("T1021.001", "Remote Services: Remote Desktop Protocol", "TA0008")],
    "mssql": [("T1505.001", "Server Software Component: SQL Stored Procedures", "TA0003")],
    "mysql": [("T1505.001", "Server Software Component: SQL Stored Procedures", "TA0003")],
    "oracle": [("T1505.001", "Server Software Component: SQL Stored Procedures", "TA0003")],
    "redis": [("T1557", "Adversary-in-the-Middle", "TA0006")],
    "mongodb": [("T1530", "Data from Cloud Storage", "TA0009")],
    "vnc": [("T1021.005", "Remote Services: VNC", "TA0008")],
    "snmp": [("T1602", "Data from Configuration Repository: SNMP", "TA0009")],
    "ldap": [("T1087.002", "Account Discovery: Domain Account", "TA0007")],
    "kerberos": [("T1558", "Steal or Forge Kerberos Tickets", "TA0006")],
    "nfs": [("T1039", "Data from Network Shared Drive", "TA0009")],
    "rpc": [("T1021.003", "Remote Services: Distributed Component Object Model", "TA0008")],
}

PORT_TO_SERVICE = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 135: "rpc", 139: "netbios", 143: "imap",
    443: "https", 445: "smb", 512: "rexec", 513: "rlogin", 514: "rsh",
    1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp",
    5900: "vnc", 6379: "redis", 8080: "http", 8443: "https",
    27017: "mongodb", 389: "ldap", 636: "ldap", 88: "kerberos",
    111: "rpc", 161: "snmp", 2049: "nfs",
}

TACTIC_NAMES = {
    "TA0001": "Initial Access", "TA0002": "Execution", "TA0003": "Persistence",
    "TA0004": "Privilege Escalation", "TA0005": "Defense Evasion", "TA0006": "Credential Access",
    "TA0007": "Discovery", "TA0008": "Lateral Movement", "TA0009": "Collection",
    "TA0010": "Exfiltration", "TA0011": "Command and Control", "TA0040": "Impact",
}


def map_ports_to_techniques(ports: list) -> list:
    """Map open ports to MITRE ATT&CK techniques."""
    seen = set()
    results = []
    for port in ports:
        if port.get("state") != "open":
            continue
        port_num = port.get("port", 0)
        service = port.get("service", "").lower() or PORT_TO_SERVICE.get(port_num, "")
        techniques = MITRE_TECHNIQUES.get(service, [])
        for tech_id, tech_name, tactic_id in techniques:
            key = (tech_id, port_num)
            if key not in seen:
                seen.add(key)
                results.append({
                    "technique_id": tech_id,
                    "technique_name": tech_name,
                    "tactic_id": tactic_id,
                    "tactic_name": TACTIC_NAMES.get(tactic_id, tactic_id),
                    "triggered_by_port": port_num,
                    "triggered_by_service": service,
                    "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}",
                })
    return results


def build_attack_chain(hosts: list) -> list:
    """Build a kill-chain ordered sequence of techniques across all hosts."""
    tactic_order = ["TA0001", "TA0002", "TA0003", "TA0004", "TA0005",
                    "TA0006", "TA0007", "TA0008", "TA0009", "TA0010", "TA0011", "TA0040"]
    all_techniques = []
    for host in hosts:
        techs = map_ports_to_techniques(host.get("ports", []))
        for t in techs:
            t["host"] = host.get("ip", "unknown")
            all_techniques.append(t)

    all_techniques.sort(key=lambda x: tactic_order.index(x["tactic_id"]) if x["tactic_id"] in tactic_order else 99)
    return all_techniques


def get_technique_detail(technique_id: str) -> dict:
    """Fetch technique details from MITRE ATT&CK TAXII server (online)."""
    try:
        clean_id = technique_id.replace("/", ".")
        url = f"https://attack.mitre.org/techniques/{clean_id}/"
        return {"technique_id": clean_id, "url": url}
    except Exception:
        return {"technique_id": technique_id}
