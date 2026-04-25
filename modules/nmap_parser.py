import xmltodict
import json
from datetime import datetime


def parse_nmap_xml(xml_content: str) -> dict:
    """Parse Nmap XML output into structured host/port data."""
    try:
        raw = xmltodict.parse(xml_content)
    except Exception as e:
        return {"error": f"Failed to parse XML: {e}", "hosts": []}

    hosts = []
    nmaprun = raw.get("nmaprun", {})
    host_data = nmaprun.get("host", [])

    if isinstance(host_data, dict):
        host_data = [host_data]

    for host in host_data:
        parsed_host = _parse_host(host)
        if parsed_host:
            hosts.append(parsed_host)

    return {
        "scan_time": nmaprun.get("@startstr", datetime.now().isoformat()),
        "scanner_version": nmaprun.get("@version", "unknown"),
        "hosts": hosts,
        "total_hosts": len(hosts),
    }


def _parse_host(host: dict) -> dict | None:
    status = host.get("status", {}).get("@state", "unknown")
    if status != "up":
        return None

    addresses = host.get("address", [])
    if isinstance(addresses, dict):
        addresses = [addresses]

    ip = next((a["@addr"] for a in addresses if a.get("@addrtype") == "ipv4"), "unknown")
    mac = next((a["@addr"] for a in addresses if a.get("@addrtype") == "mac"), None)
    hostname_block = host.get("hostnames", {}).get("hostname", {})
    if isinstance(hostname_block, list):
        hostname = hostname_block[0].get("@name", ip)
    elif isinstance(hostname_block, dict):
        hostname = hostname_block.get("@name", ip)
    else:
        hostname = ip

    ports = _parse_ports(host.get("ports", {}).get("port", []))
    os_info = _parse_os(host.get("os", {}))

    return {
        "ip": ip,
        "mac": mac,
        "hostname": hostname,
        "status": status,
        "ports": ports,
        "os": os_info,
        "open_port_count": sum(1 for p in ports if p["state"] == "open"),
        "risk_score": _calculate_risk(ports, os_info),
    }


def _parse_ports(port_data) -> list:
    if not port_data:
        return []
    if isinstance(port_data, dict):
        port_data = [port_data]

    ports = []
    for port in port_data:
        service = port.get("service", {})
        script_data = port.get("script", [])
        if isinstance(script_data, dict):
            script_data = [script_data]

        ports.append({
            "port": int(port.get("@portid", 0)),
            "protocol": port.get("@protocol", "tcp"),
            "state": port.get("state", {}).get("@state", "unknown"),
            "service": service.get("@name", "unknown"),
            "product": service.get("@product", ""),
            "version": service.get("@version", ""),
            "cpe": service.get("cpe", ""),
            "scripts": [{"id": s.get("@id"), "output": s.get("@output")} for s in script_data],
        })
    return ports


def _parse_os(os_data: dict) -> dict:
    if not os_data:
        return {}
    matches = os_data.get("osmatch", [])
    if isinstance(matches, dict):
        matches = [matches]
    if not matches:
        return {}
    best = matches[0]
    return {
        "name": best.get("@name", "unknown"),
        "accuracy": int(best.get("@accuracy", 0)),
        "family": best.get("osclass", {}).get("@osfamily", "") if isinstance(best.get("osclass"), dict) else "",
    }


HIGH_RISK_PORTS = {21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 512, 513, 514,
                   1433, 1521, 3306, 3389, 4444, 5900, 6379, 8080, 8443, 27017}


def _calculate_risk(ports: list, os_info: dict) -> int:
    score = 0
    for p in ports:
        if p["state"] != "open":
            continue
        score += 10
        if p["port"] in HIGH_RISK_PORTS:
            score += 20
        if p["service"] in ("telnet", "ftp", "rexec", "rsh"):
            score += 30
    if os_info.get("family", "").lower() in ("windows", "linux"):
        score += 5
    return min(score, 100)


def parse_nmap_text(text: str) -> dict:
    """Lightweight parser for plain-text nmap output (fallback)."""
    hosts = []
    current = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("Nmap scan report for"):
            if current:
                hosts.append(current)
            ip_part = line.split("for")[-1].strip()
            current = {"ip": ip_part, "hostname": ip_part, "ports": [], "os": {}, "status": "up", "mac": None}
        elif current and "/tcp" in line or (current and "/udp" in line):
            parts = line.split()
            if len(parts) >= 3:
                port_proto = parts[0].split("/")
                current["ports"].append({
                    "port": int(port_proto[0]),
                    "protocol": port_proto[1] if len(port_proto) > 1 else "tcp",
                    "state": parts[1],
                    "service": parts[2],
                    "product": " ".join(parts[3:]),
                    "version": "",
                    "cpe": "",
                    "scripts": [],
                })
    if current:
        hosts.append(current)

    for h in hosts:
        h["open_port_count"] = sum(1 for p in h["ports"] if p["state"] == "open")
        h["risk_score"] = _calculate_risk(h["ports"], h["os"])

    return {"hosts": hosts, "total_hosts": len(hosts), "scan_time": datetime.now().isoformat()}
