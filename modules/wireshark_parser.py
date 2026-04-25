import json
from collections import defaultdict, Counter
from datetime import datetime


def parse_pcap_json(json_content: str) -> dict:
    """
    Parse Wireshark JSON export (tshark -T json output).
    Generate with: tshark -r capture.pcap -T json > capture.json
    """
    try:
        packets = json.loads(json_content)
    except Exception as e:
        return {"error": f"Failed to parse JSON: {e}", "packets": [], "summary": {}}

    parsed = []
    for pkt in packets:
        layers = pkt.get("_source", {}).get("layers", {})
        parsed.append(_extract_packet(layers))

    return {
        "packets": parsed,
        "summary": _summarize_packets(parsed),
        "suspicious": _detect_suspicious(parsed),
        "conversations": _extract_conversations(parsed),
    }


def _extract_packet(layers: dict) -> dict:
    frame = layers.get("frame", {})
    eth = layers.get("eth", {})
    ip = layers.get("ip", {})
    tcp = layers.get("tcp", {})
    udp = layers.get("udp", {})
    dns = layers.get("dns", {})
    http = layers.get("http", {})

    proto = "OTHER"
    if "tcp" in layers:
        proto = "TCP"
    elif "udp" in layers:
        proto = "UDP"
    if "dns" in layers:
        proto = "DNS"
    if "http" in layers:
        proto = "HTTP"

    return {
        "time": frame.get("frame.time", ""),
        "length": int(frame.get("frame.len", 0)),
        "src_ip": ip.get("ip.src", ""),
        "dst_ip": ip.get("ip.dst", ""),
        "src_mac": eth.get("eth.src", ""),
        "dst_mac": eth.get("eth.dst", ""),
        "src_port": int(tcp.get("tcp.srcport", udp.get("udp.srcport", 0))),
        "dst_port": int(tcp.get("tcp.dstport", udp.get("udp.dstport", 0))),
        "protocol": proto,
        "tcp_flags": tcp.get("tcp.flags_tree", {}).get("tcp.flags.syn", ""),
        "dns_query": dns.get("dns.qry.name", "") if dns else "",
        "http_method": http.get("http.request.method", "") if http else "",
        "http_uri": http.get("http.request.uri", "") if http else "",
        "http_host": http.get("http.host", "") if http else "",
    }


def _summarize_packets(packets: list) -> dict:
    protos = Counter(p["protocol"] for p in packets)
    src_ips = Counter(p["src_ip"] for p in packets if p["src_ip"])
    dst_ports = Counter(p["dst_port"] for p in packets if p["dst_port"])
    return {
        "total_packets": len(packets),
        "protocol_breakdown": dict(protos.most_common(10)),
        "top_talkers": dict(src_ips.most_common(5)),
        "top_dest_ports": dict(dst_ports.most_common(10)),
    }


SUSPICIOUS_PORTS = {4444, 1337, 31337, 6666, 6667, 8888, 9999, 12345}
KNOWN_C2_PATTERNS = ["cmd.exe", "/bin/sh", "/bin/bash", "powershell", "wget ", "curl "]


def _detect_suspicious(packets: list) -> list:
    findings = []
    port_scan_tracker = defaultdict(set)

    for pkt in packets:
        src = pkt["src_ip"]
        dst = pkt["dst_ip"]
        dport = pkt["dst_port"]

        if dport in SUSPICIOUS_PORTS:
            findings.append({
                "type": "SUSPICIOUS_PORT",
                "severity": "HIGH",
                "description": f"Traffic to known suspicious port {dport}",
                "src": src, "dst": dst, "port": dport,
            })

        if src and dport:
            port_scan_tracker[src].add(dport)
            if len(port_scan_tracker[src]) > 50:
                findings.append({
                    "type": "PORT_SCAN",
                    "severity": "HIGH",
                    "description": f"Possible port scan from {src} ({len(port_scan_tracker[src])} unique dest ports)",
                    "src": src, "dst": dst, "port": dport,
                })
                port_scan_tracker[src] = set()

        uri = pkt.get("http_uri", "") or ""
        for pattern in KNOWN_C2_PATTERNS:
            if pattern.lower() in uri.lower():
                findings.append({
                    "type": "C2_INDICATOR",
                    "severity": "CRITICAL",
                    "description": f"Possible C2 shell command in HTTP URI: {uri[:80]}",
                    "src": src, "dst": dst, "port": dport,
                })

    seen = set()
    unique = []
    for f in findings:
        key = (f["type"], f["src"], f["dst"], f["port"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique[:50]


def _extract_conversations(packets: list) -> list:
    conv = defaultdict(lambda: {"packets": 0, "bytes": 0})
    for pkt in packets:
        src = pkt["src_ip"]
        dst = pkt["dst_ip"]
        if src and dst:
            key = tuple(sorted([src, dst]))
            conv[key]["packets"] += 1
            conv[key]["bytes"] += pkt.get("length", 0)

    result = [{"src": k[0], "dst": k[1], **v} for k, v in conv.items()]
    return sorted(result, key=lambda x: x["bytes"], reverse=True)[:20]
