import io
from collections import defaultdict, Counter
from datetime import datetime


def parse_pcap_bytes(data: bytes) -> dict:
    """Parse a raw .pcap/.pcapng file using scapy."""
    try:
        from scapy.all import rdpcap, PcapReader
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.dns import DNS, DNSQR
        from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
        from scapy.layers.l2 import Ether
    except ImportError:
        return {"error": "scapy not installed. Run: pip install scapy", "packets": [], "summary": {}}

    try:
        pkts = rdpcap(io.BytesIO(data))
    except Exception as e:
        return {"error": f"Failed to read PCAP: {e}", "packets": [], "summary": {}}

    parsed = []
    for pkt in pkts:
        p = _extract_scapy_packet(pkt)
        if p:
            parsed.append(p)

    from modules.wireshark_parser import _summarize_packets, _detect_suspicious, _extract_conversations
    return {
        "packets": parsed,
        "summary": _summarize_packets(parsed),
        "suspicious": _detect_suspicious(parsed),
        "conversations": _extract_conversations(parsed),
        "total_raw": len(pkts),
    }


def _extract_scapy_packet(pkt) -> dict | None:
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.dns import DNS, DNSQR
        from scapy.layers.l2 import Ether

        if not pkt.haslayer(IP):
            return None

        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        proto = "OTHER"
        src_port = 0
        dst_port = 0
        dns_query = ""
        http_method = ""
        http_uri = ""
        http_host = ""
        src_mac = ""
        dst_mac = ""

        if pkt.haslayer(Ether):
            src_mac = pkt[Ether].src
            dst_mac = pkt[Ether].dst

        if pkt.haslayer(TCP):
            proto = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport

            # Try scapy HTTP layer
            try:
                from scapy.layers.http import HTTPRequest, HTTPResponse
                if pkt.haslayer(HTTPRequest):
                    proto = "HTTP"
                    req = pkt[HTTPRequest]
                    http_method = req.Method.decode(errors="replace") if req.Method else ""
                    http_uri = req.Path.decode(errors="replace") if req.Path else ""
                    http_host = req.Host.decode(errors="replace") if req.Host else ""
            except Exception:
                pass

            # Raw payload sniff for HTTP
            if proto == "TCP" and pkt.haslayer("Raw"):
                raw = bytes(pkt["Raw"].load)
                if raw.startswith(b"GET ") or raw.startswith(b"POST ") or raw.startswith(b"HEAD "):
                    proto = "HTTP"
                    parts = raw.split(b"\r\n")
                    first = parts[0].decode(errors="replace").split(" ")
                    if len(first) >= 2:
                        http_method = first[0]
                        http_uri = first[1]
                    for line in parts[1:]:
                        if line.lower().startswith(b"host:"):
                            http_host = line[5:].decode(errors="replace").strip()
                            break

        elif pkt.haslayer(UDP):
            proto = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

            if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
                proto = "DNS"
                try:
                    dns_query = pkt[DNS].qd.qname.decode(errors="replace").rstrip(".")
                except Exception:
                    pass

        elif pkt.haslayer(ICMP):
            proto = "ICMP"

        ts = float(pkt.time)
        time_str = datetime.fromtimestamp(ts).strftime("%b %d, %Y %H:%M:%S.%f")

        return {
            "time": time_str,
            "length": len(pkt),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto,
            "tcp_flags": "",
            "dns_query": dns_query,
            "http_method": http_method,
            "http_uri": http_uri,
            "http_host": http_host,
        }
    except Exception:
        return None
