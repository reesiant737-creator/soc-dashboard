from collections import defaultdict


def build_attack_graph(hosts: list, techniques: list, alerts: list) -> dict:
    """
    Build a vis.js-compatible attack graph showing:
    - Attacker node → hosts → services → MITRE techniques
    """
    nodes = []
    edges = []
    node_ids = {}
    counter = [0]

    def next_id():
        counter[0] += 1
        return counter[0]

    def add_node(key, label, group, title="", shape="dot", size=20, color=None):
        if key not in node_ids:
            nid = next_id()
            node_ids[key] = nid
            node = {"id": nid, "label": label, "group": group, "title": title, "shape": shape, "size": size}
            if color:
                node["color"] = color
            nodes.append(node)
        return node_ids[key]

    attacker_id = add_node("attacker", "Attacker", "attacker", "Threat Actor", "triangle", 35, "#dc3545")

    alert_host_map = defaultdict(list)
    for a in alerts:
        alert_host_map[a["host_ip"]].append(a["severity"])

    for host in hosts:
        ip = host["ip"]
        risk = host.get("risk_score", 0)
        max_cvss = host.get("max_cvss", 0.0)

        if risk >= 70 or max_cvss >= 9.0:
            host_color = "#dc3545"
        elif risk >= 40 or max_cvss >= 7.0:
            host_color = "#fd7e14"
        else:
            host_color = "#28a745"

        severities = alert_host_map.get(ip, [])
        alert_summary = f"Alerts: {', '.join(set(severities))}" if severities else "No alerts"
        host_label = f"{ip}\n{host.get('hostname', ip)[:15]}"
        host_title = (
            f"IP: {ip}<br>OS: {host.get('os', {}).get('name', 'Unknown')}<br>"
            f"Risk: {risk}/100<br>Max CVSS: {max_cvss}<br>{alert_summary}"
        )
        host_id = add_node(f"host_{ip}", host_label, "host", host_title, "box", 25, host_color)
        edges.append({"from": attacker_id, "to": host_id, "label": "scans", "arrows": "to", "color": "#6c757d"})

        service_groups = defaultdict(list)
        for port in host.get("ports", []):
            if port.get("state") == "open":
                svc = port.get("service", "unknown")
                service_groups[svc].append(port["port"])

        for svc, ports in list(service_groups.items())[:8]:
            svc_key = f"svc_{ip}_{svc}"
            port_str = ",".join(str(p) for p in ports[:3])
            svc_id = add_node(svc_key, f"{svc}\n:{port_str}", "service",
                              f"Service: {svc}<br>Ports: {port_str}", "ellipse", 18)
            edges.append({"from": host_id, "to": svc_id, "label": "", "arrows": "to", "color": "#adb5bd"})

    seen_techniques = {}
    for tech in techniques:
        tid = tech["technique_id"]
        tactic = tech["tactic_name"]
        host_ip = tech.get("host", "")
        tech_key = f"tech_{tid}_{host_ip}"

        tactic_colors = {
            "Initial Access": "#6f42c1", "Execution": "#e83e8c",
            "Persistence": "#fd7e14", "Privilege Escalation": "#dc3545",
            "Defense Evasion": "#6c757d", "Credential Access": "#20c997",
            "Discovery": "#17a2b8", "Lateral Movement": "#007bff",
            "Collection": "#ffc107", "Exfiltration": "#dc3545",
            "Command and Control": "#343a40", "Impact": "#721c24",
        }
        tcolor = tactic_colors.get(tactic, "#6c757d")

        tech_id = add_node(tech_key, f"{tid}\n{tech['technique_name'][:20]}",
                           "technique",
                           f"Technique: {tid}<br>{tech['technique_name']}<br>Tactic: {tactic}<br>Host: {host_ip}",
                           "diamond", 22, tcolor)

        svc_key = f"svc_{host_ip}_{tech.get('triggered_by_service', '')}"
        if svc_key in node_ids:
            edges.append({"from": node_ids[svc_key], "to": tech_id, "label": tactic[:10],
                          "arrows": "to", "color": tcolor, "dashes": True})

    return {
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "host_count": len(hosts),
        }
    }
