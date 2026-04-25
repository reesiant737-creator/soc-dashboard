import requests
import os
from functools import lru_cache

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

SEVERITY_MAP = {
    "CRITICAL": {"color": "#dc3545", "icon": "skull", "score_min": 9.0},
    "HIGH": {"color": "#fd7e14", "icon": "exclamation-triangle", "score_min": 7.0},
    "MEDIUM": {"color": "#ffc107", "icon": "exclamation-circle", "score_min": 4.0},
    "LOW": {"color": "#17a2b8", "icon": "info-circle", "score_min": 0.1},
    "NONE": {"color": "#6c757d", "icon": "check-circle", "score_min": 0.0},
}


def score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "NONE"


@lru_cache(maxsize=256)
def lookup_cves_for_product(product: str, version: str = "") -> list:
    """Query NVD for CVEs matching a product/version string."""
    if not product or len(product) < 3:
        return []

    api_key = os.getenv("NVD_API_KEY", "")
    headers = {"apiKey": api_key} if api_key else {}
    params = {"keywordSearch": product, "resultsPerPage": 10}
    if version:
        params["keywordSearch"] = f"{product} {version}"

    try:
        resp = requests.get(NVD_BASE, params=params, headers=headers, timeout=10)
        if resp.status_code != 200:
            return []
        data = resp.json()
        return _parse_nvd_response(data)
    except Exception:
        return []


def _parse_nvd_response(data: dict) -> list:
    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        desc_list = cve.get("descriptions", [])
        description = next((d["value"] for d in desc_list if d["lang"] == "en"), "No description")

        metrics = cve.get("metrics", {})
        score = 0.0
        vector = ""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                score = float(cvss_data.get("baseScore", 0.0))
                vector = cvss_data.get("vectorString", "")
                break

        severity = score_to_severity(score)
        results.append({
            "cve_id": cve_id,
            "description": description[:200] + "..." if len(description) > 200 else description,
            "cvss_score": score,
            "cvss_vector": vector,
            "severity": severity,
            "severity_color": SEVERITY_MAP[severity]["color"],
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "published": cve.get("published", ""),
        })
    return sorted(results, key=lambda x: x["cvss_score"], reverse=True)


def enrich_hosts_with_cves(hosts: list) -> list:
    """Add CVE data to each host based on detected services/products."""
    for host in hosts:
        host_cves = []
        for port in host.get("ports", []):
            if port.get("state") != "open":
                continue
            product = port.get("product", "")
            version = port.get("version", "")
            if product:
                cves = lookup_cves_for_product(product, version)
                for cve in cves:
                    cve["port"] = port["port"]
                    cve["service"] = port["service"]
                host_cves.extend(cves)

        host["cves"] = sorted(host_cves, key=lambda x: x["cvss_score"], reverse=True)[:20]
        host["max_cvss"] = max((c["cvss_score"] for c in host["cves"]), default=0.0)
        host["critical_cve_count"] = sum(1 for c in host["cves"] if c["severity"] == "CRITICAL")
    return hosts
