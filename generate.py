import requests
import json
from datetime import datetime, timezone, timedelta

# --- Hae CISA KEV (Known Exploited Vulnerabilities) ---
def fetch_cisa():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    data = r.json()
    vulns = data.get("vulnerabilities", [])

    # Ota 30 päivän sisällä lisätyt
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    recent = []
    for v in vulns:
        added = v.get("dateAdded", "")
        try:
            dt = datetime.strptime(added, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            if dt >= cutoff:
                recent.append(v)
        except ValueError:
            pass

    # Järjestä uusimmat ensin, ota max 10
    recent.sort(key=lambda x: x.get("dateAdded", ""), reverse=True)
    return recent[:10]


# --- Hae CVSS-pisteet NVD:stä ---
def fetch_cvss(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code != 200:
            return None, None
        data = r.json()
        items = data.get("vulnerabilities", [])
        if not items:
            return None, None
        metrics = items[0]["cve"].get("metrics", {})

        # Kokeile ensin CVSS 3.x, sitten 2.0
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                score = m.get("cvssData", {}).get("baseScore")
                severity = m.get("cvssData", {}).get("baseSeverity") or m.get("baseSeverity", "")
                return score, severity.upper()
        return None, None
    except Exception:
        return None, None


# --- Määritä severity värin perusteella ---
def severity_class(score):
    if score is None:
        return ""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


# --- Rakenna HTML ---
def build_html(vulns):
    updated = datetime.now(timezone.utc).strftime("%B %d, %Y at %H:%M UTC")

    cards = ""
    for v in vulns:
        cve = v.get("cveID", "N/A")
        product = v.get("product", "Unknown")
        vendor = v.get("vendorProject", "")
        desc = v.get("shortDescription", "No description available.")
        action = v.get("requiredAction", "See vendor advisory.")
        added = v.get("dateAdded", "")
        due = v.get("dueDate", "")

        score, severity = fetch_cvss(cve)
        cls = severity_class(score)
        badge_score = f"{score}" if score else "N/A"
        badge_sev = severity if severity else "UNKNOWN"

        cards += f"""
        <div class="vuln-card {cls}">
            <div class="vuln-header">
                <div>
                    <div class="cve-id">{cve}</div>
                    <div class="vuln-product">{vendor} — {product}</div>
                </div>
                <div class="cvss-badge">{badge_score} &mdash; {badge_sev}</div>
            </div>
            <div class="vuln-desc">{desc}</div>
            <div class="vuln-action">{action}</div>
            <div class="vuln-meta">Added: {added} &nbsp;·&nbsp; CISA due date: {due} &nbsp;·&nbsp; Source: CISA KEV + NIST NVD</div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Live Security Vulnerability Report</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f4f7f9; color: #333; min-height: 100vh; }}
        .header {{ background: #2c3e50; color: white; padding: 24px 32px; }}
        .header h1 {{ font-size: 1.4em; font-weight: 600; }}
        .header-meta {{ font-size: 0.85em; color: #bdc3c7; margin-top: 6px; }}
        .sources-bar {{ background: #ecf0f1; padding: 10px 32px; font-size: 0.82em; color: #7f8c8d; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }}
        .source-tag {{ background: white; border: 1px solid #dde; border-radius: 12px; padding: 2px 10px; color: #555; }}
        .content {{ max-width: 900px; margin: 0 auto; padding: 28px 24px; }}
        .count-bar {{ font-size: 0.88em; color: #7f8c8d; margin-bottom: 20px; }}
        .vuln-card {{ background: white; border-radius: 8px; border-left: 5px solid #e74c3c; box-shadow: 0 2px 6px rgba(0,0,0,0.07); padding: 20px 24px; margin-bottom: 16px; }}
        .vuln-card.high {{ border-left-color: #f39c12; }}
        .vuln-card.medium {{ border-left-color: #3498db; }}
        .vuln-card.low {{ border-left-color: #27ae60; }}
        .vuln-header {{ display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }}
        .cve-id {{ font-weight: 700; color: #e74c3c; font-size: 1.1em; }}
        .vuln-card.high .cve-id {{ color: #f39c12; }}
        .vuln-card.medium .cve-id {{ color: #3498db; }}
        .vuln-card.low .cve-id {{ color: #27ae60; }}
        .cvss-badge {{ background: #e74c3c; color: white; padding: 3px 10px; border-radius: 4px; font-size: 0.82em; font-weight: 600; white-space: nowrap; flex-shrink: 0; }}
        .vuln-card.high .cvss-badge {{ background: #f39c12; }}
        .vuln-card.medium .cvss-badge {{ background: #3498db; }}
        .vuln-card.low .cvss-badge {{ background: #27ae60; }}
        .vuln-product {{ font-weight: 600; color: #2c3e50; margin-top: 6px; font-size: 0.95em; }}
        .vuln-desc {{ margin-top: 8px; color: #555; font-size: 0.9em; line-height: 1.6; }}
        .vuln-action {{ margin-top: 10px; font-weight: 600; color: #27ae60; font-size: 0.88em; }}
        .vuln-action::before {{ content: "→ "; }}
        .vuln-meta {{ margin-top: 10px; font-size: 0.78em; color: #aaa; }}
        .empty {{ text-align: center; padding: 60px 20px; color: #7f8c8d; }}
        footer {{ text-align: center; padding: 24px; font-size: 0.8em; color: #aaa; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Critical Security Vulnerabilities</h1>
        <div class="header-meta">Last updated: {updated} &nbsp;·&nbsp; Auto-refreshes daily via GitHub Actions</div>
    </div>
    <div class="sources-bar">
        <span>Sources:</span>
        <span class="source-tag">CISA Known Exploited Vulnerabilities</span>
        <span class="source-tag">NIST NVD</span>
    </div>
    <div class="content">
        <div class="count-bar">Showing {len(vulns)} vulnerabilities added to CISA KEV in the last 30 days</div>
        {"".join(cards) if vulns else '<div class="empty">No new vulnerabilities found in the last 30 days.</div>'}
    </div>
    <footer>Data from CISA KEV &amp; NIST NVD &nbsp;·&nbsp; Updated automatically every day &nbsp;·&nbsp; Free &amp; open source</footer>
</body>
</html>"""
    return html


# --- Pääohjelma ---
if __name__ == "__main__":
    print("Fetching CISA KEV data...")
    vulns = fetch_cisa()
    print(f"Found {len(vulns)} recent vulnerabilities")

    print("Fetching CVSS scores from NVD...")
    html = build_html(vulns)

    with open("index.html", "w", encoding="utf-8") as f:
        f.write(html)

    print("index.html generated successfully.")
