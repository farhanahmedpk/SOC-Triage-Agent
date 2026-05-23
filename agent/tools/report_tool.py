"""
report_tool.py
Incident report generator for the SOC Triage Agent.
Takes an enriched alert and produces a structured incident report.
"""

from datetime import datetime, timezone


# ── Verdict Logic ─────────────────────────────────────────────────────────────

ESCALATE_TYPES = {
    "Malware C2 Communication",
    "Data Exfiltration",
    "Privilege Escalation",
}

SEVERITY_VERDICTS = {
    "Critical": "ESCALATE TO TIER-2",
    "High":     "ESCALATE TO TIER-2",
    "Medium":   "MONITOR & INVESTIGATE",
    "Low":      "LOG & CLOSE",
}

RECOMMENDED_ACTIONS = {
    "Malware C2 Communication": [
        "Isolate affected host immediately",
        "Block source IP at firewall",
        "Capture memory dump for forensics",
        "Scan all hosts for similar C2 indicators",
        "Notify incident response team",
    ],
    "Data Exfiltration": [
        "Block source IP at firewall",
        "Isolate affected host",
        "Preserve network logs for forensics",
        "Identify what data was transferred",
        "Notify data protection officer",
    ],
    "Privilege Escalation": [
        "Lock affected user account",
        "Review recent sudo/admin activity",
        "Check for persistence mechanisms",
        "Audit privilege changes in last 24 hours",
        "Escalate to Tier-2 analyst",
    ],
    "Brute Force Login": [
        "Block source IP at firewall",
        "Enable account lockout policy",
        "Check if any login succeeded",
        "Enable MFA on targeted accounts",
    ],
    "Phishing Email Link Clicked": [
        "Isolate affected workstation",
        "Reset user credentials immediately",
        "Check for malware download or execution",
        "Block malicious domain at DNS",
        "Notify user awareness team",
    ],
    "Suspicious PowerShell Execution": [
        "Capture and decode the PowerShell command",
        "Check for persistence (scheduled tasks, registry)",
        "Scan host with EDR tool",
        "Review parent process of PowerShell",
    ],
    "Port Scan Detected": [
        "Block source IP at firewall",
        "Review firewall rules for exposed ports",
        "Check if scan preceded any exploitation attempt",
    ],
    "DNS Tunneling": [
        "Block suspicious domain at DNS layer",
        "Inspect DNS query logs for data patterns",
        "Isolate affected host",
        "Check for data exfiltration via DNS",
    ],
    "Unauthorized Access Attempt": [
        "Block source IP at firewall",
        "Review RDP/remote access logs",
        "Disable RDP if not required",
        "Enable NLA for RDP",
    ],
    "Failed VPN Login": [
        "Monitor for successful login after failures",
        "Enable MFA on VPN",
        "Block IP after threshold exceeded",
    ],
}

DEFAULT_ACTIONS = [
    "Review alert details manually",
    "Block source IP if confirmed malicious",
    "Escalate if activity continues",
]


# ── Report Generator ──────────────────────────────────────────────────────────

def generate_report(alert: dict) -> dict:
    """
    Generate a structured incident report from an enriched alert.

    Args:
        alert: Enriched alert dict (output of enrich_tool.enrich_alert).

    Returns:
        Incident report dict.
    """
    enrichment    = alert.get("enrichment", {})
    severity      = alert.get("severity", "Unknown")
    alert_type    = alert.get("alert_type", "Unknown")
    source_ip     = alert.get("source_ip", "Unknown")
    hostname      = alert.get("hostname", "Unknown")
    username      = alert.get("username", "Unknown")
    mitre_tactic  = alert.get("mitre_tactic", "Unknown")
    mitre_tech    = alert.get("mitre_technique", "Unknown")
    description   = alert.get("description", "No description.")
    timestamp     = alert.get("timestamp", "Unknown")
    alert_id      = alert.get("alert_id", "UNKNOWN")
    protocol      = alert.get("protocol", "Unknown")
    dest_port     = alert.get("destination_port", "Unknown")
    bytes_sent    = alert.get("bytes_sent", 0)
    action        = alert.get("action", "Unknown")

    # Verdict
    verdict = SEVERITY_VERDICTS.get(severity, "REVIEW MANUALLY")
    if alert_type in ESCALATE_TYPES and severity not in ("Critical", "High"):
        verdict = "ESCALATE TO TIER-2"  # override for dangerous types

    # Threat intel summary
    is_malicious      = enrichment.get("is_malicious", False)
    confidence_score  = enrichment.get("confidence_score", 0)
    ip_country        = enrichment.get("country", "Unknown")
    ip_isp            = enrichment.get("isp", "Unknown")
    ip_reports        = enrichment.get("total_reports", 0)
    is_tor            = enrichment.get("is_tor", False)
    enrich_error      = enrichment.get("error")

    threat_label = "CONFIRMED MALICIOUS" if is_malicious else \
                   "UNCONFIRMED (clean AbuseIPDB score)" if not enrich_error else \
                   f"ENRICHMENT ERROR: {enrich_error}"

    # Severity upgrade note
    upgrade_note = ""
    if alert.get("severity_upgraded"):
        upgrade_note = (
            f"⚠️  Severity upgraded from "
            f"{alert['severity_original']} → {severity} "
            f"(confirmed malicious source IP)"
        )

    # Recommended actions
    actions = RECOMMENDED_ACTIONS.get(alert_type, DEFAULT_ACTIONS)

    # Build report dict
    report = {
        "report_id":         f"IR-{alert_id}",
        "generated_at":      datetime.now(timezone.utc).isoformat(),
        "alert_id":          alert_id,
        "verdict":           verdict,
        "severity":          severity,
        "severity_upgraded": alert.get("severity_upgraded", False),
        "alert_type":        alert_type,
        "description":       description,
        "timeline": {
            "alert_timestamp": timestamp,
            "report_generated": datetime.now(timezone.utc).isoformat(),
        },
        "affected_assets": {
            "hostname": hostname,
            "username": username,
        },
        "network": {
            "source_ip":        source_ip,
            "destination_port": dest_port,
            "protocol":         protocol,
            "bytes_sent":       bytes_sent,
            "action":           action,
        },
        "threat_intel": {
            "source_ip":        source_ip,
            "verdict":          threat_label,
            "confidence_score": confidence_score,
            "total_reports":    ip_reports,
            "country":          ip_country,
            "isp":              ip_isp,
            "is_tor_exit_node": is_tor,
        },
        "mitre_attack": {
            "tactic":    mitre_tactic,
            "technique": mitre_tech,
        },
        "recommended_actions": actions,
        "upgrade_note":        upgrade_note,
    }

    return report


def format_report_text(report: dict) -> str:
    """
    Format an incident report dict as a readable text report.

    Args:
        report: Output of generate_report().

    Returns:
        Formatted string report.
    """
    sep   = "=" * 60
    sep2  = "-" * 60
    lines = []

    lines.append(sep)
    lines.append(f"  INCIDENT REPORT — {report['report_id']}")
    lines.append(f"  Generated : {report['generated_at']}")
    lines.append(sep)

    lines.append(f"\n  VERDICT   : 🔴 {report['verdict']}")
    lines.append(f"  SEVERITY  : {report['severity']}")
    if report.get("upgrade_note"):
        lines.append(f"  {report['upgrade_note']}")

    lines.append(f"\n{sep2}")
    lines.append("  ALERT DETAILS")
    lines.append(sep2)
    lines.append(f"  Alert ID   : {report['alert_id']}")
    lines.append(f"  Type       : {report['alert_type']}")
    lines.append(f"  Description: {report['description']}")
    lines.append(f"  Timestamp  : {report['timeline']['alert_timestamp']}")

    lines.append(f"\n{sep2}")
    lines.append("  AFFECTED ASSETS")
    lines.append(sep2)
    lines.append(f"  Hostname   : {report['affected_assets']['hostname']}")
    lines.append(f"  Username   : {report['affected_assets']['username']}")

    lines.append(f"\n{sep2}")
    lines.append("  NETWORK ACTIVITY")
    lines.append(sep2)
    net = report["network"]
    lines.append(f"  Source IP  : {net['source_ip']}")
    lines.append(f"  Dest Port  : {net['destination_port']}")
    lines.append(f"  Protocol   : {net['protocol']}")
    lines.append(f"  Bytes Sent : {net['bytes_sent']:,}")
    lines.append(f"  Action     : {net['action']}")

    lines.append(f"\n{sep2}")
    lines.append("  THREAT INTELLIGENCE")
    lines.append(sep2)
    ti = report["threat_intel"]
    lines.append(f"  IP Verdict : {ti['verdict']}")
    lines.append(f"  Confidence : {ti['confidence_score']}%")
    lines.append(f"  Reports    : {ti['total_reports']}")
    lines.append(f"  Country    : {ti['country']}")
    lines.append(f"  ISP        : {ti['isp']}")
    lines.append(f"  TOR Node   : {'Yes 🧅' if ti['is_tor_exit_node'] else 'No'}")

    lines.append(f"\n{sep2}")
    lines.append("  MITRE ATT&CK")
    lines.append(sep2)
    lines.append(f"  Tactic     : {report['mitre_attack']['tactic']}")
    lines.append(f"  Technique  : {report['mitre_attack']['technique']}")

    lines.append(f"\n{sep2}")
    lines.append("  RECOMMENDED ACTIONS")
    lines.append(sep2)
    for i, action in enumerate(report["recommended_actions"], 1):
        lines.append(f"  {i}. {action}")

    lines.append(f"\n{sep}")

    return "\n".join(lines)


def triage_alert(alert: dict, enrichment: dict = None) -> str:
    """
    Full triage pipeline: take a raw alert, enrich it, generate report.
    Convenience wrapper for the agent to call in one step.

    Args:
        alert:      Raw alert dict from elastic_tool.
        enrichment: Optional pre-fetched enrichment dict.

    Returns:
        Formatted incident report string.
    """
    if enrichment:
        alert["enrichment"] = enrichment

    report = generate_report(alert)
    return format_report_text(report)


# ── Quick Test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Simulate an enriched alert
    sample_alert = {
        "alert_id":         "ALERT-0001",
        "alert_type":       "Data Exfiltration",
        "severity":         "Critical",
        "source_ip":        "185.220.101.45",
        "destination_ip":   "10.19.24.245",
        "destination_port": 21,
        "protocol":         "FTP",
        "username":         "jsmith",
        "hostname":         "WORKSTATION-013",
        "action":           "allowed",
        "bytes_sent":       35_193_352,
        "description":      "Unusually large data transfer to external IP detected.",
        "mitre_tactic":     "Exfiltration",
        "mitre_technique":  "T1048 - Exfiltration Over Alternative Protocol",
        "timestamp":        "2026-05-23T17:25:27.978Z",
        "enrichment": {
            "ip":               "185.220.101.45",
            "is_malicious":     True,
            "confidence_score": 100,
            "total_reports":    109,
            "country":          "DE",
            "isp":              "Network for Tor-Exit traffic.",
            "is_tor":           True,
        },
    }

    report = generate_report(sample_alert)
    print(format_report_text(report))
    print("\n✅ report_tool.py working correctly.")