"""
enrich_tool.py
Threat intelligence enrichment for the SOC Triage Agent.
Queries AbuseIPDB to check IP reputation and flag malicious sources.
"""

import os
import requests
from datetime import datetime, timezone

# ── Config ────────────────────────────────────────────────────────────────────
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_URL     = "https://api.abuseipdb.com/api/v2/check"
MALICIOUS_THRESHOLD = 25  # confidence % above which IP is flagged malicious
# ─────────────────────────────────────────────────────────────────────────────


def check_ip_reputation(ip_address: str) -> dict:
    """
    Query AbuseIPDB for IP reputation data.

    Args:
        ip_address: IPv4 address to check.

    Returns:
        Dict with reputation data and a malicious flag.
    """
    if not ABUSEIPDB_API_KEY:
        raise ValueError("ABUSEIPDB_API_KEY environment variable not set.")

    # Skip private/internal IPs
    if _is_private_ip(ip_address):
        return {
            "ip": ip_address,
            "is_malicious": False,
            "confidence_score": 0,
            "total_reports": 0,
            "country": "Internal",
            "isp": "Internal Network",
            "domain": "N/A",
            "last_reported": None,
            "usage_type": "Private",
            "note": "Private/internal IP — skipped enrichment.",
        }

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90,
        "verbose": True,
    }

    try:
        resp = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json().get("data", {})

        confidence = data.get("abuseConfidenceScore", 0)

        return {
            "ip":               ip_address,
            "is_malicious":     confidence >= MALICIOUS_THRESHOLD,
            "confidence_score": confidence,
            "total_reports":    data.get("totalReports", 0),
            "country":          data.get("countryCode", "Unknown"),
            "isp":              data.get("isp", "Unknown"),
            "domain":           data.get("domain", "Unknown"),
            "last_reported":    data.get("lastReportedAt"),
            "usage_type":       data.get("usageType", "Unknown"),
            "is_tor":           data.get("isTor", False),
            "is_whitelisted":   data.get("isWhitelisted", False),
        }

    except requests.exceptions.Timeout:
        return _error_result(ip_address, "AbuseIPDB request timed out.")
    except requests.exceptions.HTTPError as e:
        return _error_result(ip_address, f"HTTP error: {e}")
    except Exception as e:
        return _error_result(ip_address, str(e))


def enrich_alert(alert: dict) -> dict:
    """
    Enrich a security alert with IP reputation data.
    Checks the source IP and adds enrichment fields to the alert.

    Args:
        alert: Alert dict from elastic_tool.

    Returns:
        Alert dict with added 'enrichment' key.
    """
    source_ip = alert.get("source_ip")

    if not source_ip:
        alert["enrichment"] = {"error": "No source IP in alert."}
        return alert

    rep = check_ip_reputation(source_ip)

    alert["enrichment"] = rep

    # Upgrade severity if IP is confirmed malicious
    if rep["is_malicious"] and alert.get("severity") == "Medium":
        alert["severity_upgraded"] = True
        alert["severity_original"] = "Medium"
        alert["severity"] = "High"
    elif rep["is_malicious"] and alert.get("severity") == "Low":
        alert["severity_upgraded"] = True
        alert["severity_original"] = "Low"
        alert["severity"] = "Medium"

    return alert


def enrich_multiple(alerts: list[dict]) -> list[dict]:
    """
    Enrich a list of alerts with IP reputation data.
    Deduplicates IP lookups to save API calls.

    Args:
        alerts: List of alert dicts.

    Returns:
        List of enriched alert dicts.
    """
    # Cache results to avoid duplicate API calls for same IP
    ip_cache: dict[str, dict] = {}

    for alert in alerts:
        source_ip = alert.get("source_ip")
        if not source_ip:
            continue

        if source_ip not in ip_cache:
            ip_cache[source_ip] = check_ip_reputation(source_ip)

        rep = ip_cache[source_ip]
        alert["enrichment"] = rep

        # Upgrade severity if malicious
        if rep["is_malicious"] and alert.get("severity") in ("Medium", "Low"):
            alert["severity_upgraded"] = True
            alert["severity_original"] = alert["severity"]
            alert["severity"] = "High" if alert["severity"] == "Medium" else "Medium"

    return alerts


def format_enrichment_summary(rep: dict) -> str:
    """
    Format IP reputation data as a human-readable string for reports.

    Args:
        rep: Result dict from check_ip_reputation().

    Returns:
        Formatted string summary.
    """
    if rep.get("note"):
        return rep["note"]

    malicious_label = "⚠️  MALICIOUS" if rep["is_malicious"] else "✅ Clean"
    tor_label       = " | 🧅 TOR Exit Node" if rep.get("is_tor") else ""

    return (
        f"{malicious_label}{tor_label}\n"
        f"  Confidence Score : {rep['confidence_score']}%\n"
        f"  Total Reports    : {rep['total_reports']}\n"
        f"  Country          : {rep['country']}\n"
        f"  ISP              : {rep['isp']}\n"
        f"  Usage Type       : {rep['usage_type']}\n"
        f"  Last Reported    : {rep.get('last_reported', 'Never')}"
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_private_ip(ip: str) -> bool:
    """Check if IP is in private/internal range."""
    private_prefixes = (
        "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
        "172.30.", "172.31.", "192.168.", "127.", "0.",
    )
    return any(ip.startswith(p) for p in private_prefixes)


def _error_result(ip: str, error: str) -> dict:
    """Return a safe error result dict."""
    return {
        "ip":               ip,
        "is_malicious":     False,
        "confidence_score": 0,
        "total_reports":    0,
        "country":          "Unknown",
        "isp":              "Unknown",
        "domain":           "Unknown",
        "last_reported":    None,
        "usage_type":       "Unknown",
        "error":            error,
    }


# ── Quick Test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Test with a known malicious IP from our dataset
    test_ips = [
        "185.220.101.45",   # Known malicious (Tor exit node)
        "198.199.119.161",  # Known malicious
        "192.168.1.1",      # Private IP (should be skipped)
    ]

    for ip in test_ips:
        print(f"\n=== Checking {ip} ===")
        result = check_ip_reputation(ip)
        print(format_enrichment_summary(result))

    print("\n✅ enrich_tool.py working correctly.")