"""
elastic_tool.py
Elasticsearch query tool for the SOC Triage Agent.
Provides functions to search, filter, and retrieve security alerts.
"""

import os
from datetime import datetime, timezone, timedelta
from elasticsearch import Elasticsearch

# ── Config ────────────────────────────────────────────────────────────────────
ELASTIC_URL     = os.getenv("ELASTIC_URL", "http://localhost:9200")
ELASTIC_API_KEY = os.getenv("ELASTIC_API_KEY", "")
INDEX_NAME      = "security-alerts"
# ─────────────────────────────────────────────────────────────────────────────


def get_client() -> Elasticsearch:
    """Return an authenticated Elasticsearch client."""
    if ELASTIC_API_KEY:
        return Elasticsearch(ELASTIC_URL, api_key=ELASTIC_API_KEY)
    return Elasticsearch(ELASTIC_URL)


# ── Tool Functions ────────────────────────────────────────────────────────────

def get_open_alerts(severity: str = None, limit: int = 10) -> list[dict]:
    """
    Fetch open security alerts, optionally filtered by severity.

    Args:
        severity: 'Critical', 'High', 'Medium', or 'Low'. None = all.
        limit:    Max number of alerts to return.

    Returns:
        List of alert dicts.
    """
    es = get_client()

    query = {"bool": {"must": [{"term": {"status": "open"}}]}}

    if severity:
        query["bool"]["must"].append({"term": {"severity": severity}})

    resp = es.search(
        index=INDEX_NAME,
        query=query,
        sort=[{"timestamp": {"order": "desc"}}],
        size=limit,
    )

    return [hit["_source"] for hit in resp["hits"]["hits"]]


def search_alerts_by_ip(ip_address: str, limit: int = 20) -> list[dict]:
    """
    Find all alerts involving a specific IP (source or destination).

    Args:
        ip_address: IP to search for.
        limit:      Max results.

    Returns:
        List of matching alert dicts.
    """
    es = get_client()

    resp = es.search(
        index=INDEX_NAME,
        query={
            "bool": {
                "should": [
                    {"term": {"source_ip": ip_address}},
                    {"term": {"destination_ip": ip_address}},
                ],
                "minimum_should_match": 1,
            }
        },
        sort=[{"timestamp": {"order": "desc"}}],
        size=limit,
    )

    return [hit["_source"] for hit in resp["hits"]["hits"]]


def search_alerts_by_host(hostname: str, limit: int = 20) -> list[dict]:
    """
    Find all alerts for a specific hostname.

    Args:
        hostname: Hostname to search for (e.g. 'WORKSTATION-001').
        limit:    Max results.

    Returns:
        List of matching alert dicts.
    """
    es = get_client()

    resp = es.search(
        index=INDEX_NAME,
        query={"term": {"hostname": hostname}},
        sort=[{"timestamp": {"order": "desc"}}],
        size=limit,
    )

    return [hit["_source"] for hit in resp["hits"]["hits"]]


def get_alert_by_id(alert_id: str) -> dict | None:
    """
    Fetch a single alert by its ID.

    Args:
        alert_id: e.g. 'ALERT-0001'

    Returns:
        Alert dict or None if not found.
    """
    es = get_client()

    try:
        resp = es.get(index=INDEX_NAME, id=alert_id)
        return resp["_source"]
    except Exception:
        return None


def get_critical_alerts(hours: int = 24, limit: int = 50) -> list[dict]:
    """
    Get Critical and High severity alerts from the last N hours.

    Args:
        hours: Time window in hours.
        limit: Max results.

    Returns:
        List of alert dicts sorted by timestamp descending.
    """
    es = get_client()

    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    resp = es.search(
        index=INDEX_NAME,
        query={
            "bool": {
                "must": [
                    {"terms": {"severity": ["Critical", "High"]}},
                    {"range": {"timestamp": {"gte": since}}},
                ]
            }
        },
        sort=[{"timestamp": {"order": "desc"}}],
        size=limit,
    )

    return [hit["_source"] for hit in resp["hits"]["hits"]]


def get_alert_summary() -> dict:
    """
    Get a count breakdown of alerts by severity and type.

    Returns:
        Dict with severity counts and top alert types.
    """
    es = get_client()

    resp = es.search(
        index=INDEX_NAME,
        size=0,
        aggs={
            "by_severity": {
                "terms": {"field": "severity", "size": 10}
            },
            "by_type": {
                "terms": {"field": "alert_type", "size": 10}
            },
            "by_status": {
                "terms": {"field": "status", "size": 5}
            },
        },
    )

    aggs = resp["aggregations"]

    return {
        "total_alerts": resp["hits"]["total"]["value"],
        "by_severity": {
            b["key"]: b["doc_count"]
            for b in aggs["by_severity"]["buckets"]
        },
        "by_type": {
            b["key"]: b["doc_count"]
            for b in aggs["by_type"]["buckets"]
        },
        "by_status": {
            b["key"]: b["doc_count"]
            for b in aggs["by_status"]["buckets"]
        },
    }


def update_alert_status(alert_id: str, status: str) -> bool:
    """
    Update the status of an alert (e.g. open → investigating → closed).

    Args:
        alert_id: e.g. 'ALERT-0001'
        status:   'open', 'investigating', 'escalated', or 'closed'

    Returns:
        True if updated successfully.
    """
    es = get_client()

    valid = {"open", "investigating", "escalated", "closed"}
    if status not in valid:
        raise ValueError(f"Invalid status. Must be one of: {valid}")

    try:
        es.update(
            index=INDEX_NAME,
            id=alert_id,
            doc={"status": status},
        )
        return True
    except Exception as e:
        print(f"Failed to update alert {alert_id}: {e}")
        return False


def search_by_mitre_tactic(tactic: str, limit: int = 20) -> list[dict]:
    """
    Find alerts matching a MITRE ATT&CK tactic.

    Args:
        tactic: e.g. 'Exfiltration', 'Command and Control', 'Execution'
        limit:  Max results.

    Returns:
        List of matching alert dicts.
    """
    es = get_client()

    resp = es.search(
        index=INDEX_NAME,
        query={"match": {"mitre_tactic": tactic}},
        sort=[{"timestamp": {"order": "desc"}}],
        size=limit,
    )

    return [hit["_source"] for hit in resp["hits"]["hits"]]


# ── Quick Test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=== Alert Summary ===")
    summary = get_alert_summary()
    print(f"Total alerts: {summary['total_alerts']}")
    print(f"By severity:  {summary['by_severity']}")
    print(f"By type:      {summary['by_type']}")

    print("\n=== Top 3 Critical Alerts ===")
    critical = get_open_alerts(severity="Critical", limit=3)
    for a in critical:
        print(f"  [{a['alert_id']}] {a['alert_type']} | {a['source_ip']} → {a['hostname']}")

    print("\n=== MITRE: Exfiltration Alerts ===")
    exfil = search_by_mitre_tactic("Exfiltration", limit=3)
    for a in exfil:
        print(f"  [{a['alert_id']}] {a['mitre_technique']} | severity: {a['severity']}")

    print("\n✅ elastic_tool.py working correctly.")