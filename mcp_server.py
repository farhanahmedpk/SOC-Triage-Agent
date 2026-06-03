import os
import json
import requests
from datetime import datetime, timezone
from elasticsearch import Elasticsearch
from mcp.server.fastmcp import FastMCP

ELASTIC_URL = os.environ.get("ELASTIC_URL", "")
ELASTIC_API_KEY = os.environ.get("ELASTIC_API_KEY", "")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
INDEX = "security-alerts"

def get_es():
    return Elasticsearch(ELASTIC_URL, api_key=ELASTIC_API_KEY, verify_certs=True)

mcp = FastMCP("SOC Triage Agent", host="0.0.0.0")

from starlette.requests import Request
from starlette.responses import JSONResponse

async def health(request: Request):
    return JSONResponse({"status": "SOC Triage Agent MCP Server running", "tools": 9})

@mcp.tool()
def get_alert_summary() -> str:
    """Get a dashboard summary of all alerts: total count, breakdown by severity, and top alert types."""
    es = get_es()
    result = es.search(index=INDEX, body={
        "size": 0,
        "aggs": {
            "by_severity": {"terms": {"field": "severity", "size": 10}},
            "by_type": {"terms": {"field": "alert_type", "size": 10}}
        }
    })
    severity = {b["key"]: b["doc_count"] for b in result["aggregations"]["by_severity"]["buckets"]}
    alert_types = {b["key"]: b["doc_count"] for b in result["aggregations"]["by_type"]["buckets"]}
    total = result["hits"]["total"]["value"]
    return json.dumps({"total": total, "by_severity": severity, "by_type": alert_types})

@mcp.tool()
def get_open_alerts(severity: str = "", limit: int = 10) -> str:
    """Fetch open security alerts from Elasticsearch SIEM, optionally filtered by severity (Critical, High, Medium, Low)."""
    es = get_es()
    query = {"bool": {"must": [{"term": {"status.keyword": "open"}}]}}
    if severity:
        query["bool"]["must"].append({"term": {"severity.keyword": severity}})
    result = es.search(index=INDEX, body={"size": limit, "query": query, "sort": [{"timestamp": {"order": "desc"}}]})
    alerts = [hit["_source"] for hit in result["hits"]["hits"]]
    return json.dumps(alerts, default=str)

@mcp.tool()
def get_critical_alerts(hours: int = 720, limit: int = 20) -> str:
    """Get Critical and High severity alerts from the last N hours."""
    es = get_es()
    result = es.search(index=INDEX, body={
        "size": limit,
        "query": {"bool": {"must": [
            {"terms": {"severity.keyword": ["Critical", "High"]}},
            {"range": {"timestamp": {"gte": f"now-{hours*24}h"}}}
        ]}},
        "sort": [{"timestamp": {"order": "desc"}}]
    })
    alerts = [hit["_source"] for hit in result["hits"]["hits"]]
    return json.dumps(alerts, default=str)

@mcp.tool()
def search_alerts_by_ip(ip_address: str, limit: int = 20) -> str:
    """Find all security alerts involving a specific IP address."""
    es = get_es()
    result = es.search(index=INDEX, body={
        "size": limit,
        "query": {"bool": {"should": [
            {"term": {"source_ip.keyword": ip_address}},
            {"term": {"dest_ip.keyword": ip_address}}
        ], "minimum_should_match": 1}}
    })
    alerts = [hit["_source"] for hit in result["hits"]["hits"]]
    return json.dumps(alerts, default=str)

@mcp.tool()
def search_alerts_by_host(hostname: str, limit: int = 20) -> str:
    """Find all security alerts for a specific hostname."""
    es = get_es()
    result = es.search(index=INDEX, body={
        "size": limit,
        "query": {"term": {"hostname.keyword": hostname}}
    })
    alerts = [hit["_source"] for hit in result["hits"]["hits"]]
    return json.dumps(alerts, default=str)

@mcp.tool()
def check_ip_reputation(ip_address: str) -> str:
    """Check the reputation of an IP address using AbuseIPDB threat intelligence."""
    if ip_address.startswith(("10.", "192.168.", "172.")):
        return json.dumps({"ip": ip_address, "is_malicious": False, "note": "Private IP"})
    resp = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
        params={"ipAddress": ip_address, "maxAgeInDays": 90}
    )
    data = resp.json().get("data", {})
    return json.dumps({
        "ip": ip_address,
        "is_malicious": data.get("abuseConfidenceScore", 0) > 25,
        "confidence_score": data.get("abuseConfidenceScore", 0),
        "total_reports": data.get("totalReports", 0),
        "country": data.get("countryCode", ""),
        "isp": data.get("isp", ""),
        "is_tor": data.get("isTor", False)
    })

@mcp.tool()
def generate_incident_report(alert_id: str) -> str:
    """Generate a full structured incident report for a security alert."""
    es = get_es()
    result = es.search(index=INDEX, body={"query": {"term": {"alert_id.keyword": alert_id}}})
    if not result["hits"]["hits"]:
        return json.dumps({"error": f"Alert {alert_id} not found"})
    alert = result["hits"]["hits"][0]["_source"]
    ip = alert.get("source_ip", "")
    enrichment = json.loads(check_ip_reputation(ip)) if ip else {}
    is_malicious = enrichment.get("is_malicious", False)
    severity = alert.get("severity", "Medium")
    verdict = "ESCALATE TO TIER-2" if severity in ["Critical", "High"] or is_malicious else "MONITOR & INVESTIGATE"
    report = {
        "report_id": f"IR-{alert_id}",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "verdict": verdict,
        "alert": alert,
        "threat_intelligence": enrichment,
        "recommended_actions": [
            "Block source IP at firewall",
            "Isolate affected host",
            "Preserve logs for forensics",
            "Review user activity on affected system",
            "Escalate to Tier-2 if confirmed malicious"
        ]
    }
    return json.dumps(report, default=str)

@mcp.tool()
def update_alert_status(alert_id: str, status: str) -> str:
    """Update the status of a security alert in Elasticsearch. Status: open, investigating, escalated, closed."""
    es = get_es()
    result = es.search(index=INDEX, body={"query": {"term": {"alert_id.keyword": alert_id}}})
    if not result["hits"]["hits"]:
        return json.dumps({"error": f"Alert {alert_id} not found"})
    doc_id = result["hits"]["hits"][0]["_id"]
    es.update(index=INDEX, id=doc_id, body={"doc": {"status": status, "updated_at": datetime.now(timezone.utc).isoformat()}})
    return json.dumps({"success": True, "alert_id": alert_id, "new_status": status})

@mcp.tool()
def search_by_mitre_tactic(tactic: str, limit: int = 20) -> str:
    """Find alerts matching a MITRE ATT&CK tactic (e.g. Exfiltration, Command and Control, Execution)."""
    es = get_es()
    result = es.search(index=INDEX, body={
        "size": limit,
        "query": {"match": {"mitre_tactic": tactic}}
    })
    alerts = [hit["_source"] for hit in result["hits"]["hits"]]
    return json.dumps(alerts, default=str)

if __name__ == "__main__":
    import uvicorn
    from starlette.routing import Route
    from starlette.applications import Starlette
    
    port = int(os.environ.get("PORT", 8080))
    mcp_app = mcp.streamable_http_app()
    
    app = Starlette(routes=[
        Route("/", health),
        Route("/health", health),
    ])
    app.mount("/mcp", mcp_app)
    
    uvicorn.run(app, host="0.0.0.0", port=port, proxy_headers=True, forwarded_allow_ips="*")