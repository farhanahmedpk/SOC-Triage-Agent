"""
mcp_server.py
MCP (Model Context Protocol) server for the SOC Triage Agent.
Exposes Elasticsearch + AbuseIPDB tools to Google Cloud Agent Builder.
Deploy this on Cloud Run.
"""

import os
import json
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS

# Add project root to path
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent.tools.elastic_tool import (
    get_open_alerts,
    get_critical_alerts,
    get_alert_summary,
    search_alerts_by_ip,
    search_alerts_by_host,
    get_alert_by_id,
    update_alert_status,
    search_by_mitre_tactic,
)
from agent.tools.enrich_tool import (
    check_ip_reputation,
    format_enrichment_summary,
)
from agent.tools.report_tool import (
    generate_report,
    format_report_text,
)

# ── App Setup ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── MCP Tool Definitions ──────────────────────────────────────────────────────
TOOLS = [
    {
        "name": "get_open_alerts",
        "description": "Fetch open security alerts from Elasticsearch SIEM, optionally filtered by severity (Critical, High, Medium, Low).",
        "parameters": {
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "description": "Filter by severity: Critical, High, Medium, or Low. Leave empty for all.",
                    "enum": ["Critical", "High", "Medium", "Low"]
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of alerts to return (default 10).",
                    "default": 10
                }
            }
        }
    },
    {
        "name": "get_critical_alerts",
        "description": "Get Critical and High severity alerts from the last N hours.",
        "parameters": {
            "type": "object",
            "properties": {
                "hours": {
                    "type": "integer",
                    "description": "Time window in hours (default 24).",
                    "default": 24
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum alerts to return (default 20).",
                    "default": 20
                }
            }
        }
    },
    {
        "name": "get_alert_summary",
        "description": "Get a dashboard summary of all alerts: total count, breakdown by severity, and top alert types.",
        "parameters": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "search_alerts_by_ip",
        "description": "Find all security alerts involving a specific IP address (as source or destination).",
        "parameters": {
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string",
                    "description": "The IP address to search for."
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum results (default 20).",
                    "default": 20
                }
            },
            "required": ["ip_address"]
        }
    },
    {
        "name": "search_alerts_by_host",
        "description": "Find all security alerts for a specific hostname.",
        "parameters": {
            "type": "object",
            "properties": {
                "hostname": {
                    "type": "string",
                    "description": "Hostname to search for (e.g. WORKSTATION-001)."
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum results (default 20).",
                    "default": 20
                }
            },
            "required": ["hostname"]
        }
    },
    {
        "name": "check_ip_reputation",
        "description": "Check the reputation of an IP address using AbuseIPDB threat intelligence. Returns malicious flag, confidence score, country, ISP, and report count.",
        "parameters": {
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string",
                    "description": "The IP address to check."
                }
            },
            "required": ["ip_address"]
        }
    },
    {
        "name": "generate_incident_report",
        "description": "Generate a full structured incident report for a security alert, including threat intel, MITRE ATT&CK mapping, verdict, and recommended actions.",
        "parameters": {
            "type": "object",
            "properties": {
                "alert_id": {
                    "type": "string",
                    "description": "The alert ID to generate a report for (e.g. ALERT-0001)."
                }
            },
            "required": ["alert_id"]
        }
    },
    {
        "name": "update_alert_status",
        "description": "Update the status of a security alert in Elasticsearch.",
        "parameters": {
            "type": "object",
            "properties": {
                "alert_id": {
                    "type": "string",
                    "description": "Alert ID to update."
                },
                "status": {
                    "type": "string",
                    "description": "New status.",
                    "enum": ["open", "investigating", "escalated", "closed"]
                }
            },
            "required": ["alert_id", "status"]
        }
    },
    {
        "name": "search_by_mitre_tactic",
        "description": "Find alerts matching a MITRE ATT&CK tactic (e.g. Exfiltration, Command and Control, Execution).",
        "parameters": {
            "type": "object",
            "properties": {
                "tactic": {
                    "type": "string",
                    "description": "MITRE tactic name."
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum results (default 20).",
                    "default": 20
                }
            },
            "required": ["tactic"]
        }
    },
]


# ── MCP Endpoints ─────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "SOC Triage Agent MCP Server running"}), 200


@app.route("/mcp/tools", methods=["GET"])
def list_tools():
    """Return list of available MCP tools."""
    return jsonify({"tools": TOOLS}), 200


@app.route("/mcp/tools/call", methods=["POST"])
def call_tool():
    """Execute a tool call from the agent."""
    body = request.get_json()
    if not body:
        return jsonify({"error": "No JSON body"}), 400

    tool_name = body.get("name")
    params    = body.get("parameters", {})

    logger.info(f"Tool call: {tool_name} | params: {params}")

    try:
        result = _dispatch(tool_name, params)
        return jsonify({"result": result}), 200
    except Exception as e:
        logger.error(f"Tool error: {tool_name} — {e}")
        return jsonify({"error": str(e)}), 500


def _dispatch(tool_name: str, params: dict):
    """Route tool calls to the correct function."""

    if tool_name == "get_open_alerts":
        alerts = get_open_alerts(
            severity=params.get("severity"),
            limit=params.get("limit", 10)
        )
        return {"alerts": alerts, "count": len(alerts)}

    elif tool_name == "get_critical_alerts":
        alerts = get_critical_alerts(
            hours=params.get("hours", 24),
            limit=params.get("limit", 20)
        )
        return {"alerts": alerts, "count": len(alerts)}

    elif tool_name == "get_alert_summary":
        return get_alert_summary()

    elif tool_name == "search_alerts_by_ip":
        alerts = search_alerts_by_ip(
            ip_address=params["ip_address"],
            limit=params.get("limit", 20)
        )
        return {"alerts": alerts, "count": len(alerts)}

    elif tool_name == "search_alerts_by_host":
        alerts = search_alerts_by_host(
            hostname=params["hostname"],
            limit=params.get("limit", 20)
        )
        return {"alerts": alerts, "count": len(alerts)}

    elif tool_name == "check_ip_reputation":
        rep = check_ip_reputation(params["ip_address"])
        rep["summary"] = format_enrichment_summary(rep)
        return rep

    elif tool_name == "generate_incident_report":
        from agent.tools.elastic_tool import get_alert_by_id
        alert = get_alert_by_id(params["alert_id"])
        if not alert:
            return {"error": f"Alert {params['alert_id']} not found."}
        # Enrich the alert
        from agent.tools.enrich_tool import enrich_alert
        enriched = enrich_alert(alert)
        report   = generate_report(enriched)
        return {
            "report":      report,
            "report_text": format_report_text(report),
        }

    elif tool_name == "update_alert_status":
        success = update_alert_status(params["alert_id"], params["status"])
        return {"success": success, "alert_id": params["alert_id"], "status": params["status"]}

    elif tool_name == "search_by_mitre_tactic":
        alerts = search_by_mitre_tactic(
            tactic=params["tactic"],
            limit=params.get("limit", 20)
        )
        return {"alerts": alerts, "count": len(alerts)}

    else:
        raise ValueError(f"Unknown tool: {tool_name}")


# ── Entry Point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
