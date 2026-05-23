"""
main.py
SOC Triage Agent — main orchestration.
Pulls open alerts from Elasticsearch, enriches with threat intel,
generates incident reports, and outputs a prioritized triage queue.
"""

import os
import sys
import json
from datetime import datetime, timezone

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.tools.elastic_tool import (
    get_client,
    get_open_alerts,
    get_critical_alerts,
    get_alert_summary,
    update_alert_status,
    search_alerts_by_ip,
)
from agent.tools.enrich_tool import (
    check_ip_reputation,
    enrich_alert,
    format_enrichment_summary,
)
from agent.tools.report_tool import (
    generate_report,
    format_report_text,
)

# ── Config ────────────────────────────────────────────────────────────────────
MAX_ALERTS_PER_RUN = int(os.getenv("MAX_ALERTS_PER_RUN", "10"))
AUTO_ESCALATE      = os.getenv("AUTO_ESCALATE", "true").lower() == "true"
REPORT_OUTPUT_DIR  = os.getenv("REPORT_OUTPUT_DIR", "reports")
# ─────────────────────────────────────────────────────────────────────────────


def print_banner():
    print("""
╔══════════════════════════════════════════════════════════╗
║           SOC TRIAGE AGENT  —  Powered by Gemini         ║
║         Google Cloud Rapid Agent Hackathon 2026          ║
╚══════════════════════════════════════════════════════════╝
""")


def print_dashboard(summary: dict):
    """Print alert dashboard summary."""
    print("📊 ALERT DASHBOARD")
    print("─" * 40)
    print(f"  Total Alerts  : {summary['total_alerts']}")
    print()
    print("  By Severity:")
    severity_order = ["Critical", "High", "Medium", "Low"]
    icons = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
    for sev in severity_order:
        count = summary["by_severity"].get(sev, 0)
        if count:
            print(f"    {icons.get(sev, '⚪')} {sev:<10}: {count}")
    print()
    print("  Top Alert Types:")
    for alert_type, count in list(summary["by_type"].items())[:5]:
        print(f"    • {alert_type:<40}: {count}")
    print()


def triage_alert(alert: dict) -> dict:
    """
    Full triage pipeline for a single alert:
    1. Enrich IP with AbuseIPDB
    2. Generate incident report
    3. Update alert status in Elasticsearch

    Args:
        alert: Raw alert dict from Elasticsearch.

    Returns:
        Dict with enriched alert + report.
    """
    alert_id   = alert.get("alert_id", "UNKNOWN")
    alert_type = alert.get("alert_type", "Unknown")
    severity   = alert.get("severity", "Unknown")
    source_ip  = alert.get("source_ip", "N/A")

    print(f"\n  🔍 Triaging [{alert_id}] {alert_type} | {severity} | {source_ip}")

    # Step 1: Enrich
    enriched = enrich_alert(alert)
    rep       = enriched.get("enrichment", {})

    if rep.get("is_malicious"):
        print(f"     ⚠️  IP MALICIOUS — confidence {rep['confidence_score']}% | {rep.get('isp', '')}")
    elif rep.get("error"):
        print(f"     ⚠️  Enrichment error: {rep['error']}")
    else:
        print(f"     ✅ IP clean — {rep.get('country', '')} | {rep.get('isp', '')}")

    if enriched.get("severity_upgraded"):
        print(f"     📈 Severity upgraded: {enriched['severity_original']} → {enriched['severity']}")

    # Step 2: Generate report
    report     = generate_report(enriched)
    report_txt = format_report_text(report)

    # Step 3: Update status in Elasticsearch
    new_status = "escalated" if report["verdict"] == "ESCALATE TO TIER-2" else "investigating"
    if AUTO_ESCALATE:
        update_alert_status(alert_id, new_status)
        print(f"     📋 Status updated → {new_status}")

    # Step 4: Save report to file
    os.makedirs(REPORT_OUTPUT_DIR, exist_ok=True)
    report_path = os.path.join(REPORT_OUTPUT_DIR, f"{alert_id}.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_txt)

    return {
        "alert_id":    alert_id,
        "alert_type":  alert_type,
        "severity":    enriched.get("severity"),
        "verdict":     report["verdict"],
        "source_ip":   source_ip,
        "is_malicious": rep.get("is_malicious", False),
        "report_path": report_path,
        "report":      report,
    }


def run_triage():
    """
    Main triage loop:
    - Fetch Critical + High alerts
    - Triage each one
    - Print summary queue
    """
    print_banner()

    # Dashboard
    print("⏳ Fetching alert summary...")
    summary = get_alert_summary()
    print_dashboard(summary)

    # Fetch alerts to triage
    print(f"⏳ Fetching top {MAX_ALERTS_PER_RUN} Critical/High alerts...")
    alerts = get_critical_alerts(hours=24, limit=MAX_ALERTS_PER_RUN)

    if not alerts:
        # Fallback: get any open alerts
        alerts = get_open_alerts(limit=MAX_ALERTS_PER_RUN)

    if not alerts:
        print("✅ No open alerts found. SOC queue is clear.")
        return

    print(f"   Found {len(alerts)} alerts to triage.\n")
    print("─" * 60)
    print("  STARTING TRIAGE RUN")
    print("─" * 60)

    results   = []
    escalated = []
    errors    = []

    for alert in alerts:
        try:
            result = triage_alert(alert)
            results.append(result)
            if result["verdict"] == "ESCALATE TO TIER-2":
                escalated.append(result)
        except Exception as e:
            alert_id = alert.get("alert_id", "UNKNOWN")
            print(f"     ❌ Error triaging {alert_id}: {e}")
            errors.append(alert_id)

    # ── Triage Summary ────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  TRIAGE COMPLETE — SUMMARY")
    print("=" * 60)
    print(f"  Alerts processed : {len(results)}")
    print(f"  Escalated        : {len(escalated)}")
    print(f"  Errors           : {len(errors)}")
    print(f"  Reports saved to : ./{REPORT_OUTPUT_DIR}/")

    if escalated:
        print(f"\n  🔴 ESCALATION QUEUE ({len(escalated)} alerts)")
        print("  " + "─" * 55)
        for r in escalated:
            malicious_tag = " ⚠️  MALICIOUS IP" if r["is_malicious"] else ""
            print(f"  [{r['alert_id']}] {r['alert_type']:<40} {r['severity']}{malicious_tag}")

    if errors:
        print(f"\n  ❌ Failed to triage: {', '.join(errors)}")

    print("\n" + "=" * 60)

    # Save full triage run summary as JSON
    run_summary = {
        "run_timestamp":    datetime.now(timezone.utc).isoformat(),
        "total_processed":  len(results),
        "total_escalated":  len(escalated),
        "total_errors":     len(errors),
        "escalated_alerts": [
            {
                "alert_id":   r["alert_id"],
                "alert_type": r["alert_type"],
                "severity":   r["severity"],
                "source_ip":  r["source_ip"],
                "verdict":    r["verdict"],
            }
            for r in escalated
        ],
    }

    summary_path = os.path.join(REPORT_OUTPUT_DIR, "triage_run_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(run_summary, f, indent=2)

    print(f"  Run summary saved → {summary_path}")
    print()


# ── Entry Point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    run_triage()