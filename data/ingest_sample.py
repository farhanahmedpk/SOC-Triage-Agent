"""
ingest_sample.py
Generates and ingests realistic fake security alerts into Elasticsearch.
Run this once to populate your index with sample data for the SOC Triage Agent.

Usage:
    pip install elasticsearch faker
    python ingest_sample.py
"""

import random
import os
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from faker import Faker

# ── Config ────────────────────────────────────────────────────────────────────
ELASTIC_URL     = os.getenv("ELASTIC_URL", "http://localhost:9200")
ELASTIC_API_KEY = os.getenv("ELASTIC_API_KEY", "")   # leave blank for local
INDEX_NAME      = "security-alerts"
NUM_ALERTS      = 100
# ─────────────────────────────────────────────────────────────────────────────

fake = Faker()

# Connect
if ELASTIC_API_KEY:
    es = Elasticsearch(ELASTIC_URL, api_key=ELASTIC_API_KEY)
else:
    es = Elasticsearch(ELASTIC_URL)

print(f"Connected to Elasticsearch: {es.info()['version']['number']}")


# ── Index Mapping ─────────────────────────────────────────────────────────────
mapping = {
    "mappings": {
        "properties": {
            "alert_id":        {"type": "keyword"},
            "timestamp":       {"type": "date"},
            "alert_type":      {"type": "keyword"},
            "severity":        {"type": "keyword"},
            "source_ip":       {"type": "ip"},
            "destination_ip":  {"type": "ip"},
            "destination_port":{"type": "integer"},
            "protocol":        {"type": "keyword"},
            "username":        {"type": "keyword"},
            "hostname":        {"type": "keyword"},
            "action":          {"type": "keyword"},
            "status":          {"type": "keyword"},
            "description":     {"type": "text"},
            "bytes_sent":      {"type": "long"},
            "country":         {"type": "keyword"},
            "mitre_tactic":    {"type": "keyword"},
            "mitre_technique": {"type": "keyword"},
        }
    }
}

# Create index (skip if exists)
if not es.indices.exists(index=INDEX_NAME):
    es.indices.create(index=INDEX_NAME, body=mapping)
    print(f"Created index: {INDEX_NAME}")
else:
    print(f"Index already exists: {INDEX_NAME}")


# ── Alert Templates ───────────────────────────────────────────────────────────
ALERT_TYPES = [
    {
        "alert_type":      "Brute Force Login",
        "severity":        "High",
        "protocol":        "SSH",
        "destination_port": 22,
        "action":          "blocked",
        "mitre_tactic":    "Credential Access",
        "mitre_technique": "T1110 - Brute Force",
        "description":     "Multiple failed login attempts detected from external IP.",
    },
    {
        "alert_type":      "Port Scan Detected",
        "severity":        "Medium",
        "protocol":        "TCP",
        "destination_port": random.randint(1, 65535),
        "action":          "detected",
        "mitre_tactic":    "Reconnaissance",
        "mitre_technique": "T1046 - Network Service Scanning",
        "description":     "Sequential port scan detected across multiple destination ports.",
    },
    {
        "alert_type":      "Malware C2 Communication",
        "severity":        "Critical",
        "protocol":        "HTTPS",
        "destination_port": 443,
        "action":          "allowed",
        "mitre_tactic":    "Command and Control",
        "mitre_technique": "T1071 - Application Layer Protocol",
        "description":     "Suspected C2 beacon traffic to known malicious domain.",
    },
    {
        "alert_type":      "Privilege Escalation",
        "severity":        "Critical",
        "protocol":        "SMB",
        "destination_port": 445,
        "action":          "detected",
        "mitre_tactic":    "Privilege Escalation",
        "mitre_technique": "T1068 - Exploitation for Privilege Escalation",
        "description":     "User account attempted to escalate privileges via exploit.",
    },
    {
        "alert_type":      "Data Exfiltration",
        "severity":        "Critical",
        "protocol":        "FTP",
        "destination_port": 21,
        "action":          "allowed",
        "mitre_tactic":    "Exfiltration",
        "mitre_technique": "T1048 - Exfiltration Over Alternative Protocol",
        "description":     "Unusually large data transfer to external IP detected.",
    },
    {
        "alert_type":      "Phishing Email Link Clicked",
        "severity":        "High",
        "protocol":        "HTTP",
        "destination_port": 80,
        "action":          "allowed",
        "mitre_tactic":    "Initial Access",
        "mitre_technique": "T1566 - Phishing",
        "description":     "User clicked a known phishing URL from internal workstation.",
    },
    {
        "alert_type":      "Suspicious PowerShell Execution",
        "severity":        "High",
        "protocol":        "N/A",
        "destination_port": 0,
        "action":          "detected",
        "mitre_tactic":    "Execution",
        "mitre_technique": "T1059.001 - PowerShell",
        "description":     "Encoded PowerShell command executed on endpoint.",
    },
    {
        "alert_type":      "Unauthorized Access Attempt",
        "severity":        "Medium",
        "protocol":        "RDP",
        "destination_port": 3389,
        "action":          "blocked",
        "mitre_tactic":    "Lateral Movement",
        "mitre_technique": "T1021 - Remote Services",
        "description":     "RDP login attempt from unauthorized IP address.",
    },
    {
        "alert_type":      "DNS Tunneling",
        "severity":        "High",
        "protocol":        "DNS",
        "destination_port": 53,
        "action":          "detected",
        "mitre_tactic":    "Command and Control",
        "mitre_technique": "T1071.004 - DNS",
        "description":     "Abnormally high DNS query volume suggests tunneling activity.",
    },
    {
        "alert_type":      "Failed VPN Login",
        "severity":        "Low",
        "protocol":        "UDP",
        "destination_port": 1194,
        "action":          "blocked",
        "mitre_tactic":    "Credential Access",
        "mitre_technique": "T1078 - Valid Accounts",
        "description":     "Multiple failed VPN authentication attempts from single IP.",
    },
]

KNOWN_MALICIOUS_IPS = [
    "185.220.101.45",
    "194.165.16.77",
    "45.142.212.100",
    "91.219.236.18",
    "198.199.119.161",
]

INTERNAL_HOSTS = [f"WORKSTATION-{i:03d}" for i in range(1, 20)] + \
                 [f"SERVER-{i:02d}" for i in range(1, 6)]

USERNAMES = ["jsmith", "ahmed.f", "nadeem.k", "admin", "svc_backup",
             "root", "guest", "m.ali", "fatima.z", "sys_admin"]


# ── Generate & Ingest ─────────────────────────────────────────────────────────
print(f"\nIngesting {NUM_ALERTS} sample security alerts...")

for i in range(NUM_ALERTS):
    template = random.choice(ALERT_TYPES).copy()

    # Randomize some fields
    use_malicious = random.random() < 0.3  # 30% chance of known bad IP
    source_ip = random.choice(KNOWN_MALICIOUS_IPS) if use_malicious \
                else fake.ipv4_public()

    alert = {
        "alert_id":         f"ALERT-{i+1:04d}",
        "timestamp":        (datetime.utcnow() - timedelta(
                                minutes=random.randint(0, 1440)
                            )).isoformat(),
        "source_ip":        source_ip,
        "destination_ip":   fake.ipv4_private(),
        "username":         random.choice(USERNAMES),
        "hostname":         random.choice(INTERNAL_HOSTS),
        "status":           "open",
        "bytes_sent":       random.randint(500, 50_000_000),
        "country":          fake.country_code(),
        **template,
    }

    # Fix: randomize port for port scan
    if alert["alert_type"] == "Port Scan Detected":
        alert["destination_port"] = random.randint(1, 65535)

    es.index(index=INDEX_NAME, id=alert["alert_id"], document=alert)

    if (i + 1) % 20 == 0:
        print(f"  ✓ {i+1}/{NUM_ALERTS} alerts ingested")

print(f"\n✅ Done! {NUM_ALERTS} alerts ingested into '{INDEX_NAME}' index.")
print(f"   Verify at: {ELASTIC_URL}/{INDEX_NAME}/_search?pretty")