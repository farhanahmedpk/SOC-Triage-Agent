# 🛡️ SOC Triage Agent

An AI-powered Tier-1 SOC analyst agent that autonomously ingests security alerts, enriches them with threat intelligence, correlates log data, and generates structured incident reports — built for the **Google Cloud Rapid Agent Hackathon 2026**.

---

## 🎯 What It Does

Manual alert triage is slow, repetitive, and burns out analysts. This agent automates the entire Tier-1 SOC workflow:

1. **Ingest** — Pulls security alerts from Elasticsearch SIEM
2. **Enrich** — Queries threat intel APIs (AbuseIPDB / VirusTotal) for IP reputation and IOC data
3. **Correlate** — Searches Elastic indices for related events and patterns
4. **Classify** — Scores each alert: `Critical / High / Medium / Low`
5. **Report** — Generates a structured incident report per alert
6. **Escalate** — Flags Critical/High severity alerts for human analyst review

---

## 🧱 Tech Stack

| Layer         | Technology                            |
| ------------- | ------------------------------------- |
| Agent Brain   | Gemini via Google Cloud Agent Builder |
| SIEM / Search | **Elasticsearch (Elastic MCP)**       |
| Threat Intel  | AbuseIPDB API                         |
| Deployment    | Google Cloud Run                      |
| Secrets       | Google Cloud Secret Manager           |
| Language      | Python                                |

---

## 🏆 Hackathon

- **Event:** [Google Cloud Rapid Agent Hackathon](https://rapid-agent.devpost.com/)
- **Track:** Elastic
- **Deadline:** June 12, 2026

---

## 📁 Project Structure

```
soc-triage-agent/
├── agent/
│   ├── main.py              # Agent orchestration logic
│   ├── tools/
│   │   ├── elastic_tool.py  # Elastic MCP integration
│   │   ├── enrich_tool.py   # Threat intel enrichment
│   │   └── report_tool.py   # Incident report generation
├── data/
│   └── ingest_sample.py     # Sample security log ingestion script
├── frontend/
│   └── index.html           # Analyst dashboard UI
├── .env.example             # Environment variable template
├── requirements.txt
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- Google Cloud account with Agent Builder enabled
- Elastic Cloud account (free trial works)
- AbuseIPDB API key (free tier)

### Installation

```bash
git clone https://github.com/YOUR_USERNAME/soc-triage-agent
cd soc-triage-agent
pip install -r requirements.txt
cp .env.example .env
# Fill in your API keys in .env
```

### Environment Variables

```env
ELASTIC_URL=your_elastic_cloud_url
ELASTIC_API_KEY=your_elastic_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
GOOGLE_CLOUD_PROJECT=your_gcp_project_id
```

### Run Locally

```bash
# Ingest sample security data into Elastic
python data/ingest_sample.py

# Start the agent
python agent/main.py
```

---

## 📊 Demo

> Demo video link will be added before submission deadline (June 12, 2026)

---

## 📄 License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.
