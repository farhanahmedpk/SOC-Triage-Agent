from google.adk.agents import LlmAgent
from google.adk.tools.mcp_tool.mcp_session_manager import StreamableHTTPConnectionParams
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset
from google.adk.tools import agent_tool
from google.adk.tools.google_search_tool import GoogleSearchTool
from google.adk.tools import url_context

soc_triage_agent_google_search_agent = LlmAgent(
  name='SOC_Triage_Agent_google_search_agent',
  model='gemini-2.5-flash',
  description=(
      'Agent specialized in performing Google searches.'
  ),
  sub_agents=[],
  instruction='Use the GoogleSearchTool to find information on the web.',
  tools=[
    GoogleSearchTool()
  ],
)
soc_triage_agent_url_context_agent = LlmAgent(
  name='SOC_Triage_Agent_url_context_agent',
  model='gemini-2.5-flash',
  description=(
      'Agent specialized in fetching content from URLs.'
  ),
  sub_agents=[],
  instruction='Use the UrlContextTool to retrieve content from provided URLs.',
  tools=[
    url_context
  ],
)
root_agent = LlmAgent(
  name='SOC_Triage_Agent',
  model='gemini-2.5-flash',
  description=(
      'An AI-powered Tier-1 SOC analyst that ingests security alerts from Elasticsearch, enriches them with threat intelligence, classifies severity, and generates structured incident reports.'
  ),
  sub_agents=[],
  instruction='You are an expert SOC (Security Operations Center) Tier-1 analyst. Your job is to triage security alerts.\n\nWhen asked to triage alerts:\n1. Retrieve open Critical and High severity alerts from Elasticsearch\n2. For each alert, check the source IP reputation using AbuseIPDB\n3. Correlate related events (same IP or hostname)\n4. Classify the alert: ESCALATE TO TIER-2, MONITOR & INVESTIGATE, or LOG & CLOSE\n5. Generate a structured incident report with MITRE ATT&CK mapping and recommended actions\n\nAlways prioritize Critical severity alerts first. Flag any IP confirmed malicious by AbuseIPDB as high priority. Be concise, factual, and actionable.',
  tools=[
    agent_tool.AgentTool(agent=soc_triage_agent_google_search_agent),
    agent_tool.AgentTool(agent=soc_triage_agent_url_context_agent),
    McpToolset(
    connection_params=StreamableHTTPConnectionParams(
        url='https://soc-triage-mcp-454362298471.us-central1.run.app/mcp',
    ),
  ),
  ],
)