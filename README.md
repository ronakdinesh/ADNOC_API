# Microsoft Sentinel Security Alerts API

This repository contains scripts to interact with Microsoft Sentinel security alerts and incidents through the Log Analytics API. It provides functionality to query, display, and analyze security data with advanced AI-powered insights.

## Features

- Query security alerts and incidents with various filters (time range, severity, status)
- Display alerts and incidents in readable table format with detailed view options
- Export security data to Excel
- Natural language interface for security analysis (using LLM)
- Generate KQL queries dynamically based on user intent
- Produce structured SOC analyst reports with actionable recommendations
- Enrich findings with threat intelligence from VirusTotal and other sources
- Map incidents to related alerts for comprehensive investigation

## Components

- `test_security_alerts.py` - Core functionality to retrieve and display security alerts
- `agent_api_test.py` - Natural language interface for security alert analysis
- `test_common_security_logs.py` - Retrieve and analyze common security logs
- `test_security_incidents.py` - Query security incidents from Microsoft Sentinel
- `llm_read_security_incidents.py` - Generate detailed SOC analyst reports with actionable recommendations
- `virustotal_integration.py` - Enrich findings with threat intelligence from VirusTotal
- `map_incident_to_alert.py` - Map incidents to their related alerts for investigation

## Requirements

- Python 3.6+
- Azure AD application with API permissions
- Microsoft Sentinel workspace
- Local LLM server (Ollama with llama3) for offline analysis
- Required Python packages (see requirements.txt)

## Setup

1. Clone this repository
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Create a `.env` file with the following variables:
   ```
   TENANT_ID=your_tenant_id
   CLIENT_ID=your_client_id
   CLIENT_SECRET=your_client_secret
   WORKSPACE_ID=your_workspace_id
   VIRUSTOTAL_API_KEY=your_vt_api_key  # Optional, for VirusTotal integration
   ```
4. Set up Ollama with llama3.2 model for local LLM processing:
   ```
   ollama pull llama3.2
   ```

## Usage

### Basic Security Alert Query

```python
from test_security_alerts import get_security_alerts, display_alerts

# Get all alerts from the last 7 days
alerts = get_security_alerts(hours=168, limit=100)

# Display alerts in table format
display_alerts(alerts)

# Get high severity alerts only
high_alerts = get_security_alerts(hours=168, limit=100, severity="High")
```

### Natural Language Interface

```bash
# Run the agent with natural language capabilities
python agent_api_test.py
```

Then ask questions like:
- "Show me high severity alerts from the last week"
- "Count alerts by provider"
- "Find alerts related to suspicious logins"

### Generate SOC Analyst Reports

```bash
# Run the SOC analyst report generation tool
python "02 AI Agent API/llm_read_security_incidents.py"
```

This will:
1. Fetch incident data from Microsoft Sentinel
2. Extract security indicators (IPs, domains, users, etc.)
3. Analyze logs and alerts related to the incident
4. Generate a comprehensive SOC analyst report with:
   - Executive summary
   - Severity assessment
   - Immediate actions with specific, actionable recommendations
   - Future investigation steps with supporting evidence
   - MITRE ATT&CK mappings

### Investigate Incidents with Related Alerts

```bash
python "02 AI Agent API/llm_read_security_incidents.py" --investigate
```

This mode allows you to select a specific incident and:
1. Find all related security alerts
2. Display incident-alert relationships
3. Generate a detailed SOC report with alert context

## License

MIT 