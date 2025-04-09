# Microsoft Sentinel Security Alerts API

This repository contains scripts to interact with Microsoft Sentinel security alerts through the Log Analytics API. It provides functionality to query, display, and analyze security alerts.

## Features

- Query security alerts with various filters (time range, severity, status)
- Display alerts in readable table format with detailed view options
- Export alerts to Excel
- Natural language interface for security alert analysis (using LLM)
- Generate KQL queries dynamically based on user intent
- Produce structured summaries of security findings

## Components

- `test_security_alerts.py` - Core functionality to retrieve and display security alerts
- `agent_api_test.py` - Natural language interface for security alert analysis
- `test_common_security_logs.py` - Retrieve and analyze common security logs
- `test_security_incidents.py` - Query security incidents from Microsoft Sentinel

## Requirements

- Python 3.6+
- Azure AD application with API permissions
- Microsoft Sentinel workspace
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

## License

MIT 