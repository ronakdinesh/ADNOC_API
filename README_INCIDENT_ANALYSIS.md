# Microsoft Sentinel Incident Analysis Tool

This tool fetches security incidents from Microsoft Sentinel and analyzes them using a local LLM (Ollama) to generate comprehensive security reports.

## Features

- Retrieves real-time security incident data from Microsoft Sentinel
- Filters for specific incident types (default: "[Custom]-[TI]-DNS with TI Domain Correlation")
- Exports incident data to Excel for further analysis
- Performs advanced LLM-based analysis of incidents
- Retrieves associated raw logs for deeper context
- Analyzes domain reputation via VirusTotal integration
- Generates detailed SOC Analyst L1 Triage Reports

## Prerequisites

- Python 3.7+
- Required Python packages:
  - pandas
  - openpyxl
  - adal
  - requests
  - dotenv
  - ollama (for LLM analysis)
- Ollama running locally (for LLM analysis)
- Valid Azure AD credentials with access to Microsoft Sentinel

## Setup

1. Ensure your `.env` file exists with the following credentials:
   ```
   TENANT_ID=your-tenant-id
   CLIENT_ID=your-client-id
   CLIENT_SECRET=your-client-secret
   WORKSPACE_ID=your-workspace-id
   VIRUSTOTAL_API_KEY=your-virustotal-api-key  # Optional
   ```

2. Install required packages:
   ```
   pip install pandas openpyxl adal requests python-dotenv ollama
   ```

3. Install and start Ollama with the required model (if using LLM analysis):
   ```
   # Start the Ollama server
   ollama serve
   
   # In another terminal, pull the required model
   ollama pull llama3.2:latest
   ```

## Usage

### Option 1: Using the Batch File (Windows)

Run the `run_incident_analysis.bat` file and follow the prompts to select your desired operation.

### Option 2: Command Line

```
python "01 Test Connections/01_test_security_incidents.py" [options]
```

#### Command Line Options

- `--days N`: Number of days back to query (default: 7)
- `--all-incidents`: Fetch all incidents (not just DNS TI correlation)
- `--output PATH`: Output Excel file path (default: auto-generated)
- `--analyze`: Run LLM analysis on the incidents
- `--quiet`: Reduce verbosity

## Examples

1. Fetch DNS TI incidents from the last 7 days (export only):
   ```
   python "01 Test Connections/01_test_security_incidents.py"
   ```

2. Fetch DNS TI incidents from the last 7 days and analyze with LLM:
   ```
   python "01 Test Connections/01_test_security_incidents.py" --analyze
   ```

3. Fetch all incidents from the last 30 days:
   ```
   python "01 Test Connections/01_test_security_incidents.py" --days 30 --all-incidents
   ```

## Output

1. An Excel file containing the incident data
2. If analysis is enabled:
   - Console output with incident analysis
   - Text files with detailed analysis reports (one per incident)

## Troubleshooting

- If you receive authentication errors, verify your Azure AD credentials in the `.env` file
- For LLM analysis issues, ensure Ollama is running and the specified model is available
- If you encounter import errors, check that all required Python packages are installed

## Architecture

This tool consists of two main components:

1. **Incident Retrieval** (`01_test_security_incidents.py`): Fetches incident data from Microsoft Sentinel API
2. **LLM Analysis** (`llm_read_security_incidents.py`): Analyzes incident data, fetches related logs, and generates comprehensive reports

The data flow is:
1. Azure AD authentication
2. Sentinel API query for incidents
3. Export to Excel
4. LLM analysis (if enabled)
5. Generation of detailed reports 