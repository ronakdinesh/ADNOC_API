# Microsoft Sentinel Security Alert Agent

This tool allows you to query Microsoft Sentinel security alerts using natural language questions and get AI-enhanced summaries of the results.

## Prerequisites

- Python 3.7 or higher
- Microsoft Sentinel environment
- Azure AD application with appropriate permissions

## Setup

1. Install required Python packages:

```bash
pip install -r requirements.txt
```

2. Set up your Azure credentials:
   - Copy the `.env.sample` file to `.env` (if not already existing)
   - Make sure the following variables are set in your `.env` file:
     - `TENANT_ID`: Your Azure Active Directory tenant ID
     - `CLIENT_ID`: Your Azure AD application client ID
     - `CLIENT_SECRET`: Your Azure AD application secret
     - `WORKSPACE_ID`: Your Log Analytics workspace ID

3. Make sure you have the Ollama API running for AI features:
   - Install Ollama from [https://ollama.com/](https://ollama.com/)
   - Run `ollama serve` to start the API
   - Pull the LLM model: `ollama pull llama3.2`

## Getting Azure Credentials

To use this tool, you need to create an Azure AD application with the appropriate permissions:

1. Register a new application in Azure Active Directory
2. Create a client secret for the application
3. Grant the application the "Reader" role on your Microsoft Sentinel workspace
4. Note down the tenant ID, client ID, client secret, and workspace ID

## Usage

Run the script:

```bash
python llm_security_alert.py
```

Example questions you can ask:

- "Show me high severity alerts from the last 24 hours"
- "Any unusual login attempts in the past week?"
- "Count alerts by provider"
- "What are the most common attack tactics?"

## Features

- Natural language query processing
- AI-enhanced summaries of security alerts
- Detailed alert view
- Export to Excel

## API Access Requirements

This tool requires direct API access to Microsoft Sentinel and will NOT work with mock data. Make sure your credentials are properly set up and have the required permissions. 