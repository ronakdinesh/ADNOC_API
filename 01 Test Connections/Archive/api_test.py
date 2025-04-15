import requests
import json
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
import adal
# Load environment variables from .env file
load_dotenv()

# Azure AD and Log Analytics configuration
tenant_id = os.getenv('TENANT_ID')
client_id = os.getenv('CLIENT_ID')
client_secret = os.getenv('CLIENT_SECRET')
workspace_id = os.getenv('WORKSPACE_ID')

# Validate that all required environment variables are set
required_vars = {
    'TENANT_ID': tenant_id,
    'CLIENT_ID': client_id,
    'CLIENT_SECRET': client_secret,
    'WORKSPACE_ID': workspace_id
}

missing_vars = [var for var, value in required_vars.items() if not value]
if missing_vars:
    raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")

# Authentication
authority_url = f"https://login.microsoftonline.com/{tenant_id}"
resource = "https://api.loganalytics.io"

context = adal.AuthenticationContext(authority_url)
token = context.acquire_token_with_client_credentials(
    resource,
    client_id,
    client_secret
)

access_token = token['accessToken']

# Set up the query
query = """
SecurityAlert
| where TimeGenerated > ago(1d)
| project TimeGenerated, AlertName, AlertSeverity, Description
| limit 10
"""

# API endpoint
url = f"https://api.loganalytics.io/v1/workspaces/2685c49d-739e-4a99-ac4d-adafb4799ac8/query"

# Headers
headers = {
    'Authorization': f'Bearer {access_token}',
    'Content-Type': 'application/json'
}

# Request body
request_body = {
    'query': query
}

# Send the request
response = requests.post(url, headers=headers, json=request_body)

# Process the results
if response.status_code == 200:
    results = response.json()
    for table in results['tables']:
        column_names = [col['name'] for col in table['columns']]
        rows = table['rows']
        
        # Print results
        for row in rows:
            row_dict = dict(zip(column_names, row))
            print(json.dumps(row_dict, indent=2))
else:
    print(f"Error: {response.status_code}")
    print(response.text)