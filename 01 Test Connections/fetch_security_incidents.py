import os
import requests
import pandas as pd
from datetime import datetime
from dotenv import load_dotenv
import adal

"""
Minimal utility to pull SecurityIncident records from Microsoft Sentinel for the
last 30 days and export them to an Excel workbook.
The workbook name follows the pattern:
    YYYYMMDD_30d_security_incidents.xlsx
Environment variables expected (can be stored in a .env file next to this script):
    TENANT_ID     – Azure AD tenant ID
    CLIENT_ID     – App registration (client) ID
    CLIENT_SECRET – Client secret for the app registration
    WORKSPACE_ID  – Sentinel / Log Analytics workspace ID
"""

# Load environment variables from a local .env if present
load_dotenv()

TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
WORKSPACE_ID = os.getenv("WORKSPACE_ID")

if not all([TENANT_ID, CLIENT_ID, CLIENT_SECRET, WORKSPACE_ID]):
    raise RuntimeError("Please set TENANT_ID, CLIENT_ID, CLIENT_SECRET, and WORKSPACE_ID as environment variables or in a .env file.")

DAYS_BACK = 30  # change this constant if you need a different window


def get_azure_ad_token() -> str:
    """Authenticate using client credentials flow and return a bearer token."""
    authority_url = f"https://login.microsoftonline.com/{TENANT_ID}"
    resource = "https://api.loganalytics.io"

    context = adal.AuthenticationContext(authority_url)
    token_response = context.acquire_token_with_client_credentials(
        resource,
        CLIENT_ID,
        CLIENT_SECRET,
    )
    return token_response["accessToken"]


def run_kql_query(access_token: str):
    """Run the KQL query against the SecurityIncident table and return rows."""
    query = (
        f"SecurityIncident\n"
        f"| where TimeGenerated > ago({DAYS_BACK}d)\n"
        f"| order by TimeGenerated desc"
    )

    url = f"https://api.loganalytics.io/v1/workspaces/{WORKSPACE_ID}/query"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    response = requests.post(url, headers=headers, json={"query": query})
    response.raise_for_status()

    data = response.json()
    if not data.get("tables"):
        return []

    # We expect only one table in the response
    table = data["tables"][0]
    columns = [col["name"] for col in table["columns"]]
    rows = [dict(zip(columns, row)) for row in table["rows"]]
    return rows


def export_to_excel(rows):
    if not rows:
        print("No incidents returned for the given period.")
        return None

    df = pd.DataFrame(rows)
    filename = f"{datetime.now().strftime('%Y%m%d')}_{DAYS_BACK}d_security_incidents.xlsx"
    df.to_excel(filename, index=False)
    print(f"Exported {len(df)} rows to {filename}")
    return filename


def main():
    print("Fetching security incidents from Microsoft Sentinel …")
    token = get_azure_ad_token()
    rows = run_kql_query(token)

    # Determine unique incident identifiers (IncidentNumber preferred, fallback to IncidentId)
    incident_ids = {
        str(row.get("IncidentNumber") if row.get("IncidentNumber") is not None else row.get("IncidentId"))
        for row in rows
        if row.get("IncidentNumber") is not None or row.get("IncidentId") is not None
    }
    print(f"Found {len(incident_ids)} unique incidents")
    if incident_ids:
        print("Incident numbers: " + ", ".join(sorted(incident_ids)))

    export_to_excel(rows)


if __name__ == "__main__":
    main() 