import os
import requests
from datetime import datetime
from dotenv import load_dotenv
import adal
import sys
import pandas as pd
import traceback

"""
Fetch Microsoft Sentinel SecurityIncident records from the last 7 days and
print how many unique incidents were found (by IncidentNumber, falling back to
IncidentId) along with the list of those IDs.

Environment variables expected (or defined in a .env file alongside the script):
    TENANT_ID
    CLIENT_ID
    CLIENT_SECRET
    WORKSPACE_ID
"""

load_dotenv()

TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
WORKSPACE_ID = os.getenv("WORKSPACE_ID")

if not all([TENANT_ID, CLIENT_ID, CLIENT_SECRET, WORKSPACE_ID]):
    raise RuntimeError("TENANT_ID, CLIENT_ID, CLIENT_SECRET, and WORKSPACE_ID must be set in the environment or .env file.")

DAYS_BACK = 7


def get_token() -> str:
    """Acquire Azure AD bearer token using client‑credentials flow."""
    authority_url = f"https://login.microsoftonline.com/{TENANT_ID}"
    resource = "https://api.loganalytics.io"
    context = adal.AuthenticationContext(authority_url)
    token_response = context.acquire_token_with_client_credentials(
        resource,
        CLIENT_ID,
        CLIENT_SECRET,
    )
    return token_response["accessToken"]


def fetch_security_incidents_last_7_days(verbose: bool = True):
    """Return list of incident dicts for the last 7 days."""
    query = (
        f"SecurityIncident\n"
        f"| where TimeGenerated > ago({DAYS_BACK}d)\n"
        f"| order by TimeGenerated desc"
    )

    if verbose:
        print("Authenticating with Azure AD …")
    token = get_token()
    if verbose:
        print("Authentication successful. Querying incidents …")

    url = f"https://api.loganalytics.io/v1/workspaces/{WORKSPACE_ID}/query"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    response = requests.post(url, headers=headers, json={"query": query})
    response.raise_for_status()

    data = response.json()
    if not data.get("tables"):
        return []

    table = data["tables"][0]
    cols = [c["name"] for c in table["columns"]]
    rows = [dict(zip(cols, r)) for r in table["rows"]]
    return rows


def main():
    print("STEP 1/5: Retrieving security incidents from Microsoft Sentinel …")
    rows = fetch_security_incidents_last_7_days(verbose=True)

    print("STEP 2/5: Summarizing incidents …")
    unique_ids = {
        str(row.get("IncidentNumber") or row.get("IncidentId"))
        for row in rows
        if row.get("IncidentNumber") or row.get("IncidentId")
    }

    print("STEP 2/5 complete.")

    print("\nSummary --------------------------------------------------")
    print(f"Queried at: {datetime.utcnow().isoformat()}Z")
    print(f"Window     : {DAYS_BACK} days")
    print(f"Total rows : {len(rows)}")
    print(f"Unique incidents: {len(unique_ids)}")
    if unique_ids:
        print("\nUnique incident list:")
        for idx, inc_id in enumerate(sorted(unique_ids), 1):
            print(f"  {idx}) {inc_id}")

    if not unique_ids:
        print("No incidents available to analyze. Exiting.")
        return

    print("\nSTEP 3/5: Select incidents for SOC analysis …")
    selection = input("Enter the incident number(s) you want to analyze (comma‑separated) or 'all' for every incident: ").strip()

    if selection.lower() == "all":
        selected_ids = unique_ids
    else:
        selected_ids = {s.strip() for s in selection.split(',') if s.strip()}

    if not selected_ids:
        print("No valid incident IDs entered. Exiting.")
        return

    # Filter rows for selected incidents
    filtered_rows = [r for r in rows if str(r.get("IncidentNumber") or r.get("IncidentId")) in selected_ids]

    if not filtered_rows:
        print("No matching incidents found for the given selection. Exiting.")
        return

    print("STEP 4/5: Preparing data for analysis …")
    df = pd.DataFrame(filtered_rows)
    tmp_excel = f"selected_incidents_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    df.to_excel(tmp_excel, index=False)
    print(f"\nSaved {len(df)} selected incident rows to {tmp_excel}")

    # Attempt to import the analysis function
    try:
        try:
            from llm_read_security_incidents import analyze_security_incidents
        except ImportError:
            # Add path to 02 AI Agent API folder if not on PYTHONPATH
            script_dir = os.path.dirname(os.path.abspath(__file__))
            parent_dir = os.path.dirname(script_dir)
            ai_api_dir = os.path.join(parent_dir, "02 AI Agent API")
            sys.path.append(ai_api_dir)
            from llm_read_security_incidents import analyze_security_incidents
    except ImportError:
        print("Could not import 'analyze_security_incidents'. Please verify the 02 AI Agent API directory is present.")
        return

    print("\nSTEP 5/5: Launching SOC analysis …")
    try:
        analyze_security_incidents(tmp_excel, fetch_time=datetime.utcnow(), log_window_days=7)
        print("Analysis complete. Review the generated text report(s).")
        print("All steps finished successfully.")
    except Exception as e:
        print(f"Error during analysis: {e}")
        traceback.print_exc()


if __name__ == "__main__":
    main() 