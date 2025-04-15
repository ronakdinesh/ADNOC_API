import requests
import json
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
import adal
from tabulate import tabulate
import pandas as pd

# Load environment variables from .env file
load_dotenv()

# Azure AD and Log Analytics configuration
tenant_id = os.getenv('TENANT_ID')
client_id = os.getenv('CLIENT_ID')
client_secret = os.getenv('CLIENT_SECRET')
workspace_id = os.getenv('WORKSPACE_ID')

def get_joint_alerts_incidents():
    try:
        print("Authenticating with Azure AD...")
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
        print("Authentication successful!")

        # Joint query
        query = """
        SecurityAlert
        | where TimeGenerated > ago(7d)
        | where AlertName == "[Custom]-[TI]-DNS with TI Domain Correlation"
        | extend SystemAlertId = tostring(SystemAlertId)
        | join kind=leftouter (
            SecurityIncident
            | where TimeGenerated > ago(7d)
            | where Title == "[Custom]-[TI]-DNS with TI Domain Correlation"
            | mv-expand todynamic(AlertIds)
            | extend AlertId = tostring(AlertIds)
        ) on $left.SystemAlertId == $right.AlertId
        | project-away AlertId // Remove the temporary AlertId column
        | order by TimeGenerated desc
        """

        print(f"\nExecuting query:\n{query}\n")

        # API endpoint
        url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"

        # Headers
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        # Request body
        request_body = {
            'query': query
        }

        print("Sending request to Microsoft Sentinel API...")
        # Send the request
        response = requests.post(url, headers=headers, json=request_body)

        if response.status_code == 200:
            print("Request successful!")
            results = response.json()
            joint_entries = []
            
            for table in results['tables']:
                column_names = [col['name'] for col in table['columns']]
                rows = table['rows']
                
                for row in rows:
                    entry = dict(zip(column_names, row))
                    # Format datetime fields to be more readable and convert to local time
                    datetime_fields = ['TimeGenerated', 'IncidentTimeGenerated']
                    
                    for field in datetime_fields:
                        if field in entry and entry[field]:
                            try:
                                # Parse UTC time and convert to local
                                utc_time = datetime.fromisoformat(entry[field].replace('Z', '+00:00'))
                                local_time = utc_time.astimezone()
                                entry[field + ' [UTC]'] = utc_time.strftime('%Y-%m-%d %H:%M:%S')
                                entry[field + ' [Local]'] = local_time.strftime('%Y-%m-%d %H:%M:%S')
                            except (ValueError, AttributeError) as e:
                                print(f"Error converting time for {field}: {e}")
                                entry[field + ' [UTC]'] = entry[field]
                                entry[field + ' [Local]'] = entry[field]
                    
                    joint_entries.append(entry)
            
            print(f"Found {len(joint_entries)} joint alert-incident entries")
            return joint_entries
        else:
            print(f"Error: {response.status_code}")
            print(f"Error details: {response.text}")
            return None

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return None

def display_joint_entries(entries):
    if not entries:
        print("No joint entries found.")
        return

    # Prepare data for tabulate
    table_data = []
    for i, entry in enumerate(entries, 1):
        row = [
            i,
            entry.get('TimeGenerated [Local]', 'N/A'),
            entry.get('AlertName', 'N/A'),
            entry.get('AlertSeverity', 'N/A'),
            entry.get('Status', 'N/A'),
            entry.get('SystemAlertId', 'N/A'),
            entry.get('TimeGenerated1 [Local]', 'N/A'),
            entry.get('Title', 'N/A'),
            entry.get('Severity', 'N/A'),
            entry.get('Status1', 'N/A'),
            entry.get('IncidentNumber', 'N/A')
        ]
        table_data.append(row)

    # Display the table
    headers = ['#', 'Alert Time', 'Alert Name', 'Alert Severity', 'Alert Status',
               'SystemAlertId', 'Incident Time', 'Incident Title', 'Incident Severity', 
               'Incident Status', 'Incident Number']
    print(tabulate(table_data, headers=headers, tablefmt='grid'))
    print(f"\nTotal joint entries found: {len(entries)}")

def export_to_excel(entries):
    if not entries:
        print("No entries to export.")
        return
        
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'joint_alerts_incidents_{timestamp}.xlsx'
    
    # Create a copy of entries to modify for Excel export
    entries_for_export = []
    for entry in entries:
        entry_copy = entry.copy()
        
        # Rename fields for better readability in Excel
        field_mapping = {
            'TimeGenerated': 'Alert Time',
            'AlertName': 'Alert Name',
            'AlertSeverity': 'Alert Severity',
            'Status': 'Alert Status',
            'SystemAlertId': 'System Alert ID',
            'TimeGenerated1': 'Incident Time',
            'Title': 'Incident Title',
            'Severity': 'Incident Severity',
            'Status1': 'Incident Status',
            'IncidentNumber': 'Incident Number'
        }
        
        # Apply field mapping
        for old_name, new_name in field_mapping.items():
            if old_name in entry_copy:
                entry_copy[new_name] = entry_copy.pop(old_name)
        
        entries_for_export.append(entry_copy)
    
    df = pd.DataFrame(entries_for_export)
    
    # Reorder columns for better readability
    preferred_order = [
        'Alert Time', 'Alert Name', 'Alert Severity', 'Alert Status', 'System Alert ID',
        'Incident Time', 'Incident Title', 'Incident Severity', 'Incident Status', 'Incident Number'
    ]
    
    # Only include columns that exist in the data
    final_columns = [col for col in preferred_order if col in df.columns]
    df = df[final_columns]
    
    # Export to Excel
    df.to_excel(filename, index=False)
    print(f"\nExported joint entries to {filename}")

def get_table_columns():
    try:
        print("Authenticating with Azure AD...")
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
        print("Authentication successful!")

        # Get SecurityAlert columns
        alert_query = """
        SecurityAlert
        | take 1
        """
        
        # Get SecurityIncident columns
        incident_query = """
        SecurityIncident
        | take 1
        """

        url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        # Get SecurityAlert columns
        print("\nGetting SecurityAlert columns...")
        response = requests.post(url, headers=headers, json={'query': alert_query})
        if response.status_code == 200:
            results = response.json()
            if results.get('tables') and results['tables'][0].get('columns'):
                alert_columns = [col['name'] for col in results['tables'][0]['columns']]
                print(f"\nSecurityAlert has {len(alert_columns)} columns:")
                for col in sorted(alert_columns):
                    print(f"- {col}")

        # Get SecurityIncident columns
        print("\nGetting SecurityIncident columns...")
        response = requests.post(url, headers=headers, json={'query': incident_query})
        if response.status_code == 200:
            results = response.json()
            if results.get('tables') and results['tables'][0].get('columns'):
                incident_columns = [col['name'] for col in results['tables'][0]['columns']]
                print(f"\nSecurityIncident has {len(incident_columns)} columns:")
                for col in sorted(incident_columns):
                    print(f"- {col}")

        # Get joined columns
        print("\nGetting joined columns...")
        joint_entries = get_joint_alerts_incidents()
        if joint_entries and len(joint_entries) > 0:
            first_entry = joint_entries[0]
            print(f"\nJoined result has {len(first_entry)} columns:")
            for col in sorted(first_entry.keys()):
                source = "SecurityAlert" if col in alert_columns else "SecurityIncident"
                print(f"- {col} (from {source})")

    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    print("\nGetting table column information...")
    get_table_columns()
    
    print("\nTesting joint query for SecurityAlert and SecurityIncident tables")
    joint_entries = get_joint_alerts_incidents()
    if joint_entries:
        display_joint_entries(joint_entries)
        export_to_excel(joint_entries) 