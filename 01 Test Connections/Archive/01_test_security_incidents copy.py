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

def get_security_incidents(days=7, severity=None, status=None, title=None):
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

        # Base query
        query = """
        SecurityIncident
        | where TimeGenerated > ago({days}d)
        {severity_filter}
        {status_filter}
        {title_filter}
        
        | order by TimeGenerated desc
        """

        # Add filters if specified
        severity_filter = f"| where Severity == \"{severity}\"" if severity else ""
        status_filter = f"| where Status == \"{status}\"" if status else ""
        title_filter = f"| where Title == \"{title}\"" if title else ""
        
        # Format the query with parameters
        query = query.format(
            days=days,
            severity_filter=severity_filter,
            status_filter=status_filter,
            title_filter=title_filter
        )

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
            incidents = []
            
            for table in results['tables']:
                column_names = [col['name'] for col in table['columns']]
                rows = table['rows']
                
                for row in rows:
                    incident_entry = dict(zip(column_names, row))
                    # Format all datetime fields to be more readable and convert to local time
                    datetime_fields = [
                        'TimeGenerated',
                        'FirstActivityTime',
                        'LastActivityTime',
                        'LastModifiedTime',
                        'CreatedTime'
                    ]
                    
                    for field in datetime_fields:
                        if field in incident_entry and incident_entry[field]:
                            try:
                                # Parse UTC time and convert to local
                                utc_time = datetime.fromisoformat(incident_entry[field].replace('Z', '+00:00'))
                                local_time = utc_time.astimezone()
                                incident_entry[field + ' [UTC]'] = utc_time.strftime('%Y-%m-%d %H:%M:%S')
                                incident_entry[field + ' [Local]'] = local_time.strftime('%Y-%m-%d %H:%M:%S')
                            except (ValueError, AttributeError) as e:
                                print(f"Error converting time for {field}: {e}")
                                incident_entry[field + ' [UTC]'] = incident_entry[field]
                                incident_entry[field + ' [Local]'] = incident_entry[field]
                    
                    # Parse JSON fields
                    json_fields = ['RelatedAnalyticRuleIds', 'AlertIds', 'BookmarkIds', 'Comments', 'Labels']
                    for field in json_fields:
                        if field in incident_entry and incident_entry[field]:
                            try:
                                incident_entry[field] = json.loads(incident_entry[field])
                            except json.JSONDecodeError:
                                pass
                    
                    incidents.append(incident_entry)
            
            print(f"Found {len(incidents)} security incidents")
            return incidents
        else:
            print(f"Error: {response.status_code}")
            print(f"Error details: {response.text}")
            return None

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return None

def display_incidents(incidents):
    if not incidents:
        print("No incidents found.")
        return

    # Prepare data for tabulate
    table_data = []
    for i, incident in enumerate(incidents, 1):
        row = [
            i,
            incident.get('IncidentNumber', 'N/A'),
            incident.get('TimeGenerated [Local]', 'N/A'),
            incident.get('Title', 'N/A'),
            incident.get('Severity', 'N/A'),
            incident.get('Status', 'N/A'),
            incident.get('Owner', 'N/A')
        ]
        table_data.append(row)

    # Display the table
    headers = ['#', 'Incident #', 'Time (Local)', 'Title', 'Severity', 'Status', 'Owner']
    print(tabulate(table_data, headers=headers, tablefmt='grid'))
    print(f"\nTotal incidents found: {len(incidents)}")

    # Ask if user wants to see details of a specific incident
    while True:
        try:
            choice = input("\nEnter incident number to see details (or 'q' to quit): ")
            if choice.lower() == 'q':
                break
            
            incident_num = int(choice) - 1
            if 0 <= incident_num < len(incidents):
                incident = incidents[incident_num]
                print("\nIncident Details:")
                print("=" * 100)
                
                # Display basic incident information
                print(f"Incident Number: {incident.get('IncidentNumber', 'N/A')}")
                print(f"Title: {incident.get('Title', 'N/A')}")
                print(f"Created Time: {incident.get('CreatedTime [Local]', 'N/A')}")
                print(f"Severity: {incident.get('Severity', 'N/A')}")
                print(f"Status: {incident.get('Status', 'N/A')}")
                print(f"Owner: {incident.get('Owner', 'N/A')}")
                print(f"Provider: {incident.get('ProviderName', 'N/A')}")
                print(f"First Activity: {incident.get('FirstActivityTime [Local]', 'N/A')}")
                print(f"Last Activity: {incident.get('LastActivityTime [Local]', 'N/A')}")
                print(f"Last Modified: {incident.get('LastModifiedTime [Local]', 'N/A')}")
                
                # Display classification information if available
                if incident.get('Classification'):
                    print("\nClassification Information:")
                    print("-" * 50)
                    print(f"Classification: {incident.get('Classification', 'N/A')}")
                    print(f"Classification Reason: {incident.get('ClassificationReason', 'N/A')}")
                    print(f"Classification Comment: {incident.get('ClassificationComment', 'N/A')}")
                
                # Display description
                if incident.get('Description'):
                    print("\nDescription:")
                    print("-" * 50)
                    print(incident.get('Description', 'N/A'))
                
                # Display related IDs
                related_rule_ids = incident.get('RelatedAnalyticRuleIds')
                if related_rule_ids:
                    print("\nRelated Analytic Rule IDs:")
                    print("-" * 50)
                    if isinstance(related_rule_ids, list):
                        for rule_id in related_rule_ids:
                            print(f"- {rule_id}")
                    else:
                        print(related_rule_ids)
                
                alert_ids = incident.get('AlertIds')
                if alert_ids:
                    print("\nRelated Alert IDs:")
                    print("-" * 50)
                    if isinstance(alert_ids, list):
                        for alert_id in alert_ids:
                            print(f"- {alert_id}")
                    else:
                        print(alert_ids)
                
                bookmark_ids = incident.get('BookmarkIds')
                if bookmark_ids:
                    print("\nBookmark IDs:")
                    print("-" * 50)
                    if isinstance(bookmark_ids, list):
                        for bookmark_id in bookmark_ids:
                            print(f"- {bookmark_id}")
                    else:
                        print(bookmark_ids)
                
                # Display comments if available
                comments = incident.get('Comments')
                if comments:
                    print("\nComments:")
                    print("-" * 50)
                    if isinstance(comments, list):
                        for i, comment in enumerate(comments, 1):
                            if isinstance(comment, dict):
                                print(f"\nComment #{i}:")
                                for k, v in comment.items():
                                    print(f"  {k}: {v}")
                            else:
                                print(f"Comment #{i}: {comment}")
                    else:
                        print(comments)
                
                # Display labels if available
                labels = incident.get('Labels')
                if labels:
                    print("\nLabels:")
                    print("-" * 50)
                    if isinstance(labels, list):
                        for label in labels:
                            print(f"- {label}")
                    else:
                        print(labels)
                
                # Display incident URL if available
                if incident.get('IncidentUrl'):
                    print("\nIncident URL:")
                    print("-" * 50)
                    print(incident.get('IncidentUrl'))
                
                print("=" * 100)
            else:
                print("Invalid incident number. Please try again.")
        except ValueError:
            print("Please enter a valid number or 'q' to quit.")

def export_to_excel(incidents):
    if not incidents:
        print("No incidents to export.")
        return
        
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'security_incidents_{timestamp}.xlsx'
    
    # Create a copy of incidents to modify for Excel export
    incidents_for_export = []
    for incident in incidents:
        incident_copy = incident.copy()
        
        # Convert complex fields to strings for Excel
        for field in ['RelatedAnalyticRuleIds', 'AlertIds', 'BookmarkIds', 'Comments', 'Labels']:
            if field in incident_copy and isinstance(incident_copy[field], (dict, list)):
                incident_copy[field] = json.dumps(incident_copy[field])
        
        incidents_for_export.append(incident_copy)
    
    df = pd.DataFrame(incidents_for_export)
    df.to_excel(filename, index=False)
    print(f"\nExported incidents to {filename}")

if __name__ == "__main__":
    # Test different scenarios
    print("\n1. Testing security incidents with title '[Custom]-[TI]-DNS with TI Domain Correlation'")
    incidents = get_security_incidents(
        days=7,  # Last 7 days
        title="[Custom]-[TI]-DNS with TI Domain Correlation"
    )
    if incidents:
        display_incidents(incidents)
        export_to_excel(incidents)
    
    # You can add specific severity filter like this:
    # print("\n2. Testing high severity incidents")
    # high_incidents = get_security_incidents(
    #     days=7,
    #     severity="High"
    # ) 