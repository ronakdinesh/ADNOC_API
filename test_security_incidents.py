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

def get_security_incidents(hours=24, limit=50, title=None):
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
        | where TimeGenerated > ago({hours}h)
        {title_filter}
        | extend Comments = parse_json(Comments)
        | extend Labels = parse_json(Labels)
        | extend AdditionalData = parse_json(AdditionalData)
        | extend Tasks = parse_json(Tasks)
        | project
            TenantId,
            TimeGenerated,
            IncidentName,
            Title,
            Description,
            Severity,
            Status,
            Classification,
            ClassificationComment,
            ClassificationReason,
            Owner,
            ProviderName,
            ProviderIncidentId,
            FirstActivityTime,
            LastActivityTime,
            FirstModifiedTime,
            LastModifiedTime,
            CreatedTime,
            ClosedTime,
            IncidentNumber,
            RelatedAnalyticRuleIds,
            AlertIds,
            BookmarkIds,
            Comments,
            Tasks,
            Labels,
            IncidentUrl,
            AdditionalData,
            ModifiedBy,
            SourceSystem,
            Type
        | order by TimeGenerated desc
        | take {limit}
        """

        # Add title filter if specified
        title_filter = f"| where Title == \"{title}\"" if title else ""
        
        # Format the query with parameters
        query = query.format(
            hours=hours,
            limit=limit,
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
                    incident = dict(zip(column_names, row))
                    # Format all datetime fields to be more readable and convert to local time
                    datetime_fields = [
                        'TimeGenerated',
                        'FirstActivityTime',
                        'LastActivityTime',
                        'FirstModifiedTime',
                        'LastModifiedTime',
                        'CreatedTime',
                        'ClosedTime'
                    ]
                    
                    for field in datetime_fields:
                        if field in incident and incident[field]:
                            try:
                                # Parse UTC time and convert to local
                                utc_time = datetime.fromisoformat(incident[field].replace('Z', '+00:00'))
                                local_time = utc_time.astimezone()
                                incident[field + ' [UTC]'] = utc_time.strftime('%Y-%m-%d %H:%M:%S')
                                incident[field + ' [Local]'] = local_time.strftime('%Y-%m-%d %H:%M:%S')
                            except (ValueError, AttributeError) as e:
                                print(f"Error converting time for {field}: {e}")
                                incident[field + ' [UTC]'] = incident[field]
                                incident[field + ' [Local]'] = incident[field]
                    incidents.append(incident)
            
            print(f"Found {len(incidents)} incidents")
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
    for incident in incidents:
        row = [
            incident.get('TimeGenerated [Local]', 'N/A'),
            incident.get('Title', 'N/A'),
            incident.get('Severity', 'N/A'),
            incident.get('Status', 'N/A'),
            incident.get('Owner', 'N/A')
        ]
        table_data.append(row)

    # Display the table
    headers = ['Time (Local)', 'Title', 'Severity', 'Status', 'Owner']
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
                print("=" * 50)
                
                # Display all available fields
                fields_to_display = [
                    ('Time Generated (UTC)', 'TimeGenerated [UTC]'),
                    ('Time Generated (Local)', 'TimeGenerated [Local]'),
                    ('Incident Name', 'IncidentName'),
                    ('Title', 'Title'),
                    ('Description', 'Description'),
                    ('Severity', 'Severity'),
                    ('Status', 'Status'),
                    ('Classification', 'Classification'),
                    ('Classification Comment', 'ClassificationComment'),
                    ('Classification Reason', 'ClassificationReason'),
                    ('Owner', 'Owner'),
                    ('Provider Name', 'ProviderName'),
                    ('Provider Incident ID', 'ProviderIncidentId'),
                    ('First Activity (UTC)', 'FirstActivityTime [UTC]'),
                    ('First Activity (Local)', 'FirstActivityTime [Local]'),
                    ('Last Activity (UTC)', 'LastActivityTime [UTC]'),
                    ('Last Activity (Local)', 'LastActivityTime [Local]'),
                    ('First Modified (UTC)', 'FirstModifiedTime [UTC]'),
                    ('First Modified (Local)', 'FirstModifiedTime [Local]'),
                    ('Last Modified (UTC)', 'LastModifiedTime [UTC]'),
                    ('Last Modified (Local)', 'LastModifiedTime [Local]'),
                    ('Created (UTC)', 'CreatedTime [UTC]'),
                    ('Created (Local)', 'CreatedTime [Local]'),
                    ('Closed (UTC)', 'ClosedTime [UTC]'),
                    ('Closed (Local)', 'ClosedTime [Local]'),
                    ('Incident Number', 'IncidentNumber'),
                    ('Incident URL', 'IncidentUrl'),
                    ('Modified By', 'ModifiedBy'),
                    ('Source System', 'SourceSystem'),
                    ('Type', 'Type')
                ]
                
                for display_name, field_name in fields_to_display:
                    value = incident.get(field_name, 'N/A')
                    if value:
                        print(f"{display_name}: {value}")
                
                if incident.get('Comments'):
                    print("\nComments:")
                    for comment in incident['Comments']:
                        print(f"- {comment}")
                
                if incident.get('Tasks'):
                    print("\nTasks:")
                    for task in incident['Tasks']:
                        print(f"- {task}")
                
                if incident.get('Labels'):
                    print("\nLabels:")
                    for label in incident['Labels']:
                        print(f"- {label}")
                
                if incident.get('AlertIds'):
                    print("\nAlert IDs:")
                    for alert_id in incident['AlertIds']:
                        print(f"- {alert_id}")
                
                if incident.get('BookmarkIds'):
                    print("\nBookmark IDs:")
                    for bookmark_id in incident['BookmarkIds']:
                        print(f"- {bookmark_id}")
                
                if incident.get('RelatedAnalyticRuleIds'):
                    print("\nRelated Analytic Rule IDs:")
                    for rule_id in incident['RelatedAnalyticRuleIds']:
                        print(f"- {rule_id}")
                
                if incident.get('AdditionalData'):
                    print("\nAdditional Data:")
                    for key, value in incident['AdditionalData'].items():
                        print(f"{key}: {value}")
                
                if incident.get('CustomDetails'):
                    print("\nCustom Details:")
                    for key, value in incident['CustomDetails'].items():
                        print(f"{key}: {value}")
                
                print("=" * 50)
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
    
    df = pd.DataFrame(incidents)
    df.to_excel(filename, index=False)
    print(f"\nExported incidents to {filename}")

if __name__ == "__main__":
    # Test different scenarios
    print("\n1. Testing all incidents from last 7 days")
    incidents = get_security_incidents(
        hours=168,  # Last 7 days
        limit=50
    )
    if incidents:
        display_incidents(incidents)
        export_to_excel(incidents)
    
    # You can add specific incident title filter like this:
    # print("\n2. Testing specific incident title")
    # specific_incidents = get_security_incidents(
    #     hours=168,
    #     limit=50,
    #     title="Your Incident Title Here"
    # ) 