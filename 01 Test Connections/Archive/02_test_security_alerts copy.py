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

def get_security_alerts(days=7, severity=None, status=None):
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
        SecurityAlert
        | where TimeGenerated > ago({days}d)
        {severity_filter}
        {status_filter}
        | where AlertName == "[Custom]-[TI]-DNS with TI Domain Correlation"
        | order by TimeGenerated desc
        """

        # Add filters if specified
        severity_filter = f"| where AlertSeverity == \"{severity}\"" if severity else ""
        status_filter = f"| where Status == \"{status}\"" if status else ""
        
        # Format the query with parameters
        query = query.format(
            days=days,
            severity_filter=severity_filter,
            status_filter=status_filter
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
            alerts = []
            
            for table in results['tables']:
                column_names = [col['name'] for col in table['columns']]
                rows = table['rows']
                
                for row in rows:
                    alert_entry = dict(zip(column_names, row))
                    # Format all datetime fields to be more readable and convert to local time
                    datetime_fields = [
                        'TimeGenerated',
                        'ProcessingEndTime'
                    ]
                    
                    for field in datetime_fields:
                        if field in alert_entry and alert_entry[field]:
                            try:
                                # Parse UTC time and convert to local
                                utc_time = datetime.fromisoformat(alert_entry[field].replace('Z', '+00:00'))
                                local_time = utc_time.astimezone()
                                alert_entry[field + ' [UTC]'] = utc_time.strftime('%Y-%m-%d %H:%M:%S')
                                alert_entry[field + ' [Local]'] = local_time.strftime('%Y-%m-%d %H:%M:%S')
                            except (ValueError, AttributeError) as e:
                                print(f"Error converting time for {field}: {e}")
                                alert_entry[field + ' [UTC]'] = alert_entry[field]
                                alert_entry[field + ' [Local]'] = alert_entry[field]
                    
                    # Parse JSON fields
                    json_fields = ['ExtendedProperties', 'Entities', 'Tactics', 'Techniques']
                    for field in json_fields:
                        if field in alert_entry and alert_entry[field]:
                            try:
                                alert_entry[field] = json.loads(alert_entry[field])
                            except json.JSONDecodeError:
                                pass
                    
                    alerts.append(alert_entry)
            
            print(f"Found {len(alerts)} security alerts")
            return alerts
        else:
            print(f"Error: {response.status_code}")
            print(f"Error details: {response.text}")
            return None

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return None

def display_alerts(alerts):
    if not alerts:
        print("No alerts found.")
        return

    # Prepare data for tabulate
    table_data = []
    for i, alert in enumerate(alerts, 1):
        row = [
            i,
            alert.get('TimeGenerated [Local]', 'N/A'),
            alert.get('DisplayName', 'N/A'),
            alert.get('AlertSeverity', 'N/A'),
            alert.get('Status', 'N/A'),
            alert.get('ProviderName', 'N/A')
        ]
        table_data.append(row)

    # Display the table
    headers = ['#', 'Time (Local)', 'Alert Name', 'Severity', 'Status', 'Provider']
    print(tabulate(table_data, headers=headers, tablefmt='grid'))
    print(f"\nTotal alerts found: {len(alerts)}")

    # Ask if user wants to see details of a specific alert
    while True:
        try:
            choice = input("\nEnter alert number to see details (or 'q' to quit): ")
            if choice.lower() == 'q':
                break
            
            alert_num = int(choice) - 1
            if 0 <= alert_num < len(alerts):
                alert = alerts[alert_num]
                print("\nAlert Details:")
                print("=" * 100)
                
                # Display basic alert information
                print(f"Name: {alert.get('DisplayName', 'N/A')}")
                print(f"Time: {alert.get('TimeGenerated [Local]', 'N/A')}")
                print(f"Severity: {alert.get('AlertSeverity', 'N/A')}")
                print(f"Status: {alert.get('Status', 'N/A')}")
                print(f"Provider: {alert.get('ProviderName', 'N/A')}")
                print(f"Product: {alert.get('ProductName', 'N/A')}")
                print(f"Vendor: {alert.get('VendorName', 'N/A')}")
                print(f"Alert Type: {alert.get('AlertType', 'N/A')}")
                print(f"Confidence Level: {alert.get('ConfidenceLevel', 'N/A')}")
                print(f"Confidence Score: {alert.get('ConfidenceScore', 'N/A')}")
                print(f"System Alert ID: {alert.get('SystemAlertId', 'N/A')}")
                print(f"Compromised Entity: {alert.get('CompromisedEntity', 'N/A')}")
                
                # Display description
                print("\nDescription:")
                print("-" * 50)
                print(alert.get('Description', 'N/A'))
                
                # Display remediation steps if available
                if alert.get('RemediationSteps'):
                    print("\nRemediation Steps:")
                    print("-" * 50)
                    print(alert.get('RemediationSteps', 'N/A'))
                
                # Display tactics and techniques if available
                tactics = alert.get('Tactics')
                if tactics:
                    if isinstance(tactics, str):
                        print(f"\nTactics: {tactics}")
                    else:
                        print("\nTactics:")
                        print("-" * 50)
                        for tactic in tactics:
                            print(f"- {tactic}")
                
                techniques = alert.get('Techniques')
                if techniques:
                    if isinstance(techniques, str):
                        print(f"\nTechniques: {techniques}")
                    else:
                        print("\nTechniques:")
                        print("-" * 50)
                        for technique in techniques:
                            print(f"- {technique}")
                
                # Display entities if available
                entities = alert.get('Entities')
                if entities and isinstance(entities, list) and len(entities) > 0:
                    print("\nEntities:")
                    print("-" * 50)
                    for i, entity in enumerate(entities, 1):
                        if isinstance(entity, dict):
                            print(f"\nEntity #{i}:")
                            for k, v in entity.items():
                                print(f"  {k}: {v}")
                        else:
                            print(f"Entity #{i}: {entity}")
                
                # Display extended properties if available
                ext_props = alert.get('ExtendedProperties')
                if ext_props and isinstance(ext_props, dict) and len(ext_props) > 0:
                    print("\nExtended Properties:")
                    print("-" * 50)
                    for k, v in ext_props.items():
                        print(f"{k}: {v}")
                
                # Display links if available
                if alert.get('AlertLink'):
                    print("\nAlert Link:")
                    print("-" * 50)
                    print(alert.get('AlertLink'))
                
                print("=" * 100)
            else:
                print("Invalid alert number. Please try again.")
        except ValueError:
            print("Please enter a valid number or 'q' to quit.")

def export_to_excel(alerts):
    if not alerts:
        print("No alerts to export.")
        return
        
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'security_alerts_{timestamp}.xlsx'
    
    # Create a copy of alerts to modify for Excel export
    alerts_for_export = []
    for alert in alerts:
        alert_copy = alert.copy()
        
        # Convert complex fields to strings for Excel
        for field in ['ExtendedProperties', 'Entities', 'Tactics', 'Techniques']:
            if field in alert_copy and isinstance(alert_copy[field], (dict, list)):
                alert_copy[field] = json.dumps(alert_copy[field])
        
        alerts_for_export.append(alert_copy)
    
    df = pd.DataFrame(alerts_for_export)
    df.to_excel(filename, index=False)
    print(f"\nExported alerts to {filename}")

if __name__ == "__main__":
    # Test different scenarios
    print("\n1. Testing all security alerts from last 7 days")
    alerts = get_security_alerts(
        days=7  # Last 7 days
    )
    if alerts:
        display_alerts(alerts)
        export_to_excel(alerts)
    
    # You can add specific severity filter like this:
    # print("\n2. Testing high severity alerts")
    # high_alerts = get_security_alerts(
    #     days=7,
    #     severity="High"
    # ) 