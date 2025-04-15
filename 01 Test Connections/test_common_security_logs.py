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

def get_common_security_logs(hours=24, limit=50, device_vendor=None):
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

        # Base query with specific columns
        query = """
        CommonSecurityLog_Enrich
        | where TimeGenerated > ago({hours}h)
        {vendor_filter}
        | project TimeGenerated, 
                 DeviceVendor,
                 DeviceEventClassID,
                 Activity,
                 DeviceAction,
                 ApplicationProtocol,
                 DestinationPort,
                 DestinationIP,
                 DeviceName,
                 Protocol,
                 RequestURL,
                 SourceHostName,
                 SourceIP,
                 SourceUserName,
                 DeviceEventCategory,
                 FlexString2,
                 OpCo
        | order by TimeGenerated desc
        | take {limit}
        """

        # Add vendor filter if specified
        vendor_filter = f"| where DeviceVendor == \"{device_vendor}\"" if device_vendor else ""
        
        # Format the query with parameters
        query = query.format(
            hours=hours,
            limit=limit,
            vendor_filter=vendor_filter
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
            logs = []
            
            for table in results['tables']:
                column_names = [col['name'] for col in table['columns']]
                rows = table['rows']
                
                for row in rows:
                    log_entry = dict(zip(column_names, row))
                    # Format TimeGenerated field to be more readable
                    if 'TimeGenerated' in log_entry and log_entry['TimeGenerated']:
                        try:
                            # Parse UTC time and convert to local
                            utc_time = datetime.fromisoformat(log_entry['TimeGenerated'].replace('Z', '+00:00'))
                            local_time = utc_time.astimezone()
                            log_entry['TimeGenerated [UTC]'] = utc_time.strftime('%Y-%m-%d %H:%M:%S')
                            log_entry['TimeGenerated [Local]'] = local_time.strftime('%Y-%m-%d %H:%M:%S')
                        except (ValueError, AttributeError) as e:
                            print(f"Error converting time for TimeGenerated: {e}")
                            log_entry['TimeGenerated [UTC]'] = log_entry['TimeGenerated']
                            log_entry['TimeGenerated [Local]'] = log_entry['TimeGenerated']
                    logs.append(log_entry)
            
            print(f"Found {len(logs)} log entries")
            return logs
        else:
            print(f"Error: {response.status_code}")
            print(f"Error details: {response.text}")
            return None

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return None

def display_logs(logs):
    if not logs:
        print("No logs found.")
        return

    # Prepare data for tabulate
    table_data = []
    for log in logs:
        row = [
            log.get('TimeGenerated [Local]', 'N/A'),
            log.get('DeviceVendor', 'N/A'),
            log.get('DeviceEventClassID', 'N/A'),
            log.get('Activity', 'N/A'),
            log.get('DeviceAction', 'N/A'),
            log.get('ApplicationProtocol', 'N/A'),
            log.get('DestinationPort', 'N/A'),
            log.get('DestinationIP', 'N/A'),
            log.get('DeviceName', 'N/A'),
            log.get('Protocol', 'N/A'),
            log.get('RequestURL', 'N/A'),
            log.get('SourceHostName', 'N/A'),
            log.get('SourceIP', 'N/A'),
            log.get('SourceUserName', 'N/A'),
            log.get('DeviceEventCategory', 'N/A'),
            log.get('FlexString2', 'N/A'),
            log.get('OpCo', 'N/A')
        ]
        table_data.append(row)

    # Display the table with all columns from the query
    headers = [
        'TimeGenerated', 'DeviceVendor', 'DeviceEventClassID', 'Activity',
        'DeviceAction', 'ApplicationProtocol', 'DestinationPort', 'DestinationIP',
        'DeviceName', 'Protocol', 'RequestURL', 'SourceHostName',
        'SourceIP', 'SourceUserName', 'DeviceEventCategory', 'FlexString2', 'OpCo'
    ]
    print(tabulate(table_data, headers=headers, tablefmt='grid'))
    print(f"\nTotal logs found: {len(logs)}")

    # Ask if user wants to see details of a specific log
    while True:
        try:
            choice = input("\nEnter log number to see details (or 'q' to quit): ")
            if choice.lower() == 'q':
                break
            
            log_num = int(choice) - 1
            if 0 <= log_num < len(logs):
                log = logs[log_num]
                print("\nLog Details:")
                print("=" * 100)
                
                # Display all fields in the log
                for field, value in log.items():
                    if value:
                        print(f"{field}: {value}")
                
                print("=" * 100)
            else:
                print("Invalid log number. Please try again.")
        except ValueError:
            print("Please enter a valid number or 'q' to quit.")

def export_to_excel(logs):
    if not logs:
        print("No logs to export.")
        return
        
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'common_security_logs_{timestamp}.xlsx'
    
    df = pd.DataFrame(logs)
    df.to_excel(filename, index=False)
    print(f"\nExported logs to {filename}")

if __name__ == "__main__":
    # Test different scenarios
    print("\n1. Testing all security logs from last 7 days")
    logs = get_common_security_logs(
        hours=24*7,  # Last 7 days
        limit=50
    )
    if logs:
        display_logs(logs)
        export_to_excel(logs)
    
    # You can add specific vendor filter like this:
    # print("\n2. Testing logs from specific vendor")
    # vendor_logs = get_common_security_logs(
    #     hours=24,
    #     limit=50,
    #     device_vendor="Cisco"
    # ) 