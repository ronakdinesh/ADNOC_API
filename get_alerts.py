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

def get_security_alerts(hours=24, limit=50):
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

        # Set up the query to get security alerts
        query = f"""
        SecurityAlert
        | where TimeGenerated > ago({hours}h)
        | where AlertName == "[Custom]-[TI]-DNS with TI Domain Correlation"
        | project 
            TimeGenerated,
            AlertName,
            AlertSeverity,
            Description,
            ProviderName,
            Status,
            CompromisedEntity,
            SystemAlertId,
            Tactics,
            ConfidenceLevel
        | order by TimeGenerated desc
        | take {limit}
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
            alerts = []
            
            for table in results['tables']:
                column_names = [col['name'] for col in table['columns']]
                rows = table['rows']
                
                for row in rows:
                    alert = dict(zip(column_names, row))
                    # Format the time to be more readable
                    alert['TimeGenerated'] = datetime.fromisoformat(alert['TimeGenerated'].replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S')
                    alerts.append(alert)
            
            print(f"Found {len(alerts)} alerts")
            return alerts
        else:
            print(f"Error: {response.status_code}")
            print(f"Error details: {response.text}")
            return None

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return None

def get_common_security_logs(hours=24, limit=50):
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

        # Set up the query to get CommonSecurityLog_Enrich data
        query = f"""
        CommonSecurityLog_Enrich
        | where TimeGenerated > ago({hours}h)
        | project
            TenantId,
            TimeGenerated,
            DeviceVendor,
            DeviceProduct,
            DeviceVersion,
            DeviceEventClassID,
            Activity,
            LogSeverity,
            OriginalLogSeverity,
            AdditionalExtensions,
            DeviceAction,
            ApplicationProtocol,
            EventCount,
            DestinationDnsDomain,
            DestinationServiceName,
            DestinationTranslatedAddress,
            DestinationTranslatedPort,
            CommunicationDirection,
            DeviceDnsDomain,
            DeviceExternalID,
            DeviceFacility,
            DeviceInboundInterface,
            DeviceNtDomain,
            DeviceOutboundInterface,
            DevicePayloadId,
            ProcessName,
            DeviceTranslatedAddress,
            DestinationHostName,
            DestinationMACAddress,
            DestinationNTDomain,
            DestinationProcessId,
            DestinationUserPrivileges,
            DestinationProcessName,
            DestinationPort,
            DestinationIP,
            DeviceTimeZone,
            DestinationUserID,
            DestinationUserName,
            DeviceAddress,
            DeviceName,
            DeviceMacAddress,
            ProcessID,
            EndTime,
            ExternalID,
            ExtID,
            FileCreateTime,
            FileHash,
            FileID,
            FileModificationTime,
            FilePath,
            FilePermission,
            FileType,
            FileName,
            FileSize,
            ReceivedBytes,
            Message,
            OldFileCreateTime,
            OldFileHash,
            OldFileID,
            OldFileModificationTime,
            OldFileName,
            OldFilePath,
            OldFilePermission,
            OldFileSize,
            OldFileType,
            SentBytes,
            EventOutcome,
            Protocol,
            Reason,
            RequestURL,
            RequestClientApplication,
            RequestContext,
            RequestCookies,
            RequestMethod,
            ReceiptTime,
            SourceHostName,
            SourceMACAddress,
            SourceNTDomain,
            SourceDnsDomain,
            SourceServiceName,
            SourceTranslatedAddress,
            SourceTranslatedPort,
            SourceProcessId,
            SourceUserPrivileges,
            SourceProcessName,
            SourcePort,
            SourceIP,
            StartTime,
            SourceUserID,
            SourceUserName,
            EventType,
            DeviceEventCategory,
            DeviceCustomIPv6Address1,
            DeviceCustomIPv6Address1Label,
            DeviceCustomIPv6Address2,
            DeviceCustomIPv6Address2Label,
            DeviceCustomIPv6Address3,
            DeviceCustomIPv6Address3Label,
            DeviceCustomIPv6Address4,
            DeviceCustomIPv6Address4Label,
            DeviceCustomFloatingPoint1,
            DeviceCustomFloatingPoint1Label,
            DeviceCustomFloatingPoint2,
            DeviceCustomFloatingPoint2Label,
            DeviceCustomFloatingPoint3,
            DeviceCustomFloatingPoint3Label,
            DeviceCustomFloatingPoint4,
            DeviceCustomFloatingPoint4Label,
            DeviceCustomNumber1,
            FieldDeviceCustomNumber1,
            DeviceCustomNumber1Label,
            DeviceCustomNumber2,
            FieldDeviceCustomNumber2,
            DeviceCustomNumber2Label,
            DeviceCustomNumber3,
            FieldDeviceCustomNumber3,
            DeviceCustomNumber3Label,
            DeviceCustomString1,
            DeviceCustomString1Label,
            DeviceCustomString2,
            DeviceCustomString2Label,
            DeviceCustomString3,
            DeviceCustomString3Label,
            DeviceCustomString4,
            DeviceCustomString4Label,
            DeviceCustomString5,
            DeviceCustomString5Label,
            DeviceCustomString6,
            DeviceCustomString6Label,
            DeviceCustomDate1,
            DeviceCustomDate1Label,
            DeviceCustomDate2,
            DeviceCustomDate2Label,
            FlexDate1,
            FlexDate1Label,
            FlexNumber1,
            FlexNumber1Label,
            FlexNumber2,
            FlexNumber2Label,
            FlexString1,
            FlexString1Label,
            FlexString2,
            FlexString2Label,
            RemoteIP,
            RemotePort,
            MaliciousIP,
            ThreatSeverity,
            IndicatorThreatType,
            ThreatDescription,
            ThreatConfidence,
            ReportReferenceLink,
            MaliciousIPLongitude,
            MaliciousIPLatitude,
            MaliciousIPCountry,
            Computer,
            SourceSystem,
            SimplifiedDeviceAction,
            CollectorHostName,
            UCLogGen_CF,
            Type,
            _ResourceId,
            OpCo
        | order by TimeGenerated desc
        | take {limit}
        """

        print(f"\nExecuting query for CommonSecurityLog_Enrich...\n")

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
                    # Format the time fields to be more readable
                    time_fields = ['TimeGenerated', 'EndTime', 'StartTime', 'FileCreateTime', 
                                 'FileModificationTime', 'OldFileCreateTime', 'OldFileModificationTime',
                                 'ReceiptTime', 'DeviceCustomDate1', 'DeviceCustomDate2', 'FlexDate1']
                    
                    for field in time_fields:
                        if field in log_entry and log_entry[field]:
                            try:
                                log_entry[field] = datetime.fromisoformat(log_entry[field].replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S')
                            except (ValueError, AttributeError):
                                pass  # Skip if the field is empty or not in the expected format
                    
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

def export_to_excel(data_dict):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'sentinel_data_{timestamp}.xlsx'
    
    with pd.ExcelWriter(filename, engine='openpyxl') as writer:
        for sheet_name, data in data_dict.items():
            if data:
                df = pd.DataFrame(data)
                df.to_excel(writer, sheet_name=sheet_name, index=False)
    
    print(f"\nExported all data to {filename}")

def display_alerts(alerts):
    if not alerts:
        print("No alerts found.")
        return

    # Prepare data for tabulate
    table_data = []
    for alert in alerts:
        row = [
            alert['TimeGenerated'],
            alert['AlertName'],
            alert['AlertSeverity'],
            alert['ProviderName'],
            alert['Status']
        ]
        table_data.append(row)

    # Display the table
    headers = ['Time', 'Alert Name', 'Severity', 'Provider', 'Status']
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
                print(f"Time: {alert['TimeGenerated']}")
                print(f"Name: {alert['AlertName']}")
                print(f"Severity: {alert['AlertSeverity']}")
                print(f"Provider: {alert['ProviderName']}")
                print(f"Status: {alert['Status']}")
                print(f"Description: {alert['Description']}")
                print(f"Compromised Entity: {alert.get('CompromisedEntity', 'N/A')}")
                print(f"System Alert ID: {alert.get('SystemAlertId', 'N/A')}")
                print(f"Tactics: {alert.get('Tactics', 'N/A')}")
                print(f"Confidence Level: {alert.get('ConfidenceLevel', 'N/A')}")
            else:
                print("Invalid alert number. Please try again.")
        except ValueError:
            print("Please enter a valid number or 'q' to quit.")

if __name__ == "__main__":
    all_data = {}
    
    print("\n🔍 Fetching Latest Security Alerts from Microsoft Sentinel...\n")
    alerts = get_security_alerts(hours=168, limit=50)  # Look back 7 days
    if alerts:
        display_alerts(alerts)
        all_data['SecurityAlerts'] = alerts
    else:
        print("No alerts found in the specified time range.")

    print("\n🔍 Fetching Latest Security Logs from Microsoft Sentinel...\n")
    logs = get_common_security_logs(hours=24, limit=50)  # Look back 24 hours
    if logs:
        all_data['CommonSecurityLogs'] = logs
        print(f"Found {len(logs)} log entries")
    else:
        print("No logs found in the specified time range.")
    
    # Export all data to Excel if we have any data
    if all_data:
        export_to_excel(all_data)
    else:
        print("\nNo data found to export.")