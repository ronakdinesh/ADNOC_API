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

        # Base query
        query = """
        CommonSecurityLog_Enrich
        | where TimeGenerated > ago({hours}h)
        {vendor_filter}
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
                    # Format all datetime fields to be more readable and convert to local time
                    datetime_fields = [
                        'TimeGenerated',
                        'EndTime',
                        'FileCreateTime',
                        'FileModificationTime',
                        'OldFileCreateTime',
                        'OldFileModificationTime',
                        'ReceiptTime',
                        'StartTime',
                        'DeviceCustomDate1',
                        'DeviceCustomDate2',
                        'FlexDate1'
                    ]
                    
                    for field in datetime_fields:
                        if field in log_entry and log_entry[field]:
                            try:
                                # Parse UTC time and convert to local
                                utc_time = datetime.fromisoformat(log_entry[field].replace('Z', '+00:00'))
                                local_time = utc_time.astimezone()
                                log_entry[field + ' [UTC]'] = utc_time.strftime('%Y-%m-%d %H:%M:%S')
                                log_entry[field + ' [Local]'] = local_time.strftime('%Y-%m-%d %H:%M:%S')
                            except (ValueError, AttributeError) as e:
                                print(f"Error converting time for {field}: {e}")
                                log_entry[field + ' [UTC]'] = log_entry[field]
                                log_entry[field + ' [Local]'] = log_entry[field]
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
            log.get('DeviceProduct', 'N/A'),
            log.get('Activity', 'N/A'),
            log.get('LogSeverity', 'N/A'),
            log.get('DeviceAction', 'N/A')
        ]
        table_data.append(row)

    # Display the table
    headers = ['Time (Local)', 'Vendor', 'Product', 'Activity', 'Severity', 'Action']
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
                
                # Group fields by category for better readability
                field_categories = {
                    "Basic Information": [
                        ('Time Generated (UTC)', 'TimeGenerated [UTC]'),
                        ('Time Generated (Local)', 'TimeGenerated [Local]'),
                        ('Device Vendor', 'DeviceVendor'),
                        ('Device Product', 'DeviceProduct'),
                        ('Device Version', 'DeviceVersion'),
                        ('Device Event Class ID', 'DeviceEventClassID'),
                        ('Activity', 'Activity'),
                        ('Message', 'Message'),
                        ('Log Severity', 'LogSeverity'),
                        ('Original Log Severity', 'OriginalLogSeverity'),
                        ('Device Action', 'DeviceAction'),
                        ('Event Type', 'EventType'),
                        ('Event Outcome', 'EventOutcome'),
                        ('Event Count', 'EventCount')
                    ],
                    "Time Information": [
                        ('Start Time (UTC)', 'StartTime [UTC]'),
                        ('Start Time (Local)', 'StartTime [Local]'),
                        ('End Time (UTC)', 'EndTime [UTC]'),
                        ('End Time (Local)', 'EndTime [Local]'),
                        ('Receipt Time (UTC)', 'ReceiptTime [UTC]'),
                        ('Receipt Time (Local)', 'ReceiptTime [Local]')
                    ],
                    "Source Information": [
                        ('Source IP', 'SourceIP'),
                        ('Source Hostname', 'SourceHostName'),
                        ('Source Port', 'SourcePort'),
                        ('Source User ID', 'SourceUserID'),
                        ('Source Username', 'SourceUserName'),
                        ('Source DNS Domain', 'SourceDnsDomain'),
                        ('Source NT Domain', 'SourceNTDomain'),
                        ('Source MAC Address', 'SourceMACAddress'),
                        ('Source Process Name', 'SourceProcessName'),
                        ('Source Process ID', 'SourceProcessId'),
                        ('Source User Privileges', 'SourceUserPrivileges'),
                        ('Source Translated Address', 'SourceTranslatedAddress'),
                        ('Source Translated Port', 'SourceTranslatedPort'),
                        ('Source Service Name', 'SourceServiceName')
                    ],
                    "Destination Information": [
                        ('Destination IP', 'DestinationIP'),
                        ('Destination Hostname', 'DestinationHostName'),
                        ('Destination Port', 'DestinationPort'),
                        ('Destination User ID', 'DestinationUserID'),
                        ('Destination Username', 'DestinationUserName'),
                        ('Destination DNS Domain', 'DestinationDnsDomain'),
                        ('Destination NT Domain', 'DestinationNTDomain'),
                        ('Destination MAC Address', 'DestinationMACAddress'),
                        ('Destination Process Name', 'DestinationProcessName'),
                        ('Destination Process ID', 'DestinationProcessId'),
                        ('Destination User Privileges', 'DestinationUserPrivileges'),
                        ('Destination Translated Address', 'DestinationTranslatedAddress'),
                        ('Destination Translated Port', 'DestinationTranslatedPort'),
                        ('Destination Service Name', 'DestinationServiceName')
                    ],
                    "Device Information": [
                        ('Device Name', 'DeviceName'),
                        ('Device Address', 'DeviceAddress'),
                        ('Device MAC Address', 'DeviceMacAddress'),
                        ('Device NT Domain', 'DeviceNtDomain'),
                        ('Device DNS Domain', 'DeviceDnsDomain'),
                        ('Device Timezone', 'DeviceTimeZone'),
                        ('Device Facility', 'DeviceFacility'),
                        ('Device External ID', 'DeviceExternalID'),
                        ('Device Event Category', 'DeviceEventCategory'),
                        ('Device Translated Address', 'DeviceTranslatedAddress'),
                        ('Device Inbound Interface', 'DeviceInboundInterface'),
                        ('Device Outbound Interface', 'DeviceOutboundInterface'),
                        ('Device Payload ID', 'DevicePayloadId')
                    ],
                    "File Information": [
                        ('File Name', 'FileName'),
                        ('File Path', 'FilePath'),
                        ('File Size', 'FileSize'),
                        ('File Type', 'FileType'),
                        ('File ID', 'FileID'),
                        ('File Hash', 'FileHash'),
                        ('File Permission', 'FilePermission'),
                        ('File Create Time (UTC)', 'FileCreateTime [UTC]'),
                        ('File Create Time (Local)', 'FileCreateTime [Local]'),
                        ('File Modification Time (UTC)', 'FileModificationTime [UTC]'),
                        ('File Modification Time (Local)', 'FileModificationTime [Local]'),
                        ('Old File Name', 'OldFileName'),
                        ('Old File Path', 'OldFilePath'),
                        ('Old File Size', 'OldFileSize'),
                        ('Old File Type', 'OldFileType'),
                        ('Old File ID', 'OldFileID'),
                        ('Old File Hash', 'OldFileHash'),
                        ('Old File Permission', 'OldFilePermission'),
                        ('Old File Create Time (UTC)', 'OldFileCreateTime [UTC]'),
                        ('Old File Create Time (Local)', 'OldFileCreateTime [Local]'),
                        ('Old File Modification Time (UTC)', 'OldFileModificationTime [UTC]'),
                        ('Old File Modification Time (Local)', 'OldFileModificationTime [Local]')
                    ],
                    "Network Information": [
                        ('Protocol', 'Protocol'),
                        ('Application Protocol', 'ApplicationProtocol'),
                        ('Communication Direction', 'CommunicationDirection'),
                        ('Sent Bytes', 'SentBytes'),
                        ('Received Bytes', 'ReceivedBytes'),
                        ('Remote IP', 'RemoteIP'),
                        ('Remote Port', 'RemotePort')
                    ],
                    "Request Information": [
                        ('Request URL', 'RequestURL'),
                        ('Request Method', 'RequestMethod'),
                        ('Request Client Application', 'RequestClientApplication'),
                        ('Request Context', 'RequestContext'),
                        ('Request Cookies', 'RequestCookies')
                    ],
                    "Process Information": [
                        ('Process Name', 'ProcessName'),
                        ('Process ID', 'ProcessID')
                    ],
                    "Threat Information": [
                        ('Malicious IP', 'MaliciousIP'),
                        ('Malicious IP Country', 'MaliciousIPCountry'),
                        ('Malicious IP Latitude', 'MaliciousIPLatitude'),
                        ('Malicious IP Longitude', 'MaliciousIPLongitude'),
                        ('Threat Severity', 'ThreatSeverity'),
                        ('Threat Description', 'ThreatDescription'),
                        ('Threat Confidence', 'ThreatConfidence'),
                        ('Indicator Threat Type', 'IndicatorThreatType'),
                        ('Report Reference Link', 'ReportReferenceLink')
                    ],
                    "Custom Fields": [
                        ('Device Custom String 1', 'DeviceCustomString1'),
                        ('Device Custom String 1 Label', 'DeviceCustomString1Label'),
                        ('Device Custom String 2', 'DeviceCustomString2'),
                        ('Device Custom String 2 Label', 'DeviceCustomString2Label'),
                        ('Device Custom String 3', 'DeviceCustomString3'),
                        ('Device Custom String 3 Label', 'DeviceCustomString3Label'),
                        ('Device Custom String 4', 'DeviceCustomString4'),
                        ('Device Custom String 4 Label', 'DeviceCustomString4Label'),
                        ('Device Custom String 5', 'DeviceCustomString5'),
                        ('Device Custom String 5 Label', 'DeviceCustomString5Label'),
                        ('Device Custom String 6', 'DeviceCustomString6'),
                        ('Device Custom String 6 Label', 'DeviceCustomString6Label'),
                        ('Device Custom Number 1', 'DeviceCustomNumber1'),
                        ('Device Custom Number 1 Label', 'DeviceCustomNumber1Label'),
                        ('Device Custom Number 2', 'DeviceCustomNumber2'),
                        ('Device Custom Number 2 Label', 'DeviceCustomNumber2Label'),
                        ('Device Custom Number 3', 'DeviceCustomNumber3'),
                        ('Device Custom Number 3 Label', 'DeviceCustomNumber3Label'),
                        ('Device Custom Date 1 (UTC)', 'DeviceCustomDate1 [UTC]'),
                        ('Device Custom Date 1 (Local)', 'DeviceCustomDate1 [Local]'),
                        ('Device Custom Date 1 Label', 'DeviceCustomDate1Label'),
                        ('Device Custom Date 2 (UTC)', 'DeviceCustomDate2 [UTC]'),
                        ('Device Custom Date 2 (Local)', 'DeviceCustomDate2 [Local]'),
                        ('Device Custom Date 2 Label', 'DeviceCustomDate2Label'),
                        ('Device Custom IPv6 Address 1', 'DeviceCustomIPv6Address1'),
                        ('Device Custom IPv6 Address 1 Label', 'DeviceCustomIPv6Address1Label'),
                        ('Device Custom IPv6 Address 2', 'DeviceCustomIPv6Address2'),
                        ('Device Custom IPv6 Address 2 Label', 'DeviceCustomIPv6Address2Label'),
                        ('Device Custom IPv6 Address 3', 'DeviceCustomIPv6Address3'),
                        ('Device Custom IPv6 Address 3 Label', 'DeviceCustomIPv6Address3Label'),
                        ('Device Custom IPv6 Address 4', 'DeviceCustomIPv6Address4'),
                        ('Device Custom IPv6 Address 4 Label', 'DeviceCustomIPv6Address4Label'),
                        ('Device Custom Floating Point 1', 'DeviceCustomFloatingPoint1'),
                        ('Device Custom Floating Point 1 Label', 'DeviceCustomFloatingPoint1Label'),
                        ('Device Custom Floating Point 2', 'DeviceCustomFloatingPoint2'),
                        ('Device Custom Floating Point 2 Label', 'DeviceCustomFloatingPoint2Label'),
                        ('Device Custom Floating Point 3', 'DeviceCustomFloatingPoint3'),
                        ('Device Custom Floating Point 3 Label', 'DeviceCustomFloatingPoint3Label'),
                        ('Device Custom Floating Point 4', 'DeviceCustomFloatingPoint4'),
                        ('Device Custom Floating Point 4 Label', 'DeviceCustomFloatingPoint4Label'),
                        ('Flex String 1', 'FlexString1'),
                        ('Flex String 1 Label', 'FlexString1Label'),
                        ('Flex String 2', 'FlexString2'),
                        ('Flex String 2 Label', 'FlexString2Label'),
                        ('Flex Number 1', 'FlexNumber1'),
                        ('Flex Number 1 Label', 'FlexNumber1Label'),
                        ('Flex Number 2', 'FlexNumber2'),
                        ('Flex Number 2 Label', 'FlexNumber2Label'),
                        ('Flex Date 1 (UTC)', 'FlexDate1 [UTC]'),
                        ('Flex Date 1 (Local)', 'FlexDate1 [Local]'),
                        ('Flex Date 1 Label', 'FlexDate1Label')
                    ],
                    "System Information": [
                        ('Computer', 'Computer'),
                        ('Tenant ID', 'TenantId'),
                        ('Source System', 'SourceSystem'),
                        ('Type', 'Type'),
                        ('External ID', 'ExternalID'),
                        ('Ext ID', 'ExtID'),
                        ('Simplified Device Action', 'SimplifiedDeviceAction'),
                        ('Collector Host Name', 'CollectorHostName'),
                        ('UCLogGen_CF', 'UCLogGen_CF'),
                        ('Resource ID', '_ResourceId'),
                        ('OpCo', 'OpCo'),
                        ('Reason', 'Reason'),
                        ('Additional Extensions', 'AdditionalExtensions')
                    ]
                }
                
                # Display fields by category
                for category, fields in field_categories.items():
                    # Check if any fields in this category have values
                    has_values = False
                    for _, field_name in fields:
                        if log.get(field_name) and log.get(field_name) != 'N/A':
                            has_values = True
                            break
                    
                    if has_values:
                        print(f"\n{category}:")
                        print("-" * 50)
                        for display_name, field_name in fields:
                            value = log.get(field_name, 'N/A')
                            if value and value != 'N/A':
                                print(f"{display_name}: {value}")
                
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
    print("\n1. Testing all security logs from last 24 hours")
    logs = get_common_security_logs(
        hours=24,  # Last 24 hours
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