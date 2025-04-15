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

def get_threat_intelligence_indicators(days=90, limit=None, threat_type=None, confidence=None, status=None, source=None):
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

        # Build filters
        filters = []
        if threat_type:
            filters.append(f"ThreatType == \"{threat_type}\"")
        if confidence:
            filters.append(f"Confidence >= {confidence}")
        if status:
            filters.append(f"Active == {status.lower() == 'active'}")
        if source:
            filters.append(f"SourceSystem == \"{source}\"")
        
        # Join filters if any
        filter_string = ""
        if filters:
            filter_string = "| where " + " and ".join(filters)

        # Convert days to hours for the query
        hours = days * 24

        # Base query
        query = f"""
        ThreatIntelligenceIndicator
        | where TimeGenerated > ago({days}d)
        {filter_string}
        | order by TimeGenerated desc
        {f"| take {limit}" if limit else ""}
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
            indicators = []
            
            if not results.get('tables') or not results['tables'][0].get('rows'):
                print("No threat intelligence indicators found.")
                return []
            
            for table in results['tables']:
                column_names = [col['name'] for col in table['columns']]
                rows = table['rows']
                
                for row in rows:
                    indicator_entry = dict(zip(column_names, row))
                    # Format datetime fields
                    datetime_fields = [
                        'TimeGenerated',
                        'ExpirationDateTime'
                    ]
                    
                    for field in datetime_fields:
                        if field in indicator_entry and indicator_entry[field]:
                            try:
                                # Parse UTC time and convert to local
                                utc_time = datetime.fromisoformat(indicator_entry[field].replace('Z', '+00:00'))
                                local_time = utc_time.astimezone()
                                indicator_entry[field + ' [UTC]'] = utc_time.strftime('%Y-%m-%d %H:%M:%S')
                                indicator_entry[field + ' [Local]'] = local_time.strftime('%Y-%m-%d %H:%M:%S')
                            except (ValueError, AttributeError) as e:
                                print(f"Error converting time for {field}: {e}")
                                indicator_entry[field + ' [UTC]'] = indicator_entry[field]
                                indicator_entry[field + ' [Local]'] = indicator_entry[field]
                    
                    # Parse any JSON fields
                    json_fields = ['Tags']
                    for field in json_fields:
                        if field in indicator_entry and indicator_entry[field]:
                            try:
                                indicator_entry[field] = json.loads(indicator_entry[field])
                            except json.JSONDecodeError:
                                pass
                    
                    indicators.append(indicator_entry)
            
            print(f"Found {len(indicators)} threat intelligence indicators")
            return indicators
        else:
            print(f"Error: {response.status_code}")
            print(f"Error details: {response.text}")
            return None

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return None

def display_indicators(indicators):
    if not indicators:
        print("No threat intelligence indicators found.")
        return

    # Prepare data for tabulate
    table_data = []
    for i, indicator in enumerate(indicators, 1):
        # Determine the identifier based on what's available
        identifier = (
            indicator.get('DomainName') or 
            indicator.get('NetworkIP') or 
            indicator.get('Url') or 
            indicator.get('FileHashValue') or 
            indicator.get('IndicatorId', 'N/A')
        )
        
        row = [
            i,
            indicator.get('ThreatType', 'N/A'),
            identifier[:50] + ('...' if len(identifier) > 50 else ''),  # Truncate long identifiers
            indicator.get('ConfidenceScore', 'N/A'),
            'Active' if indicator.get('Active') else 'Inactive',
            indicator.get('ThreatSeverity', 'N/A'),
            indicator.get('SourceSystem', 'N/A'),
            indicator.get('TimeGenerated [Local]', 'N/A')
        ]
        table_data.append(row)

    # Display the table
    headers = ['#', 'Threat Type', 'Identifier', 'Confidence', 'Status', 'Severity', 'Source', 'Last Updated']
    print(tabulate(table_data, headers=headers, tablefmt='grid'))
    print(f"\nTotal indicators found: {len(indicators)}")

    # Ask if user wants to see details of a specific indicator
    while True:
        try:
            choice = input("\nEnter indicator number to see details (or 'q' to quit): ")
            if choice.lower() == 'q':
                break
            
            indicator_num = int(choice) - 1
            if 0 <= indicator_num < len(indicators):
                indicator = indicators[indicator_num]
                print("\nIndicator Details:")
                print("=" * 100)
                
                # Display basic indicator information
                print(f"Indicator ID: {indicator.get('IndicatorId', 'N/A')}")
                print(f"Threat Type: {indicator.get('ThreatType', 'N/A')}")
                print(f"Time Generated: {indicator.get('TimeGenerated [Local]', 'N/A')}")
                print(f"Expiration Date: {indicator.get('ExpirationDateTime [Local]', 'N/A')}")
                print(f"Confidence Score: {indicator.get('ConfidenceScore', 'N/A')}")
                print(f"Threat Severity: {indicator.get('ThreatSeverity', 'N/A')}")
                print(f"Status: {'Active' if indicator.get('Active') else 'Inactive'}")
                print(f"Source System: {indicator.get('SourceSystem', 'N/A')}")
                print(f"Traffic Light Protocol Level: {indicator.get('TrafficLightProtocolLevel', 'N/A')}")
                
                # Display indicator-specific fields
                print("\nIndicator Details:")
                print("-" * 50)
                
                # Domain or IP related
                if indicator.get('DomainName'):
                    print(f"Domain Name: {indicator.get('DomainName')}")
                if indicator.get('NetworkIP'):
                    print(f"Network IP: {indicator.get('NetworkIP')}")
                if indicator.get('NetworkSourceIP'):
                    print(f"Network Source IP: {indicator.get('NetworkSourceIP')}")
                if indicator.get('NetworkDestinationIP'):
                    print(f"Network Destination IP: {indicator.get('NetworkDestinationIP')}")
                    
                # Email related
                if indicator.get('EmailSourceDomain'):
                    print(f"Email Source Domain: {indicator.get('EmailSourceDomain')}")
                if indicator.get('EmailSourceIpAddress'):
                    print(f"Email Source IP: {indicator.get('EmailSourceIpAddress')}")
                if indicator.get('EmailRecipient'):
                    print(f"Email Recipient: {indicator.get('EmailRecipient')}")
                    
                # File related
                if indicator.get('FileHashType'):
                    print(f"File Hash Type: {indicator.get('FileHashType')}")
                if indicator.get('FileHashValue'):
                    print(f"File Hash Value: {indicator.get('FileHashValue')}")
                if indicator.get('FileSize'):
                    print(f"File Size: {indicator.get('FileSize')}")
                if indicator.get('FileName'):
                    print(f"File Name: {indicator.get('FileName')}")
                if indicator.get('FilePath'):
                    print(f"File Path: {indicator.get('FilePath')}")
                    
                # URL related
                if indicator.get('Url'):
                    print(f"URL: {indicator.get('Url')}")
                
                # Display description if available
                if indicator.get('Description'):
                    print("\nDescription:")
                    print("-" * 50)
                    print(indicator.get('Description', 'N/A'))
                
                # Display tags if available
                tags = indicator.get('Tags')
                if tags:
                    print("\nTags:")
                    print("-" * 50)
                    if isinstance(tags, list):
                        for tag in tags:
                            print(f"- {tag}")
                    else:
                        print(tags)
                
                # Display action if available
                if indicator.get('Action'):
                    print("\nAction:")
                    print("-" * 50)
                    print(indicator.get('Action'))
                
                print("=" * 100)
            else:
                print("Invalid indicator number. Please try again.")
        except ValueError:
            print("Please enter a valid number or 'q' to quit.")

def export_to_excel(indicators):
    if not indicators:
        print("No indicators to export.")
        return
        
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'threat_intelligence_indicators_{timestamp}.xlsx'
    
    # Create a copy of indicators to modify for Excel export
    indicators_for_export = []
    for indicator in indicators:
        indicator_copy = indicator.copy()
        
        # Convert complex fields to strings for Excel
        for field in ['Tags']:
            if field in indicator_copy and isinstance(indicator_copy[field], (dict, list)):
                indicator_copy[field] = json.dumps(indicator_copy[field])
        
        indicators_for_export.append(indicator_copy)
    
    df = pd.DataFrame(indicators_for_export)
    df.to_excel(filename, index=False)
    print(f"\nExported indicators to {filename}")

if __name__ == "__main__":
    print("Threat Intelligence Indicator Extraction Tool")
    print("=" * 50)
    
    # Test basic extraction
    print("\n1. Testing all threat intelligence indicators from last 90 days")
    indicators = get_threat_intelligence_indicators(
        days=90,  # Last 90 days
        limit=None  # No limit - retrieve all indicators
    )
    if indicators:
        display_indicators(indicators)
        export_to_excel(indicators)
    
    # Additional filtering examples (commented out by default)
    """
    # Example: Get only high confidence indicators
    print("\n2. Testing high confidence indicators (>=80)")
    high_confidence_indicators = get_threat_intelligence_indicators(
        days=90,
        limit=None,
        confidence=80
    )
    if high_confidence_indicators:
        display_indicators(high_confidence_indicators)
    
    # Example: Get only active malware indicators
    print("\n3. Testing active malware indicators")
    malware_indicators = get_threat_intelligence_indicators(
        days=90,
        limit=None,
        threat_type="Malware",
        status="active"
    )
    if malware_indicators:
        display_indicators(malware_indicators)
    """ 