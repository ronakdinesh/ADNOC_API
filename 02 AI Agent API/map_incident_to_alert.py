import requests
import json
from datetime import datetime
from dotenv import load_dotenv
import os
import adal
import pandas as pd
from tabulate import tabulate
import traceback

# Load environment variables from .env file
load_dotenv()

# Azure AD and Log Analytics configuration
TENANT_ID = os.getenv('TENANT_ID')
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
WORKSPACE_ID = os.getenv('WORKSPACE_ID')

def get_security_incident(incident_number):
    """
    Retrieve a specific security incident from Microsoft Sentinel
    
    Args:
        incident_number: The incident number to retrieve
    
    Returns:
        dict: The incident data or None if not found
    """
    try:
        print(f"Retrieving security incident #{incident_number}...")
        
        # Authentication
        authority_url = f"https://login.microsoftonline.com/{TENANT_ID}"
        resource = "https://api.loganalytics.io"

        context = adal.AuthenticationContext(authority_url)
        token = context.acquire_token_with_client_credentials(
            resource,
            CLIENT_ID,
            CLIENT_SECRET
        )

        access_token = token['accessToken']
        print("Authentication successful!")

        # Build KQL query
        query = f"""
        SecurityIncident
        | where IncidentNumber == "{incident_number}"
        """

        print(f"\nExecuting query:\n{query}\n")

        # API endpoint
        url = f"https://api.loganalytics.io/v1/workspaces/{WORKSPACE_ID}/query"

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
                    incidents.append(incident_entry)
            
            if incidents:
                print(f"Found incident #{incident_number}")
                return incidents[0]  # Return the first (should be only) incident
            else:
                print(f"Incident #{incident_number} not found")
                return None
        else:
            print(f"Error: {response.status_code}")
            print(f"Error details: {response.text}")
            return None

    except Exception as e:
        print(f"An error occurred retrieving incident: {str(e)}")
        traceback.print_exc()
        return None

def extract_alert_ids(incident):
    """
    Extract alert IDs from an incident
    
    Args:
        incident (dict): The incident data
    
    Returns:
        list: List of alert IDs
    """
    if not incident or 'AlertIds' not in incident:
        print("No AlertIds found in incident")
        return []
    
    alert_ids = []
    alert_id_str = incident['AlertIds']
    
    try:
        # Handle different formats of AlertIds
        if isinstance(alert_id_str, str):
            # Remove brackets, quotes, and spaces if in JSON array format ["id1", "id2"]
            if alert_id_str.startswith('[') and alert_id_str.endswith(']'):
                # Try to parse as JSON array
                try:
                    parsed_ids = json.loads(alert_id_str)
                    if isinstance(parsed_ids, list):
                        alert_ids.extend(parsed_ids)
                except:
                    # Fallback to string manipulation if JSON parsing fails
                    ids = alert_id_str.strip('[]').split(',')
                    for id in ids:
                        clean_id = id.strip().strip('"\'')
                        if clean_id:
                            alert_ids.append(clean_id)
            else:
                # Single ID not in array format
                clean_id = alert_id_str.strip().strip('"\'')
                if clean_id:
                    alert_ids.append(clean_id)
        elif isinstance(alert_id_str, list):
            # Already a list, add all non-empty elements
            alert_ids.extend([id for id in alert_id_str if id])
            
    except Exception as e:
        print(f"Error parsing AlertIds: {str(e)}")
    
    # Remove duplicates
    unique_ids = list(set(alert_ids))
    if unique_ids:
        print(f"Extracted {len(unique_ids)} alert ID(s): {', '.join(unique_ids)}")
    else:
        print("No alert IDs could be extracted")
        
    return unique_ids

def get_security_alerts_by_ids(alert_ids):
    """
    Retrieve security alerts by their IDs
    
    Args:
        alert_ids (list): List of alert IDs to retrieve
    
    Returns:
        list: List of alert dictionaries
    """
    if not alert_ids:
        print("No alert IDs provided")
        return []
    
    try:
        print("Retrieving security alerts...")
        
        # Authentication
        authority_url = f"https://login.microsoftonline.com/{TENANT_ID}"
        resource = "https://api.loganalytics.io"

        context = adal.AuthenticationContext(authority_url)
        token = context.acquire_token_with_client_credentials(
            resource,
            CLIENT_ID,
            CLIENT_SECRET
        )

        access_token = token['accessToken']
        print("Authentication successful!")

        # Build KQL query
        ids_str = ", ".join([f"'{id}'" for id in alert_ids])
        query = f"""
        SecurityAlert
        | where SystemAlertId in ({ids_str})
        | order by TimeGenerated desc
        """

        print(f"\nExecuting query:\n{query}\n")

        # API endpoint
        url = f"https://api.loganalytics.io/v1/workspaces/{WORKSPACE_ID}/query"

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
                    alerts.append(alert_entry)
            
            print(f"Found {len(alerts)} matching alert(s)")
            return alerts
        else:
            print(f"Error: {response.status_code}")
            print(f"Error details: {response.text}")
            return []

    except Exception as e:
        print(f"An error occurred retrieving alerts: {str(e)}")
        traceback.print_exc()
        return []

def display_incident_with_alerts(incident, alerts):
    """
    Display a security incident with its corresponding alerts
    
    Args:
        incident (dict): The incident data
        alerts (list): List of alert dictionaries
    """
    print("\n" + "=" * 80)
    print(f"SECURITY INCIDENT #{incident.get('IncidentNumber', 'Unknown')}")
    print("=" * 80)
    
    # Display incident details
    print("\nINCIDENT DETAILS:")
    print("-" * 80)
    
    # Format incident details
    incident_details = [
        ("Incident Number", incident.get('IncidentNumber', 'Unknown')),
        ("Title", incident.get('Title', 'Unknown')),
        ("Severity", incident.get('Severity', 'Unknown')),
        ("Status", incident.get('Status', 'Unknown')),
        ("Created", incident.get('CreatedTimeUTC', 'Unknown')),
        ("Last Modified", incident.get('LastModifiedTimeUTC', 'Unknown')),
        ("Owner", incident.get('Owner', 'Unknown')),
        ("Classification", incident.get('Classification', 'Unknown')),
        ("Classification Reason", incident.get('ClassificationReason', 'Unknown')),
    ]
    
    # Display incident details as a table
    print(tabulate(incident_details, tablefmt="simple"))
    
    # Display associated alerts
    print("\nASSOCIATED ALERTS:")
    print("-" * 80)
    
    if not alerts:
        print("No matching alerts found for this incident.")
    else:
        for i, alert in enumerate(alerts, 1):
            print(f"\nAlert #{i}:")
            
            # Format alert details
            alert_details = [
                ("SystemAlertId", alert.get('SystemAlertId', 'Unknown')),
                ("Alert Name", alert.get('AlertName', alert.get('DisplayName', 'Unknown'))),
                ("Severity", alert.get('AlertSeverity', 'Unknown')),
                ("Status", alert.get('Status', 'Unknown')),
                ("Time Generated", alert.get('TimeGenerated', 'Unknown')),
                ("Provider", alert.get('ProviderName', 'Unknown')),
            ]
            
            # Display alert details as a table
            print(tabulate(alert_details, tablefmt="simple"))
            
            # Display description if available
            description = alert.get('Description', '')
            if description:
                print("\nDescription:")
                print(description[:500] + ('...' if len(description) > 500 else ''))
                
            # Display entities if available and not too large
            entities = alert.get('Entities', '')
            if entities and len(str(entities)) < 1000:
                print("\nEntities:")
                print(entities)
            
            # Techniques and tactics
            tactics = alert.get('Tactics', '')
            if tactics:
                print("\nTactics:", tactics)
                
            techniques = alert.get('Techniques', '')
            if techniques:
                print("Techniques:", techniques)
                
            # Add separator between alerts
            if i < len(alerts):
                print("\n" + "-" * 40)
    
    print("\n" + "=" * 80)
    print("RELATIONSHIP SUMMARY:")
    print("-" * 80)
    print(f"Incident #{incident.get('IncidentNumber', 'Unknown')} is associated with {len(alerts)} alert(s).")
    
    # Show the ID mapping clearly
    alert_ids_from_incident = extract_alert_ids(incident)
    matched_alert_ids = [alert.get('SystemAlertId', 'Unknown') for alert in alerts]
    
    print("\nID MAPPING:")
    print(f"Incident.AlertIds: {incident.get('AlertIds', 'None')}")
    print(f"Extracted IDs: {', '.join(alert_ids_from_incident)}")
    print(f"Matched Alert SystemAlertIds: {', '.join(matched_alert_ids)}")
    
    # Calculate match rate
    if alert_ids_from_incident:
        match_rate = len(matched_alert_ids) / len(alert_ids_from_incident) * 100
        print(f"\nMatch rate: {match_rate:.1f}% ({len(matched_alert_ids)}/{len(alert_ids_from_incident)} IDs matched)")
    
    print("=" * 80)

def main():
    """
    Main function to retrieve and display a specific incident with its alerts
    """
    try:
        # Get incident number from user
        incident_number = input("Enter the incident number to investigate: ")
        
        # Get the incident
        incident = get_security_incident(incident_number)
        if not incident:
            print("Incident not found. Exiting.")
            return
        
        # Extract alert IDs
        alert_ids = extract_alert_ids(incident)
        if not alert_ids:
            print("No alert IDs found in incident. Exiting.")
            return
        
        # Get alerts
        alerts = get_security_alerts_by_ids(alert_ids)
        
        # Display incident with alerts
        display_incident_with_alerts(incident, alerts)
        
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        traceback.print_exc()

if __name__ == "__main__":
    main() 