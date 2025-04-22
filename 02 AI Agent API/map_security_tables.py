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

def get_security_alerts(alert_ids=None):
    """
    Retrieve security alerts from Microsoft Sentinel
    
    Args:
        alert_ids (list): Optional list of alert IDs to filter by
    
    Returns:
        DataFrame: DataFrame containing security alerts or None if error
    """
    try:
        print("Authenticating with Azure AD for SecurityAlert retrieval...")
        
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
        query = """
        SecurityAlert
        """
        
        # Add filter for specific alert IDs if provided
        if alert_ids and len(alert_ids) > 0:
            # Create a string of IDs for the query
            ids_str = ", ".join([f"'{id}'" for id in alert_ids])
            query += f"| where SystemAlertId in ({ids_str})"
        
        # Add sorting
        query += "| order by TimeGenerated desc"

        print(f"\nExecuting SecurityAlert query:\n{query}\n")

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
            
            print(f"\nFound {len(alerts)} security alerts")
            
            # Convert to DataFrame
            if alerts:
                return pd.DataFrame(alerts)
            else:
                return pd.DataFrame()
        else:
            print(f"Error: {response.status_code}")
            print(f"Error details: {response.text}")
            return None

    except Exception as e:
        print(f"An error occurred retrieving alerts: {str(e)}")
        traceback.print_exc()
        return None

def get_security_incidents():
    """
    Retrieve security incidents from Microsoft Sentinel
    
    Returns:
        DataFrame: DataFrame containing security incidents or None if error
    """
    try:
        print("Authenticating with Azure AD for SecurityIncident retrieval...")
        
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
        query = """
        SecurityIncident
        | order by TimeGenerated desc
        """

        print(f"\nExecuting SecurityIncident query:\n{query}\n")

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
            
            print(f"\nFound {len(incidents)} security incidents")
            
            # Convert to DataFrame
            if incidents:
                return pd.DataFrame(incidents)
            else:
                return pd.DataFrame()
        else:
            print(f"Error: {response.status_code}")
            print(f"Error details: {response.text}")
            return None

    except Exception as e:
        print(f"An error occurred retrieving incidents: {str(e)}")
        traceback.print_exc()
        return None

def extract_alert_ids(incident_data):
    """
    Extract AlertIds from incident data and clean them
    
    Args:
        incident_data (pd.DataFrame): DataFrame containing incident data
    
    Returns:
        dict: Dictionary mapping incident numbers to lists of alert IDs
    """
    incident_alert_map = {}
    
    if 'AlertIds' not in incident_data.columns:
        print("No AlertIds column found in incident data")
        return incident_alert_map
    
    for _, row in incident_data.iterrows():
        incident_number = row.get('IncidentNumber')
        alert_id_str = row.get('AlertIds')
        
        if pd.isna(incident_number) or pd.isna(alert_id_str):
            continue
        
        alert_ids = []
        
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
                
            # Add to the mapping if we found alert IDs
            if alert_ids:
                incident_alert_map[incident_number] = list(set(alert_ids))
        except Exception as e:
            print(f"Error parsing AlertId for incident {incident_number}: {str(e)}")
    
    return incident_alert_map

def create_joined_dataframe(incidents_df, alerts_df, incident_alert_map):
    """
    Create a joined dataframe based on the incident-alert mapping
    
    Args:
        incidents_df (pd.DataFrame): DataFrame containing incidents
        alerts_df (pd.DataFrame): DataFrame containing alerts
        incident_alert_map (dict): Mapping of incident numbers to alert IDs
    
    Returns:
        pd.DataFrame: Joined dataframe
    """
    joined_rows = []
    
    # Track stats for join success
    matched_incidents = set()
    matched_alerts = set()
    total_mappings = 0
    
    # Safety check for empty dataframes
    if incidents_df.empty or alerts_df.empty:
        print("Warning: One or both dataframes are empty. Cannot create joined dataframe.")
        return pd.DataFrame(), {"success": False, "reason": "Empty dataframes"}
    
    # Ensure SystemAlertId is a string in alerts_df
    if 'SystemAlertId' in alerts_df.columns:
        alerts_df['SystemAlertId'] = alerts_df['SystemAlertId'].astype(str)
    else:
        print("Warning: SystemAlertId column not found in alerts dataframe")
        return pd.DataFrame(), {"success": False, "reason": "Missing SystemAlertId column"}
    
    # Check if we have an incident alert mapping
    if not incident_alert_map:
        print("Warning: No incident-alert mappings found")
        return pd.DataFrame(), {"success": False, "reason": "No mappings found"}
    
    # Create joined rows using the mapping
    for incident_number, alert_ids in incident_alert_map.items():
        # Get the incident data
        incident_rows = incidents_df[incidents_df['IncidentNumber'] == incident_number]
        
        if incident_rows.empty:
            continue
        
        # Use the latest incident record
        incident = incident_rows.iloc[0]
        
        for alert_id in alert_ids:
            # Find matching alert
            alert_rows = alerts_df[alerts_df['SystemAlertId'] == alert_id]
            
            if alert_rows.empty:
                continue
            
            # Use the latest alert record
            alert = alert_rows.iloc[0]
            
            # Create a combined row
            combined_row = {}
            
            # Add incident columns with "Incident_" prefix
            for col in incident.index:
                combined_row[f"Incident_{col}"] = incident[col]
            
            # Add alert columns with "Alert_" prefix
            for col in alert.index:
                combined_row[f"Alert_{col}"] = alert[col]
            
            joined_rows.append(combined_row)
            
            # Track stats
            matched_incidents.add(incident_number)
            matched_alerts.add(alert_id)
            total_mappings += 1
    
    # Create the combined dataframe
    if joined_rows:
        joined_df = pd.DataFrame(joined_rows)
        
        # Create stats about the join success
        join_stats = {
            "success": len(joined_rows) > 0,
            "total_incidents": len(incidents_df['IncidentNumber'].unique()),
            "total_alerts": len(alerts_df['SystemAlertId'].unique()),
            "matched_incidents": len(matched_incidents),
            "matched_alerts": len(matched_alerts),
            "total_mappings": total_mappings,
            "incident_match_rate": f"{len(matched_incidents) / len(incidents_df['IncidentNumber'].unique()):.2%}",
            "alert_match_rate": f"{len(matched_alerts) / len(alerts_df['SystemAlertId'].unique()):.2%}"
        }
        
        return joined_df, join_stats
    else:
        return pd.DataFrame(), {"success": False, "reason": "No matching rows found"}

def display_join_results(joined_df, join_stats):
    """
    Display information about the join results
    
    Args:
        joined_df (pd.DataFrame): Joined dataframe
        join_stats (dict): Statistics about the join
    """
    print("\n=== Join Results ===\n")
    
    if not join_stats.get("success", False):
        print(f"Join was unsuccessful. Reason: {join_stats.get('reason', 'Unknown')}")
        return
    
    print(f"Join was successful with {len(joined_df)} total rows")
    print(f"Total incidents: {join_stats['total_incidents']}")
    print(f"Total alerts: {join_stats['total_alerts']}")
    print(f"Incidents with matching alerts: {join_stats['matched_incidents']} ({join_stats['incident_match_rate']})")
    print(f"Alerts matched to incidents: {join_stats['matched_alerts']} ({join_stats['alert_match_rate']})")
    print(f"Total relationship mappings: {join_stats['total_mappings']}")
    
    # Display sample of the joined data
    if not joined_df.empty:
        print("\n=== Sample of Joined Data ===\n")
        
        # Select key columns for display
        display_columns = [
            'Incident_IncidentNumber', 'Incident_Title', 'Incident_Severity', 'Incident_Status',
            'Alert_SystemAlertId', 'Alert_AlertName', 'Alert_AlertSeverity', 'Alert_Status'
        ]
        
        # Only include columns that exist in the dataframe
        available_columns = [col for col in display_columns if col in joined_df.columns]
        
        # If we don't have the key columns, show the first few columns
        if not available_columns:
            available_columns = joined_df.columns[:8]
        
        # Display the sample
        sample_df = joined_df[available_columns].head(10)
        
        # Convert to list of lists for tabulate
        headers = sample_df.columns.tolist()
        rows = sample_df.values.tolist()
        
        print(tabulate(rows, headers=headers, tablefmt='grid'))
        
        if len(joined_df) > 10:
            print(f"\n... and {len(joined_df) - 10} more rows")

def export_joined_data(joined_df, prefix="joined_security_data"):
    """
    Export the joined data to Excel
    
    Args:
        joined_df (pd.DataFrame): Joined dataframe
        prefix (str): Prefix for the output filename
    """
    if joined_df.empty:
        print("No data to export")
        return
    
    # Create timestamp for filename
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = f"{prefix}_{timestamp}.xlsx"
    
    # Export to Excel
    joined_df.to_excel(output_file, index=False)
    print(f"\nExported joined data to {output_file}")

def main():
    """
    Main function to retrieve and join security incidents and alerts
    """
    try:
        # Get security incidents
        incidents_df = get_security_incidents()
        if incidents_df is None or incidents_df.empty:
            print("No security incidents found. Exiting.")
            return
        
        # Extract alert IDs from incidents
        incident_alert_map = extract_alert_ids(incidents_df)
        
        if not incident_alert_map:
            print("No alert IDs found in incidents. Exiting.")
            return
        
        # Get all unique alert IDs
        all_alert_ids = [alert_id for alert_ids in incident_alert_map.values() for alert_id in alert_ids]
        unique_alert_ids = list(set(all_alert_ids))
        
        print(f"\nFound {len(unique_alert_ids)} unique alert IDs referenced in incidents")
        
        # Get security alerts for these IDs
        alerts_df = get_security_alerts(unique_alert_ids)
        if alerts_df is None or alerts_df.empty:
            print("No security alerts found. Exiting.")
            return
        
        # Create joined dataframe
        joined_df, join_stats = create_joined_dataframe(incidents_df, alerts_df, incident_alert_map)
        
        # Display join results
        display_join_results(joined_df, join_stats)
        
        # Export joined data if successful
        if join_stats.get("success", False):
            export_joined_data(joined_df)
    
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        traceback.print_exc()

if __name__ == "__main__":
    main() 