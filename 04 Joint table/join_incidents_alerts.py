import pandas as pd
import json
import os
from datetime import datetime
import sys

# Get the base directory
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Import functions from existing scripts
from importlib.machinery import SourceFileLoader

# Load the incident and alert modules using absolute paths
incidents_module = SourceFileLoader(
    "incidents_module", 
    os.path.join(base_dir, "01 Test Connections", "01_test_security_incidents.py")
).load_module()

alerts_module = SourceFileLoader(
    "alerts_module", 
    os.path.join(base_dir, "01 Test Connections", "02_test_security_alerts.py")
).load_module()

def load_data(days=90):
    """
    Fetch data from API
    """
    print(f"Fetching incidents data from API (last {days} days)...")
    incidents_data = incidents_module.get_security_incidents(days=days, 
                                                  title="[Custom]-[TI]-DNS with TI Domain Correlation")
    incidents_df = pd.DataFrame(incidents_data) if incidents_data else pd.DataFrame()
    
    print(f"Fetching alerts data from API (last {days} days)...")
    alerts_data = alerts_module.get_security_alerts(days=days)
    alerts_df = pd.DataFrame(alerts_data) if alerts_data else pd.DataFrame()
    
    return incidents_df, alerts_df

def parse_json_fields(df, json_columns):
    """
    Parse JSON strings in the specified columns to Python objects
    """
    for col in json_columns:
        if col in df.columns:
            # Create a safe parsing function that handles empty strings and None values
            def safe_json_parse(x):
                if not x or not isinstance(x, str):
                    return None
                try:
                    return json.loads(x)
                except json.JSONDecodeError:
                    # Return original value if it can't be parsed
                    return x
            
            # Apply the safe parsing function
            df[f"{col}_parsed"] = df[col].apply(safe_json_parse)
    return df

def create_incident_alert_mapping(incidents_df, alerts_df):
    """
    Create a mapping between incidents and their related alerts
    """
    # Show columns available in each dataframe
    print("\nIncident DataFrame Columns:")
    print(", ".join(incidents_df.columns))
    print("\nAlert DataFrame Columns:")
    print(", ".join(alerts_df.columns))
    
    # SUPER DETAILED DEBUGGING
    print("\n==== SUPER DETAILED DEBUGGING ====")
    
    # Check if both key columns exist
    alert_id_col_exists = 'AlertIds' in incidents_df.columns
    system_alert_id_col_exists = 'SystemAlertId' in alerts_df.columns
    
    print(f"AlertIds column exists in incidents: {alert_id_col_exists}")
    print(f"SystemAlertId column exists in alerts: {system_alert_id_col_exists}")
    
    if not alert_id_col_exists or not system_alert_id_col_exists:
        print("ERROR: One or both required columns are missing!")
        
        # Try to find similar columns
        incident_cols = [col for col in incidents_df.columns if 'alert' in col.lower()]
        alert_cols = [col for col in alerts_df.columns if 'alert' in col.lower() and 'id' in col.lower()]
        
        print(f"Possible incident alert columns: {incident_cols}")
        print(f"Possible alert ID columns: {alert_cols}")
        
        # If we find potential alternatives, use them
        if not alert_id_col_exists and incident_cols:
            print(f"Using {incident_cols[0]} as alternative to AlertIds")
            alert_id_col = incident_cols[0]
        else:
            alert_id_col = 'AlertIds'
            
        if not system_alert_id_col_exists and alert_cols:
            print(f"Using {alert_cols[0]} as alternative to SystemAlertId")
            system_alert_id_col = alert_cols[0]
        else:
            system_alert_id_col = 'SystemAlertId'
    else:
        alert_id_col = 'AlertIds'
        system_alert_id_col = 'SystemAlertId'
    
    # Create a set of all alert IDs to make lookups faster
    all_alert_ids = set()
    for _, alert in alerts_df.iterrows():
        if system_alert_id_col in alert and alert[system_alert_id_col]:
            all_alert_ids.add(str(alert[system_alert_id_col]).lower())
    
    print(f"\nTotal unique alert IDs: {len(all_alert_ids)}")
    print("\nSample alert IDs (first 10, lowercase):")
    sample_alert_ids = list(all_alert_ids)[:10]
    for i, alert_id in enumerate(sample_alert_ids):
        print(f"  {i+1}. '{alert_id}'")
    
    # Print length ranges of alert IDs to help identify format issues
    alert_id_lengths = [len(aid) for aid in all_alert_ids]
    if alert_id_lengths:
        min_len = min(alert_id_lengths)
        max_len = max(alert_id_lengths)
        print(f"\nAlert ID length range: {min_len} to {max_len} characters")
    
    # Sample raw alert IDs from incidents
    print("\nSample incident alert IDs (first 10, raw):")
    incident_alert_ids_samples = []
    for idx, incident in incidents_df.iterrows():
        if alert_id_col in incident and incident[alert_id_col] and len(incident_alert_ids_samples) < 10:
            raw_value = incident[alert_id_col]
            incident_alert_ids_samples.append(raw_value)
            print(f"  {len(incident_alert_ids_samples)}. '{raw_value}' (type: {type(raw_value)})")
    
    # Try various cleaning approaches and check for matches
    print("\nTesting different cleaning approaches...")
    
    # Create a mapping from alert IDs to alerts
    alert_id_to_alert = {}
    for _, alert in alerts_df.iterrows():
        if system_alert_id_col in alert:
            # Store with lowercase key for case-insensitive matching
            alert_id_to_alert[str(alert[system_alert_id_col]).lower()] = alert
    
    # Approach 1: Simple bracket and quote removal
    approach1_matches = 0
    for raw_id in incident_alert_ids_samples:
        if isinstance(raw_id, str):
            clean_id = raw_id.replace('[', '').replace(']', '').replace('"', '').replace("'", "").strip()
            if clean_id.lower() in all_alert_ids:
                approach1_matches += 1
    print(f"Approach 1 (Simple bracket/quote removal): {approach1_matches} matches out of {len(incident_alert_ids_samples)}")
    
    # Approach 2: JSON parsing then cleaning
    approach2_matches = 0
    for raw_id in incident_alert_ids_samples:
        try:
            if isinstance(raw_id, str):
                parsed = json.loads(raw_id)
                if isinstance(parsed, list) and parsed:
                    for id_item in parsed:
                        if isinstance(id_item, str) and id_item.lower() in all_alert_ids:
                            approach2_matches += 1
        except:
            pass
    print(f"Approach 2 (JSON parse + cleaning): {approach2_matches} matches out of {len(incident_alert_ids_samples)}")
    
    # Approach 3: Deep extraction with GUID pattern matching
    import re
    guid_pattern = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE)
    approach3_matches = 0
    
    for raw_id in incident_alert_ids_samples:
        if isinstance(raw_id, str):
            # Find all GUIDs in the string
            guids = guid_pattern.findall(raw_id)
            for guid in guids:
                if guid.lower() in all_alert_ids:
                    approach3_matches += 1
    print(f"Approach 3 (GUID pattern extraction): {approach3_matches} matches out of {len(incident_alert_ids_samples)}")
    
    # Find the best approach
    best_approach = max(
        [(1, approach1_matches), (2, approach2_matches), (3, approach3_matches)],
        key=lambda x: x[1]
    )[0]
    
    print(f"\nBest cleaning approach: Approach {best_approach}")
    
    # Now analyze a larger sample of incidents to verify
    print("\nAnalyzing a larger sample of 100 incidents with the best approach...")
    
    sample_size = min(100, len(incidents_df))
    sample_matches = 0
    
    for idx, incident in incidents_df.head(sample_size).iterrows():
        if alert_id_col in incident and incident[alert_id_col]:
            raw_id = incident[alert_id_col]
            
            found_match = False
            if best_approach == 1:
                # Simple bracket and quote removal
                if isinstance(raw_id, str):
                    clean_id = raw_id.replace('[', '').replace(']', '').replace('"', '').replace("'", "").strip()
                    if clean_id.lower() in all_alert_ids:
                        found_match = True
            elif best_approach == 2:
                # JSON parsing then cleaning
                try:
                    if isinstance(raw_id, str):
                        parsed = json.loads(raw_id)
                        if isinstance(parsed, list) and parsed:
                            for id_item in parsed:
                                if isinstance(id_item, str) and id_item.lower() in all_alert_ids:
                                    found_match = True
                except:
                    pass
            elif best_approach == 3:
                # Deep extraction with GUID pattern matching
                if isinstance(raw_id, str):
                    guids = guid_pattern.findall(raw_id)
                    for guid in guids:
                        if guid.lower() in all_alert_ids:
                            found_match = True
            
            if found_match:
                sample_matches += 1
    
    print(f"Found {sample_matches} matches out of {sample_size} incidents using Approach {best_approach}")
    
    if sample_matches == 0:
        # Direct value comparison to find exactly what's different
        print("\n==== DIRECT VALUE COMPARISON ====")
        print("Showing exact alert IDs from both sources to diagnose the issue:")
        
        print("\nSample alert IDs from alerts (exact values, first 5):")
        for idx, (alert_id, _) in enumerate(list(alert_id_to_alert.items())[:5]):
            print(f"  {idx+1}. '{alert_id}'")
            # Print character by character
            print(f"    Character codes: {[ord(c) for c in alert_id]}")
        
        # Now try to extract and clean GUIDs from incidents
        print("\nSample alert IDs extracted from incidents (after cleaning, first 5):")
        extracted_count = 0
        for idx, incident in incidents_df.iterrows():
            if extracted_count >= 5:
                break
                
            if alert_id_col in incident and incident[alert_id_col]:
                raw_id = incident[alert_id_col]
                if isinstance(raw_id, str):
                    # Try all approaches
                    # 1. Simple cleaning
                    clean_id = raw_id.replace('[', '').replace(']', '').replace('"', '').replace("'", "").strip()
                    
                    # 2. JSON parsing
                    json_extracted = None
                    try:
                        parsed = json.loads(raw_id)
                        if isinstance(parsed, list) and parsed and isinstance(parsed[0], str):
                            json_extracted = parsed[0]
                    except:
                        pass
                    
                    # 3. GUID extraction
                    guids = guid_pattern.findall(raw_id)
                    guid_extracted = guids[0] if guids else None
                    
                    print(f"  {extracted_count+1}. Original: '{raw_id}'")
                    print(f"     Simple clean: '{clean_id}'")
                    if json_extracted:
                        print(f"     JSON extracted: '{json_extracted}'")
                        print(f"     Character codes: {[ord(c) for c in json_extracted]}")
                    if guid_extracted:
                        print(f"     GUID extracted: '{guid_extracted}'")
                        print(f"     Character codes: {[ord(c) for c in guid_extracted]}")
                    
                    extracted_count += 1
    
    # Create mappings with the best approach
    print("\n==== CREATING FINAL MAPPING ====")
    incident_to_alerts = {}
    alert_to_incidents = {}
    unmapped_incidents = []
    unmapped_alerts = set(alert_id_to_alert.keys())
    matched_incident_count = 0
    matched_alert_count = 0
    total_incident_count = len(incidents_df)
    total_alert_count = len(alerts_df)
    
    # Map incidents to alerts with the best cleaning approach
    for _, incident in incidents_df.iterrows():
        incident_number = incident.get('IncidentNumber')
        
        raw_id = incident.get(alert_id_col)
        matched_alerts = []
        clean_ids = []
        
        # Apply the best cleaning approach
        if best_approach == 1:
            # Simple bracket and quote removal
            if isinstance(raw_id, str):
                clean_id = raw_id.replace('[', '').replace(']', '').replace('"', '').replace("'", "").strip()
                clean_ids = [clean_id]
        elif best_approach == 2:
            # JSON parsing then cleaning
            try:
                if isinstance(raw_id, str):
                    parsed = json.loads(raw_id)
                    if isinstance(parsed, list):
                        clean_ids = [str(id_item).strip() for id_item in parsed if id_item]
            except:
                pass
        elif best_approach == 3:
            # Deep extraction with GUID pattern matching
            if isinstance(raw_id, str):
                clean_ids = guid_pattern.findall(raw_id)
        
        # Make everything lowercase for case-insensitive matching
        clean_ids = [id.lower() for id in clean_ids if id]
        
        for clean_id in clean_ids:
            if clean_id in alert_id_to_alert:
                matched_alerts.append(alert_id_to_alert[clean_id])
                matched_alert_count += 1
                if clean_id in unmapped_alerts:
                    unmapped_alerts.remove(clean_id)
                
                # Add to alert to incidents mapping
                if clean_id not in alert_to_incidents:
                    alert_to_incidents[clean_id] = []
                alert_to_incidents[clean_id].append(incident_number)
        
        if matched_alerts:
            incident_to_alerts[incident_number] = matched_alerts
            matched_incident_count += 1
        else:
            unmapped_incidents.append(incident_number)
    
    # Convert unmapped_alerts to list of actual alert objects
    unmapped_alert_objects = [alert_id_to_alert[alert_id] for alert_id in unmapped_alerts if alert_id in alert_id_to_alert]
    
    # Print final statistics
    print(f"\nFinal join statistics (using best approach):")
    print(f"  Matched incidents: {matched_incident_count} out of {total_incident_count} ({matched_incident_count/total_incident_count*100:.2f}%)")
    print(f"  Matched alerts: {matched_alert_count} out of {total_alert_count} ({matched_alert_count/total_alert_count*100:.2f}%)")
    print(f"  Unmapped incidents: {len(unmapped_incidents)} out of {total_incident_count} ({len(unmapped_incidents)/total_incident_count*100:.2f}%)")
    print(f"  Unmapped alerts: {len(unmapped_alert_objects)} out of {total_alert_count} ({len(unmapped_alert_objects)/total_alert_count*100:.2f}%)")
    
    return {
        "incident_to_alerts": incident_to_alerts,
        "alert_to_incidents": alert_to_incidents,
        "unmapped_incidents": unmapped_incidents,
        "unmapped_alerts": unmapped_alert_objects
    }

def create_joined_dataframe(incidents_df, alerts_df, mapping):
    """
    Create a flat dataframe showing all incident-alert relationships
    """
    joined_rows = []
    
    # Add rows for mapped relationships
    for incident_number, alerts in mapping["incident_to_alerts"].items():
        incident = incidents_df[incidents_df['IncidentNumber'] == incident_number].iloc[0]
        
        for alert in alerts:
            row = {
                # Incident fields (with prefix)
                "Incident_Number": incident_number,
                "Incident_Title": incident.get('Title'),
                "Incident_Severity": incident.get('Severity'),
                "Incident_Status": incident.get('Status'),
                "Incident_TimeGenerated": incident.get('TimeGenerated [Local]'),
                "Incident_Owner": incident.get('Owner'),
                
                # Alert fields (with prefix)
                "Alert_Id": alert.get('SystemAlertId'),
                "Alert_Name": alert.get('DisplayName', alert.get('AlertName')),
                "Alert_Severity": alert.get('AlertSeverity'),
                "Alert_Status": alert.get('Status'),
                "Alert_TimeGenerated": alert.get('TimeGenerated [Local]'),
                "Alert_Provider": alert.get('ProviderName')
            }
            
            joined_rows.append(row)
    
    # Create the joined dataframe
    joined_df = pd.DataFrame(joined_rows)
    
    return joined_df

def export_to_excel(joined_df):
    """
    Export joined data to Excel
    """
    # Create output directory if it doesn't exist
    output_dir = os.path.join(base_dir, "03 extracted data")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Create output filename with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = os.path.join(output_dir, f"joined_security_data_{timestamp}.xlsx")
    
    print(f"Exporting joined data to {output_file}...")
    
    # Export to Excel
    joined_df.to_excel(output_file, index=False)
    
    print(f"Data exported successfully to {output_file}")
    return output_file

def main():
    # Load data from API (last 90 days)
    incidents_df, alerts_df = load_data(days=90)
    
    if incidents_df.empty:
        print("No incident data available. Exiting.")
        return
    
    if alerts_df.empty:
        print("No alert data available. Exiting.")
        return
    
    print(f"Loaded {len(incidents_df)} incidents and {len(alerts_df)} alerts.")
    
    # Parse JSON fields
    incidents_json_fields = ['AlertIds', 'RelatedAnalyticRuleIds', 'BookmarkIds', 'Comments', 'Labels']
    alerts_json_fields = ['ExtendedProperties', 'Entities', 'Tactics', 'Techniques']
    
    incidents_df = parse_json_fields(incidents_df, incidents_json_fields)
    alerts_df = parse_json_fields(alerts_df, alerts_json_fields)
    
    # Create mapping between incidents and alerts
    mapping = create_incident_alert_mapping(incidents_df, alerts_df)
    
    # Create joined dataframe
    joined_df = create_joined_dataframe(incidents_df, alerts_df, mapping)
    
    # Export to Excel
    export_to_excel(joined_df)
    
    print("Done! Joined security incidents and alerts data exported successfully.")

if __name__ == "__main__":
    main()