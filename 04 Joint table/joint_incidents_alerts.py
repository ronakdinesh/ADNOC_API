"""
Joint Security Incidents and Alerts

This script joins data from security incidents and alerts Excel files, cleaning up the AlertIds field
from the incidents file to make it match with the SystemAlertId field in the alerts file.

See README.md for detailed instructions on running this script.
"""

import pandas as pd
import os
import sys
from datetime import datetime

# Constants
INCIDENTS_FILE = "security_incidents_20250410_141645.xlsx"
ALERTS_FILE = "security_alerts_20250410_135652.xlsx"
DATA_FOLDER = "03 extracted data"
OUTPUT_FOLDER = "03 extracted data"

def find_column_by_pattern(df, patterns):
    """Find a column in a dataframe that matches any of the given patterns"""
    for pattern in patterns:
        matching_cols = [col for col in df.columns if pattern.lower() in col.lower()]
        if matching_cols:
            return matching_cols[0]
    return None

def clean_alert_id(value):
    """Clean the AlertIds field from the incidents table"""
    if pd.isna(value) or value is None:
        return None
    
    # Convert to string if it's not already
    value_str = str(value)
    
    # Remove brackets, quotes, and whitespace
    cleaned = value_str.replace('[', '').replace(']', '').replace('"', '').replace("'", "").strip()
    
    # Return None if we end up with an empty string
    if not cleaned:
        return None
        
    return cleaned

def main():
    """Main function to join security incidents and alerts data"""
    print("-" * 60)
    print("SECURITY INCIDENTS AND ALERTS JOINER")
    print("-" * 60)
    
    try:
        # Get the current working directory
        current_dir = os.getcwd()
        print(f"Current directory: {current_dir}")
        
        # Build paths
        incidents_path = os.path.join(current_dir, DATA_FOLDER, INCIDENTS_FILE)
        alerts_path = os.path.join(current_dir, DATA_FOLDER, ALERTS_FILE)
        
        # Check if files exist
        print("\nChecking input files:")
        if not os.path.exists(incidents_path):
            print(f"ERROR: Incidents file not found at {incidents_path}")
            return
            
        if not os.path.exists(alerts_path):
            print(f"ERROR: Alerts file not found at {alerts_path}")
            return
            
        print(f"✓ Found incidents file: {incidents_path}")
        print(f"✓ Found alerts file: {alerts_path}")
        
        # Load data
        print("\nLoading data files...")
        incidents_df = pd.read_excel(incidents_path)
        alerts_df = pd.read_excel(alerts_path)
        
        print(f"✓ Loaded {len(incidents_df)} incident records with {len(incidents_df.columns)} columns")
        print(f"✓ Loaded {len(alerts_df)} alert records with {len(alerts_df.columns)} columns")
        
        # Find required columns
        print("\nIdentifying required columns:")
        
        # Find AlertIds column in incidents
        alert_ids_col = find_column_by_pattern(incidents_df, ['alertids', 'alert_ids', 'alertid', 'alert_id'])
        if not alert_ids_col:
            print("ERROR: Could not find AlertIds column in incidents data")
            return
        print(f"✓ Found AlertIds column: '{alert_ids_col}'")
        
        # Find SystemAlertId column in alerts
        system_alert_id_col = find_column_by_pattern(alerts_df, ['systemalertid', 'system_alert_id', 'alertid', 'alert_id'])
        if not system_alert_id_col:
            print("ERROR: Could not find SystemAlertId column in alerts data")
            return
        print(f"✓ Found SystemAlertId column: '{system_alert_id_col}'")
        
        # Show sample data
        print("\nSample AlertIds from incidents:")
        sample_alert_ids = incidents_df[alert_ids_col].head(3).tolist()
        for i, aid in enumerate(sample_alert_ids):
            print(f"  {i+1}. {aid}")
            
        print("\nSample SystemAlertIds from alerts:")
        sample_system_ids = alerts_df[system_alert_id_col].head(3).tolist()
        for i, sid in enumerate(sample_system_ids):
            print(f"  {i+1}. {sid}")
        
        # Clean AlertIds
        print("\nCleaning AlertIds from incidents data...")
        incidents_df['CleanAlertId'] = incidents_df[alert_ids_col].apply(clean_alert_id)
        
        # Print sample of cleaned IDs
        print("Sample of cleaned AlertIds:")
        sample_cleaned = list(zip(
            incidents_df[alert_ids_col].head(3).tolist(),
            incidents_df['CleanAlertId'].head(3).tolist()
        ))
        for i, (orig, cleaned) in enumerate(sample_cleaned):
            print(f"  {i+1}. '{orig}' -> '{cleaned}'")
        
        # Rename columns to prevent conflicts during merge
        print("\nRenaming columns to prevent conflicts during merge...")
        incidents_df_renamed = incidents_df.add_prefix('Incident_')
        alerts_df_renamed = alerts_df.add_prefix('Alert_')
        
        # Ensure CleanAlertId column is still available after renaming
        incidents_df_renamed['CleanAlertId'] = incidents_df['CleanAlertId']
        
        # Join tables
        print("\nJoining incidents and alerts...")
        joined_df = pd.merge(
            incidents_df_renamed,
            alerts_df_renamed,
            left_on='CleanAlertId',
            right_on=f'Alert_{system_alert_id_col}',
            how='inner'
        )
        
        print(f"✓ Join complete with {len(joined_df)} matched rows")
        print(f"✓ Joined table has {len(joined_df.columns)} columns (all columns from both source tables)")
        
        if len(joined_df) == 0:
            print("WARNING: No matching rows found! This likely indicates an issue with the ID formats.")
            
            # Try case-insensitive comparison
            print("\nAttempting case-insensitive join...")
            incidents_df_renamed['CleanAlertId_lower'] = incidents_df_renamed['CleanAlertId'].str.lower() if incidents_df_renamed['CleanAlertId'].dtype == 'object' else incidents_df_renamed['CleanAlertId']
            alerts_df_renamed[f'Alert_{system_alert_id_col}_lower'] = alerts_df_renamed[f'Alert_{system_alert_id_col}'].str.lower() if alerts_df_renamed[f'Alert_{system_alert_id_col}'].dtype == 'object' else alerts_df_renamed[f'Alert_{system_alert_id_col}']
            
            joined_df = pd.merge(
                incidents_df_renamed,
                alerts_df_renamed,
                left_on='CleanAlertId_lower',
                right_on=f'Alert_{system_alert_id_col}_lower',
                how='inner'
            )
            
            print(f"✓ Case-insensitive join complete with {len(joined_df)} matched rows")
            
            if len(joined_df) == 0:
                print("ERROR: Still no matches found. Cannot continue.")
                return
        
        # Create a second output with the KQL query format columns
        print("\nCreating KQL-formatted output dataframe...")
        
        # Map known column names to KQL format
        kql_columns = {
            'Incident_IncidentNumber': 'IncidentId',
            'Incident_IncidentName': 'IncidentName',
            'Incident_Title': 'IncidentName',
            'Incident_Severity': 'IncidentSeverity',
            'Incident_Status': 'IncidentStatus',
            'Alert_AlertName': 'AlertName',
            'Alert_DisplayName': 'AlertName',
            'Alert_Severity': 'AlertSeverity',
            'Incident_TimeGenerated': 'IncidentTimeGenerated',
            'Alert_TimeGenerated': 'AlertTimeGenerated',
            'Alert_ProviderName': 'ProviderName',
            'Alert_Description': 'Description',
            'Alert_Tactics': 'Tactics',
            'Alert_Techniques': 'Techniques'
        }
        
        # Select only columns that exist in the joined dataframe
        available_kql_columns = {k: v for k, v in kql_columns.items() if k in joined_df.columns}
        
        if available_kql_columns:
            kql_df = joined_df[list(available_kql_columns.keys())].rename(columns=available_kql_columns)
            print(f"✓ Created KQL-formatted dataframe with {len(kql_df)} rows and {len(kql_df.columns)} columns")
        else:
            print("WARNING: Could not identify expected columns for KQL format. Using all columns.")
            kql_df = joined_df
        
        # Save results
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Save complete joined table with all columns
        full_output_path = os.path.join(current_dir, OUTPUT_FOLDER, f"joined_incidents_alerts_full_{timestamp}.xlsx")
        print(f"\nSaving complete joined table with all columns to: {full_output_path}")
        joined_df.to_excel(full_output_path, index=False)
        print(f"✓ Successfully saved complete joined data!")
        
        # Save KQL formatted table
        kql_output_path = os.path.join(current_dir, OUTPUT_FOLDER, f"joined_incidents_alerts_kql_{timestamp}.xlsx")
        print(f"\nSaving KQL-formatted table to: {kql_output_path}")
        kql_df.to_excel(kql_output_path, index=False)
        print(f"✓ Successfully saved KQL-formatted data!")
        
        # Print summary
        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)
        print(f"Incidents: {len(incidents_df)} rows, {len(incidents_df.columns)} columns")
        print(f"Alerts: {len(alerts_df)} rows, {len(alerts_df.columns)} columns")
        print(f"Matched rows: {len(joined_df)} ({len(joined_df)/len(incidents_df)*100:.1f}% of incidents)")
        print(f"Complete output: {full_output_path}")
        print(f"KQL-formatted output: {kql_output_path}")
        
    except Exception as e:
        print(f"\nERROR: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    try:
        main()
        print("\nScript execution complete!")
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
    
    # Keep the console window open if run by double-clicking
    if 'idlelib' not in sys.modules:
        input("\nPress Enter to exit...") 