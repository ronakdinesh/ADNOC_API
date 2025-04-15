import pandas as pd
import os
from datetime import datetime

def main():
    """Main function to join incidents and alerts data"""
    try:
        # Define file paths
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        incidents_path = os.path.join(base_dir, "03 extracted data", "security_incidents_20250410_141645.xlsx")
        alerts_path = os.path.join(base_dir, "03 extracted data", "security_alerts_20250410_135652.xlsx")
        
        # Check if files exist
        print(f"Checking files:")
        print(f"  Incidents file: {os.path.abspath(incidents_path)} - {'Exists' if os.path.exists(incidents_path) else 'NOT FOUND'}")
        print(f"  Alerts file: {os.path.abspath(alerts_path)} - {'Exists' if os.path.exists(alerts_path) else 'NOT FOUND'}")
        
        if not os.path.exists(incidents_path) or not os.path.exists(alerts_path):
            print("ERROR: One or both input files not found")
            return
        
        # Load Excel files
        print("Loading incidents data...")
        incidents_df = pd.read_excel(incidents_path)
        print(f"Loaded {len(incidents_df)} incidents")
        
        print("Loading alerts data...")
        alerts_df = pd.read_excel(alerts_path)
        print(f"Loaded {len(alerts_df)} alerts")
        
        # Display first few rows to understand the structure
        print("\nFirst 2 rows of incidents data:")
        print(incidents_df.head(2))
        
        # Process AlertIds in incidents dataframe
        print("\nCleaning AlertIds...")
        incidents_df['AlertId'] = incidents_df['AlertIds'].apply(
            lambda x: x.replace('[', '').replace(']', '').replace('"', '').replace("'", "").strip() 
            if isinstance(x, str) else x
        )
        
        # Join the dataframes
        print("\nJoining tables...")
        joined_df = pd.merge(
            incidents_df,
            alerts_df,
            left_on='AlertId',
            right_on='SystemAlertId',
            how='inner'
        )
        
        print(f"Join complete. {len(joined_df)} matched rows")
        
        # Create final output dataframe with required columns
        result_columns = {
            'IncidentNumber': 'IncidentId',
            'IncidentName': 'IncidentName',
            'Severity_x': 'IncidentSeverity',
            'Status_x': 'IncidentStatus',
            'AlertName': 'AlertName',
            'Severity_y': 'AlertSeverity',
            'TimeGenerated_x': 'IncidentTimeGenerated',
            'TimeGenerated_y': 'AlertTimeGenerated',
            'ProviderName_y': 'ProviderName',
            'Description_y': 'Description',
            'Tactics': 'Tactics',
            'Techniques': 'Techniques'
        }
        
        # Select and rename columns if they exist
        available_columns = {}
        for src, dst in result_columns.items():
            if src in joined_df.columns:
                available_columns[src] = dst
        
        if available_columns:
            result_df = joined_df[list(available_columns.keys())].rename(columns=available_columns)
        else:
            print("WARNING: Could not find expected columns. Using all columns.")
            result_df = joined_df
            
        # Save the result
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = os.path.join(base_dir, "03 extracted data", f"joined_security_data_{timestamp}.xlsx")
        
        print(f"\nSaving joined data to {output_path}")
        result_df.to_excel(output_path, index=False)
        print(f"Joined data saved successfully!")
        
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main() 