import requests
import json
from datetime import datetime
from dotenv import load_dotenv
import os
import adal
import pandas as pd

# Load environment variables from .env file
load_dotenv()

# Azure AD and Log Analytics configuration
tenant_id = os.getenv('TENANT_ID')
client_id = os.getenv('CLIENT_ID')
client_secret = os.getenv('CLIENT_SECRET')
workspace_id = os.getenv('WORKSPACE_ID')

def get_security_alerts():
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

        # KQL query
        query = """
        SecurityAlert
        | where TimeGenerated > ago(30d)
        | where AlertName == "[Custom]-[TI]-DNS with TI Domain Correlation"
        | order by TimeGenerated desc
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
            
            # Print column information
            if results.get('tables') and results['tables'][0].get('columns'):
                columns = [col['name'] for col in results['tables'][0]['columns']]
                print(f"\nSecurityAlert table has {len(columns)} columns:")
                for col in sorted(columns):
                    print(f"- {col}")
            
            for table in results['tables']:
                column_names = [col['name'] for col in table['columns']]
                rows = table['rows']
                
                for row in rows:
                    alert_entry = dict(zip(column_names, row))
                    alerts.append(alert_entry)
            
            print(f"\nFound {len(alerts)} security alerts")
            return alerts
        else:
            print(f"Error: {response.status_code}")
            print(f"Error details: {response.text}")
            return None

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return None

def export_to_excel(alerts):
    if not alerts or len(alerts) == 0:
        print("No data to export to Excel.")
        return
    
    try:
        # Convert to DataFrame
        df = pd.DataFrame(alerts)
        
        # Get current date for filename
        current_date = datetime.now().strftime("%Y-%m-%d")
        excel_filename = f"TI_DNS_Domain_Correlation_{current_date}.xlsx"
        
        # Export to Excel
        with pd.ExcelWriter(excel_filename, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='TI DNS Alerts', index=False)
            
            # Auto-adjust columns' width
            worksheet = writer.sheets['TI DNS Alerts']
            for i, col in enumerate(df.columns):
                max_length = max(df[col].astype(str).map(len).max(), len(col)) + 2
                worksheet.column_dimensions[worksheet.cell(row=1, column=i+1).column_letter].width = max_length
        
        print(f"Data exported successfully to {excel_filename}")
        return excel_filename
    except Exception as e:
        print(f"Error exporting to Excel: {str(e)}")
        return None

if __name__ == "__main__":
    print("\nExecuting SecurityAlert query")
    alerts = get_security_alerts()
    if alerts:
        excel_file = export_to_excel(alerts) 