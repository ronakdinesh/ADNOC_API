import requests
import json
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
import adal

# Load environment variables from .env file
load_dotenv()

# Azure AD and Log Analytics configuration
tenant_id = os.getenv('TENANT_ID')
client_id = os.getenv('CLIENT_ID')
client_secret = os.getenv('CLIENT_SECRET')
workspace_id = os.getenv('WORKSPACE_ID')

def test_connection():
    try:
        # Validate that all required environment variables are set
        required_vars = {
            'TENANT_ID': tenant_id,
            'CLIENT_ID': client_id,
            'CLIENT_SECRET': client_secret,
            'WORKSPACE_ID': workspace_id
        }

        missing_vars = [var for var, value in required_vars.items() if not value]
        if missing_vars:
            print(f"❌ Error: Missing required environment variables: {', '.join(missing_vars)}")
            return False

        print("✅ All required environment variables are present")

        # Authentication
        print("🔐 Attempting to authenticate with Azure AD...")
        authority_url = f"https://login.microsoftonline.com/{tenant_id}"
        resource = "https://api.loganalytics.io"

        context = adal.AuthenticationContext(authority_url)
        token = context.acquire_token_with_client_credentials(
            resource,
            client_id,
            client_secret
        )

        access_token = token['accessToken']
        print("✅ Successfully authenticated with Azure AD")

        # Set up a simple test query
        query = """
        SecurityAlert
        | where TimeGenerated > ago(1h)
        | take 1
        """

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

        print("🔍 Testing API connection with a simple query...")
        response = requests.post(url, headers=headers, json=request_body)

        if response.status_code == 200:
            print("✅ Successfully connected to Microsoft Sentinel API")
            results = response.json()
            if results['tables'][0]['rows']:
                print("✅ Found security alerts in the workspace")
            else:
                print("ℹ️ No recent security alerts found (this is normal if there are no alerts in the last hour)")
            return True
        else:
            print(f"❌ API request failed with status code: {response.status_code}")
            print(f"Error details: {response.text}")
            return False

    except Exception as e:
        print(f"❌ An error occurred: {str(e)}")
        return False

if __name__ == "__main__":
    print("\n🔍 Testing Microsoft Sentinel API Connection...\n")
    success = test_connection()
    print("\nTest completed!")
    if success:
        print("✅ All tests passed successfully!")
    else:
        print("❌ Some tests failed. Please check the error messages above.") 