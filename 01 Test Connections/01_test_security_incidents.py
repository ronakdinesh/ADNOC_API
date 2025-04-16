import requests
import json
import pandas as pd
import argparse
import sys
import os
import adal
from datetime import datetime, timedelta
from dotenv import load_dotenv
import traceback

# Add path to the parent directory to import the LLM analysis module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from llm_read_security_incidents import analyze_security_incidents
    LLM_ANALYSIS_AVAILABLE = True
except ImportError:
    try:
        # Try to import from the AI Agent API directory
        sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "02 AI Agent API"))
        from llm_read_security_incidents import analyze_security_incidents
        LLM_ANALYSIS_AVAILABLE = True
    except ImportError:
        print("Warning: LLM analysis module not found. Export-only mode available.")
        LLM_ANALYSIS_AVAILABLE = False

# Load environment variables from .env file
load_dotenv()

# Azure AD and Log Analytics configuration
tenant_id = os.getenv('TENANT_ID')
client_id = os.getenv('CLIENT_ID')
client_secret = os.getenv('CLIENT_SECRET')
workspace_id = os.getenv('WORKSPACE_ID')

def get_security_incidents(days_back=7, include_title_filter=True, verbose=True):
    """
    Retrieve security incidents from Microsoft Sentinel
    
    Args:
        days_back (int): Number of days back to look for incidents
        include_title_filter (bool): Whether to filter for specific DNS TI incidents
        verbose (bool): Whether to print detailed information
    
    Returns:
        List of incident dictionaries or None if error
    """
    try:
        if verbose:
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
        if verbose:
            print("Authentication successful!")

        # Build KQL query
        query = f"""
        SecurityIncident
        | where TimeGenerated > ago({days_back}d)
        """
        
        # Add title filter if specified
        if include_title_filter:
            query += """| where Title == "[Custom]-[TI]-DNS with TI Domain Correlation"\n"""
            
        # Add sorting and limit
        query += """| order by TimeGenerated desc"""

        if verbose:
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

        if verbose:
            print("Sending request to Microsoft Sentinel API...")
        
        # Send the request
        response = requests.post(url, headers=headers, json=request_body)

        if response.status_code == 200:
            if verbose:
                print("Request successful!")
            
            results = response.json()
            incidents = []
            
            # Print column information if verbose
            if verbose and results.get('tables') and results['tables'][0].get('columns'):
                columns = [col['name'] for col in results['tables'][0]['columns']]
                print(f"\nSecurityIncident table has {len(columns)} columns:")
                for col in sorted(columns):
                    print(f"- {col}")
            
            for table in results['tables']:
                column_names = [col['name'] for col in table['columns']]
                rows = table['rows']
                
                for row in rows:
                    incident_entry = dict(zip(column_names, row))
                    incidents.append(incident_entry)
            
            if verbose:
                print(f"\nFound {len(incidents)} security incidents")
            
            return incidents
        else:
            print(f"Error: {response.status_code}")
            print(f"Error details: {response.text}")
            return None

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return None

def export_to_excel(incidents, output_file=None):
    """
    Export incidents to Excel format compatible with llm_read_security_incidents.py
    
    Args:
        incidents (list): List of incident dictionaries
        output_file (str): Optional output file path
        
    Returns:
        str: Path to the created Excel file
    """
    if not incidents:
        print("No incidents to export")
        return None
    
    # Convert to DataFrame
    df = pd.DataFrame(incidents)
    
    # Add a metadata row with the current timestamp to confirm real-time API access
    fetch_time = datetime.now()
    fetch_time_str = fetch_time.strftime("%Y-%m-%d %H:%M:%S")
    
    # Generate default filename if not provided
    if not output_file:
        timestamp = fetch_time.strftime("%Y%m%d_%H%M%S")
        output_file = f"security_incidents_{timestamp}.xlsx"
    
    # Ensure output directory exists
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Save to Excel
    df.to_excel(output_file, index=False)
    
    # Add metadata about when the incidents were fetched
    print(f"\nREAL-TIME CONFIRMATION:")
    print(f"Security incidents fetched from Sentinel API on: {fetch_time_str}")
    print(f"Data is current as of API response time")
    if incidents:
        most_recent = max([pd.to_datetime(incident.get('TimeGenerated', fetch_time_str)) 
                           for incident in incidents if 'TimeGenerated' in incident], 
                          default=fetch_time)
        print(f"Most recent incident timestamp: {most_recent}")
    
    print(f"\nSuccessfully exported {len(incidents)} incidents to {output_file}")
    
    # Add fetch time to return value for use in analysis
    return output_file, fetch_time

def main():
    parser = argparse.ArgumentParser(description="Fetch security incidents from Microsoft Sentinel and analyze with LLM")
    parser.add_argument("--days", type=int, default=7, help="Number of days back to query (default: 7)")
    parser.add_argument("--all-incidents", action="store_true", help="Fetch all incidents (not just DNS TI correlation)")
    parser.add_argument("--output", type=str, help="Output Excel file path (default: auto-generated)")
    parser.add_argument("--analyze", action="store_true", help="Run LLM analysis on the incidents")
    parser.add_argument("--quiet", action="store_true", help="Reduce verbosity")
    
    args = parser.parse_args()
    
    # Validate LLM analysis request
    if args.analyze and not LLM_ANALYSIS_AVAILABLE:
        print("Error: LLM analysis requested but module not available. Please check that 02 AI Agent API/llm_read_security_incidents.py exists.")
        return
    
    # Get incidents
    incidents = get_security_incidents(
        days_back=args.days,
        include_title_filter=not args.all_incidents,
        verbose=not args.quiet
    )
    
    if not incidents:
        print("No incidents found or error occurred. Exiting.")
        return
    
    # Export to Excel
    excel_result = export_to_excel(incidents, args.output)
    
    if isinstance(excel_result, tuple):
        excel_path, fetch_time = excel_result
    else:
        excel_path = excel_result
        fetch_time = datetime.now()
    
    if not excel_path:
        print("Failed to export incidents. Exiting.")
        return
    
    # Run LLM analysis if requested
    if args.analyze:
        print(f"\nStarting LLM analysis on {len(incidents)} incidents...")
        try:
            # Create output directory for analysis if it doesn't exist
            output_dir = os.path.dirname(excel_path) or "."
            os.makedirs(os.path.join(output_dir, "analysis"), exist_ok=True)
            
            # Call the analyze_security_incidents function with fetch time
            if 'analyze_security_incidents' in globals():
                # Direct import case
                analyze_security_incidents(excel_path, fetch_time=fetch_time)
            else:
                # Module import case
                from llm_read_security_incidents import analyze_security_incidents
                analyze_security_incidents(excel_path, fetch_time=fetch_time)
                
            print("\nAnalysis complete. Check the generated text files for results.")
        except Exception as e:
            print(f"Error running LLM analysis: {str(e)}")
            traceback.print_exc()

if __name__ == "__main__":
    print("\nMicrosoft Sentinel Incident Retrieval and Analysis Tool")
    print("=====================================================")
    main() 