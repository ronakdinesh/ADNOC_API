import pandas as pd
import os
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Union, Set
import re
import traceback
import ollama  # Using ollama client directly
from pydantic import BaseModel, Field
import requests  # Added for API calls
import adal      # Added for Azure AD Authentication
from dotenv import load_dotenv # Added for environment variables
from tabulate import tabulate # Added for formatting log output

# Load environment variables from .env file
load_dotenv()

# Import VirusTotal integration
try:
    # Try current directory first
    from virustotal_integration import analyze_domains, format_vt_results
    VIRUSTOTAL_AVAILABLE = True
except ImportError:
    try:
        # Try relative import from current module directory
        from .virustotal_integration import analyze_domains, format_vt_results
        VIRUSTOTAL_AVAILABLE = True
    except ImportError:
        try:
            # Try absolute import by adding the PARENT directory
            current_dir = os.path.dirname(os.path.abspath(__file__))
            parent_dir = os.path.dirname(current_dir) # <-- Get the parent directory
            import sys
            if parent_dir not in sys.path:
                 sys.path.append(parent_dir) # <-- Add the PARENT directory to the path
            from virustotal_integration import analyze_domains, format_vt_results
            VIRUSTOTAL_AVAILABLE = True
        except ImportError:
            print("VirusTotal integration not available. Domain reputation checks will be skipped.")
            VIRUSTOTAL_AVAILABLE = False

# Ollama configuration
OLLAMA_API_BASE = "http://localhost:11434"
OLLAMA_MODEL = "llama3.2:latest"

# Azure AD and Log Analytics configuration
TENANT_ID = os.getenv('TENANT_ID')
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
WORKSPACE_ID = os.getenv('WORKSPACE_ID')

# Check if required Azure credentials are loaded
AZURE_CREDS_LOADED = all([TENANT_ID, CLIENT_ID, CLIENT_SECRET, WORKSPACE_ID])
if not AZURE_CREDS_LOADED:
    print("Warning: Azure Log Analytics credentials (TENANT_ID, CLIENT_ID, CLIENT_SECRET, WORKSPACE_ID) not found in environment variables. Raw log fetching will be skipped.")
else:
    print("Azure Log Analytics credentials loaded successfully.")


class IncidentAnalysisOutput(BaseModel):
    threat_details: Union[str, Dict[str, Any]]
    significance: Union[str, Dict[str, Any]]
    recommended_actions: List[str]
    summary: Union[str, Dict[str, Any]]
    attack_techniques: List[str]
    technique_details: Optional[Dict[str, Dict[str, str]]] = {}
    severity_assessment: Union[str, Dict[str, Any]]
    next_steps_for_l1: List[str]
    time_sensitivity: Union[str, Dict[str, Any]]
    incident_type: Union[str, Dict[str, Any]]
    potential_impact: Optional[Union[str, Dict[str, Any]]] = "Not assessed"


class SecurityIndicators(BaseModel):
    ips: List[str] = Field(default=[], description="IP addresses found in the incident")
    domains: List[str] = Field(default=[], description="Domain names found in the incident")
    file_hashes: List[str] = Field(default=[], description="File hashes (MD5, SHA1, SHA256) found in the incident")
    cves: List[str] = Field(default=[], description="CVE identifiers found in the incident")
    users: List[str] = Field(default=[], description="User accounts mentioned in the incident")
    processes: List[str] = Field(default=[], description="Process names mentioned in the incident")
    urls: List[str] = Field(default=[], description="URLs found in the incident")
    internal_ips: List[str] = Field(default=[], description="Internal IP addresses")
    external_ips: List[str] = Field(default=[], description="External IP addresses")


def get_mitre_attack_info(technique_ids: List[str], technique_details: Dict[str, Dict[str, str]] = None) -> str:
    """Provide information about MITRE ATT&CK techniques, preferring LLM-provided details when available"""
    # Instead of hardcoding MITRE ATT&CK techniques, we'll use the LLM to generate information
    # about techniques that aren't provided in technique_details
    
    # First, check which techniques need additional information
    techniques_needing_info = []
    for technique_id in technique_ids:
        # Clean up technique ID format
        clean_id = technique_id.strip().upper()
        if not clean_id.startswith("T"):
            clean_id = f"T{clean_id}"
        
        # If we don't have details for this technique, add it to the list
        if not technique_details or clean_id not in technique_details:
            techniques_needing_info.append(clean_id)
    
    # If we need to get information for any techniques, use the LLM
    if techniques_needing_info:
        try:
            # Configure ollama client with the right base URL
            client = ollama.Client(host=OLLAMA_API_BASE)
            
            # Create a prompt asking for MITRE ATT&CK information
            prompt = (
                f"Provide information about the following MITRE ATT&CK techniques: {', '.join(techniques_needing_info)}.\n\n"
                f"For each technique, provide the following in JSON format:\n"
                f"- name: The name of the technique\n"
                f"- tactic: The tactic(s) this technique belongs to\n"
                f"- description: A brief description of the technique\n"
                f"- mitigation: Recommended mitigations for this technique\n\n"
                f"Format your response as a JSON object where keys are technique IDs and values are objects with the fields above."
            )
            
            # Make the API call to Ollama
            response = client.chat(
                model=OLLAMA_MODEL,
                messages=[{"role": "user", "content": prompt}],
                stream=False,
                format='json'
            )
            
            # Extract and parse the JSON response
            json_str = response['message']['content']
            generated_techniques = json.loads(json_str)
            
            # If technique_details is None, initialize it
            if technique_details is None:
                technique_details = {}
                
            # Add the generated techniques to our technique_details
            for tech_id, tech_info in generated_techniques.items():
                if tech_id not in technique_details:
                    technique_details[tech_id] = tech_info
                    
        except Exception as e:
            print(f"Error generating MITRE ATT&CK information: {str(e)}")
            # If there's an error, we'll continue with whatever information we have
    
    # Format the info for each technique
    formatted_info = "MITRE ATT&CK TECHNIQUES:\n"
    
    for technique_id in technique_ids:
        # Clean up technique ID format
        technique_id = technique_id.strip().upper()
        if not technique_id.startswith("T"):
            technique_id = f"T{technique_id}"
        
        # Prefer LLM-provided details if available
        if technique_details and technique_id in technique_details:
            technique_info = technique_details[technique_id]
            name = technique_info.get("name", "Unknown")
            tactic = technique_info.get("tactic", "Unknown")
            description = technique_info.get("description", "No description provided")
            mitigation = technique_info.get("mitigation", "No mitigation details provided")
        # Fall back to our local database
        elif technique_id in mitre_techniques:
            tech = mitre_techniques[technique_id]
            name = tech["name"]
            tactic = tech["tactic"]
            description = tech["description"]
            mitigation = tech["mitigation"]
        # No info available
        else:
            name = "Unknown Technique"
            tactic = "Unknown"
            description = "This technique ID was not found in the local database or LLM-provided details."
            mitigation = "Refer to the MITRE ATT&CK website (https://attack.mitre.org/techniques/) for more information."
        
        # Add to output
        formatted_info += (
            f"[{technique_id}] {name} - {tactic}\n"
            f"  Description: {description}\n"
            f"  Mitigation: {mitigation}\n\n"
        )
    
    return formatted_info


def get_playbook_reference(incident_type: str) -> str:
    """Provide reference to common SOC playbooks based on incident type"""
    # This function dynamically generates a playbook reference based on the incident type
    # Rather than using hard-coded playbooks, we'll have the LLM generate appropriate
    # playbook content based on the incident type provided
    
    # Normalize the incident type
    incident_type_normalized = incident_type.lower() if incident_type else "suspicious_activity"
    
    # Prepare the prompt for the LLM to generate a playbook
    prompt = f"""
    As a security operations expert, create a concise SOC playbook reference for a {incident_type_normalized} incident.
    Include:
    1. An appropriate playbook name
    2. 5 key investigation steps (specific to this incident type)
    3. 3-4 recommended tools for investigation
    4. Clear escalation criteria
    
    Format as a JSON object with keys: 'name', 'key_steps' (list), 'tools' (list), and 'escalation_criteria' (string).
    """
    
    try:
        # Configure ollama client with the right base URL
        client = ollama.Client(host=OLLAMA_API_BASE)
        
        # Make the API call to Ollama, enforcing JSON output
        response = client.chat(
            model=OLLAMA_MODEL,
            messages=[{"role": "user", "content": prompt}],
            stream=False,
            format='json'
        )
        
        # Extract and parse the response
        json_str = response['message']['content']
        playbook = json.loads(json_str)
        
        # Validate the response has the expected structure
        if not all(k in playbook for k in ['name', 'key_steps', 'tools', 'escalation_criteria']):
            raise ValueError("LLM response missing required playbook fields")
        
        # Format the playbook reference
        formatted_playbook = (
            f"PLAYBOOK REFERENCE: {playbook['name']}\n"
            f"Key Investigation Steps:\n"
        )
        
        for idx, step in enumerate(playbook['key_steps'], 1):
            formatted_playbook += f"  {idx}. {step}\n"
        
        formatted_playbook += f"\nRecommended Tools: {', '.join(playbook['tools'])}\n"
        formatted_playbook += f"Escalation Criteria: {playbook['escalation_criteria']}\n"
        
        return formatted_playbook
        
    except Exception as e:
        # Fallback to a generic playbook if LLM generation fails
        print(f"Error generating playbook with LLM: {e}")
        
        # Create a generic playbook based on the incident type
        generic_name = f"{incident_type_normalized.title()} Response Playbook"
        generic_steps = [
            "Document observed indicators and scope",
            "Collect and preserve relevant evidence",
            "Analyze affected systems and accounts",
            "Implement containment measures",
            "Determine root cause and impact"
        ]
        generic_tools = ["SIEM", "EDR", "Log analysis tools", "Forensic utilities"]
        generic_criteria = "Critical systems affected, evidence of data exfiltration, or widespread impact"
        
        # Format the generic playbook
        formatted_playbook = (
            f"PLAYBOOK REFERENCE: {generic_name}\n"
            f"Key Investigation Steps:\n"
        )
        
        for idx, step in enumerate(generic_steps, 1):
            formatted_playbook += f"  {idx}. {step}\n"
        
        formatted_playbook += f"\nRecommended Tools: {', '.join(generic_tools)}\n"
        formatted_playbook += f"Escalation Criteria: {generic_criteria}\n"
        
        return formatted_playbook
    
    # Normalize incident type and look for best match
    incident_type_lower = incident_type.lower() if incident_type else ""
    
    # Direct match
    if incident_type_lower in playbooks:
        playbook = playbooks[incident_type_lower]
    # Partial match
    else:
        # Find the best match based on key terms
        for key in playbooks:
            if key in incident_type_lower:
                playbook = playbooks[key]
                break
        else:
            # Default to suspicious activity if no match
            playbook = playbooks["suspicious_activity"]
    
    # Format the playbook reference
    formatted_playbook = (
        f"PLAYBOOK REFERENCE: {playbook['name']}\n"
        f"Key Investigation Steps:\n"
    )
    
    for idx, step in enumerate(playbook['key_steps'], 1):
        formatted_playbook += f"  {idx}. {step}\n"
    
    formatted_playbook += f"\nRecommended Tools: {', '.join(playbook['tools'])}\n"
    formatted_playbook += f"Escalation Criteria: {playbook['escalation_criteria']}\n"
    
    return formatted_playbook


def extract_security_indicators(text: str) -> SecurityIndicators:
    """Extract security indicators from text"""
    # Pattern for IPv4 addresses
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    
    # Simple pattern for domains
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    
    # Pattern for file hashes
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    
    # Pattern for CVEs
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    
    # Pattern for URLs
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    
    # Pattern for user accounts (basic pattern - can be refined)
    user_pattern = r'(?:user|username|account):\s*(\w+)'
    
    # Pattern for process names (basic pattern - can be refined)
    process_pattern = r'(?:process|executable):\s*([\w\.-]+\.exe)'
    
    # Find all matches
    ips = re.findall(ip_pattern, str(text))
    domains = re.findall(domain_pattern, str(text))
    md5_hashes = re.findall(md5_pattern, str(text))
    sha1_hashes = re.findall(sha1_pattern, str(text))
    sha256_hashes = re.findall(sha256_pattern, str(text))
    cves = re.findall(cve_pattern, str(text), re.IGNORECASE)
    urls = re.findall(url_pattern, str(text))
    users = re.findall(user_pattern, str(text), re.IGNORECASE)
    processes = re.findall(process_pattern, str(text), re.IGNORECASE)
    
    # Filter out IPs that might be timestamps or not valid
    valid_ips = [ip for ip in ips if all(0 <= int(octet) <= 255 for octet in ip.split('.'))]
    
    # Categorize IPs as internal or external (simple heuristic)
    internal_ips = [ip for ip in valid_ips if (
        ip.startswith('10.') or 
        ip.startswith('192.168.') or 
        (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31)
    )]
    external_ips = [ip for ip in valid_ips if ip not in internal_ips]
    
    # Combine all file hashes
    all_hashes = md5_hashes + sha1_hashes + sha256_hashes
    
    return SecurityIndicators(
        ips=valid_ips,
        domains=domains,
        file_hashes=all_hashes,
        cves=cves,
        users=users,
        processes=processes,
        urls=urls,
        internal_ips=internal_ips,
        external_ips=external_ips
    )


def find_related_incidents(all_incidents: Dict[str, pd.DataFrame], current_incident: pd.DataFrame, 
                          current_indicators: SecurityIndicators) -> List[Dict[str, Any]]:
    """Find potentially related incidents based on common indicators or timeframe"""
    related_incidents = []
    
    # Get current incident details
    current_id = str(current_incident.iloc[0]['IncidentNumber'])
    current_first_time = current_incident.iloc[0]['LastModifiedTime']
    
    # Ensure current_first_time is a datetime object
    if isinstance(current_first_time, str):
        try:
            current_first_time = pd.to_datetime(current_first_time)
        except:
            print(f"Warning: Could not convert incident timestamp to datetime: {current_first_time}")
            # Return empty list if we can't process the timestamp
            return []
    
    # Define the timeframe for related incidents (e.g., 1 week before and after)
    time_window_start = current_first_time - timedelta(days=7)
    time_window_end = current_first_time + timedelta(days=7)
    
    # Set of current indicators to check
    current_iocs: Set[str] = set()
    current_iocs.update(current_indicators.ips)
    current_iocs.update(current_indicators.domains)
    current_iocs.update(current_indicators.file_hashes)
    
    for incident_id, incident_df in all_incidents.items():
        # Skip current incident
        if incident_id == current_id:
            continue
        
        # Check timeframe - get first detection time
        incident_time = incident_df.iloc[0]['LastModifiedTime']
        
        # Ensure incident_time is a datetime object
        if isinstance(incident_time, str):
            try:
                incident_time = pd.to_datetime(incident_time)
            except:
                # Skip this incident if we can't parse its timestamp
                print(f"Warning: Could not convert timestamp for incident {incident_id}: {incident_time}")
                continue
        
        # Get latest row for status and severity
        latest_row = incident_df.iloc[-1]
        
        # Skip if the incident is outside our timeframe
        if not (time_window_start <= incident_time <= time_window_end):
            continue
        
        # Extract indicators from this incident
        combined_text = ""
        if 'Comments' in latest_row and pd.notna(latest_row['Comments']):
            try:
                comments_data = json.loads(latest_row['Comments'])
                if isinstance(comments_data, list):
                    for comment in comments_data:
                        if isinstance(comment, dict) and 'message' in comment:
                            combined_text += comment['message'] + "\n"
            except:
                combined_text += str(latest_row['Comments'])
        
        # Add title and description if available
        title_text = str(latest_row.get('Title', ''))
        description_text = str(latest_row.get('Description', ''))
        combined_text += f"{title_text}\n{description_text}"
        
        # Extract indicators
        incident_indicators = extract_security_indicators(combined_text)
        
        # Create set of indicators from this incident
        incident_iocs: Set[str] = set()
        incident_iocs.update(incident_indicators.ips)
        incident_iocs.update(incident_indicators.domains)
        incident_iocs.update(incident_indicators.file_hashes)
        
        # Check for overlap
        common_iocs = current_iocs.intersection(incident_iocs)
        
        # Add to related incidents if there are common IOCs or if it's in the timeframe
        if common_iocs or (time_window_start <= incident_time <= time_window_end):
            # Safely calculate time difference
            try:
                time_diff_days = abs((current_first_time - incident_time).days)
            except:
                time_diff_days = "unknown"
                
            related_incidents.append({
                'incident_id': incident_id,
                'detection_time': incident_time,
                'status': latest_row['Status'],
                'severity': latest_row['Severity'],
                'common_indicators': list(common_iocs),
                'time_proximity': f"{time_diff_days} days" if isinstance(time_diff_days, int) else "unknown"
            })
    
    # Sort by relevance - incidents with common IOCs first, then by time proximity
    # Only sort if we have enough related incidents and they have the required attributes
    if related_incidents:
        try:
            def sort_key(x):
                has_common_indicators = len(x['common_indicators']) > 0
                time_proximity = 0
                try:
                    if hasattr(x['detection_time'], 'days') or (isinstance(x['detection_time'], (datetime, pd.Timestamp))):
                        time_proximity = -abs((current_first_time - x['detection_time']).days)
                except:
                    pass
                return (has_common_indicators, time_proximity)
                
            related_incidents.sort(key=sort_key, reverse=True)
        except Exception as e:
            print(f"Warning: Could not sort related incidents: {str(e)}")
    
    # Limit to top 5 most relevant
    return related_incidents[:5]


def fetch_relevant_logs(start_time_iso: str, end_time_iso: str, indicators: SecurityIndicators, limit: int = 100) -> List[Dict[str, Any]]:
    """Fetch relevant logs from Azure Log Analytics (CommonSecurityLog_Enrich) based on incident indicators and time window."""
    if not AZURE_CREDS_LOADED:
        print("Skipping log fetching as Azure credentials are not loaded.")
        return []

    print(f"Attempting to fetch relevant logs from {start_time_iso} to {end_time_iso}...")

    try:
        # --- Authentication ---
        authority_url = f"https://login.microsoftonline.com/{TENANT_ID}"
        resource = "https://api.loganalytics.io"
        context = adal.AuthenticationContext(authority_url)
        token = context.acquire_token_with_client_credentials(resource, CLIENT_ID, CLIENT_SECRET)
        access_token = token.get('accessToken')
        if not access_token:
            print("Error: Failed to acquire access token.")
            return []
        # Commenting out success message for brevity during normal operation
        # print("Authentication successful!")

        # --- Build KQL Query ---
        query_parts = [
            "CommonSecurityLog_Enrich",
            f"| where TimeGenerated >= datetime('{start_time_iso}') and TimeGenerated <= datetime('{end_time_iso}')" # Use single quotes for datetime
        ]

        indicator_filters = []
        if indicators.external_ips:
            # Ensure IPs are correctly quoted for KQL 'in' operator
            ips_quoted = [f'"{ip}"' for ip in indicators.external_ips]
            ips_str = ",".join(ips_quoted)
            indicator_filters.append(f'(DestinationIP in ({ips_str}) or SourceIP in ({ips_str}))')
        
        # Combine internal and external IP checks for simplicity, looking for connections involving these IPs
        all_incident_ips = list(set(indicators.internal_ips + indicators.external_ips))
        if all_incident_ips:
            ips_quoted = [f'"{ip}"' for ip in all_incident_ips]
            ips_str = ",".join(ips_quoted)
            indicator_filters.append(f'(SourceIP in ({ips_str}) or DestinationIP in ({ips_str}))')

        if indicators.domains:
            domain_conditions = []
            for domain in indicators.domains:
                 escaped_domain = domain.replace('"', '\"').replace("'","\'") # Escape both quote types
                 # Using 'has' for substring matching in RequestURL is common for web/proxy logs
                 domain_conditions.append(f'RequestURL has \'{escaped_domain}\'')
                 # You might check other fields depending on your CSL schema, e.g., DestinationHostName
                 domain_conditions.append(f'DestinationHostName has \'{escaped_domain}\'')
            if domain_conditions:
                 indicator_filters.append(f'({" or ".join(domain_conditions)})')

        # Combine indicator filters with OR logic
        if indicator_filters:
            query_parts.append(f"| where {' or '.join(indicator_filters)}")

        query_parts.append("| order by TimeGenerated desc")
        query_parts.append(f"| take {limit}")

        query = "\n".join(query_parts)
        print(f"Executing KQL query:\n-------\n{query}\n-------")

        # --- Execute Query ---
        url = f"https://api.loganalytics.io/v1/workspaces/{WORKSPACE_ID}/query"
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        request_body = {'query': query}

        response = requests.post(url, headers=headers, json=request_body, timeout=90) # Increased timeout

        if response.status_code == 200:
            results = response.json()
            logs = []
            if 'tables' in results and results['tables']:
                table = results['tables'][0]
                if 'rows' in table:
                    column_names = [col['name'] for col in table['columns']]
                    for row in table['rows']:
                        log_entry = dict(zip(column_names, row))
                        logs.append(log_entry)
                    print(f"Successfully fetched {len(logs)} log entries.")
                    return logs
                else:
                    print("No 'rows' found in the results table.")
                    return [] # Return empty list if no rows
            else:
                print("No 'tables' data found in the API response.")
                return [] # Return empty list if no tables
        else:
            print(f"Error fetching logs: {response.status_code}")
            print(f"Error details: {response.text}")
            return [] # Return empty list on error

    except adal.AdalError as auth_err:
         print(f"Authentication Error: {str(auth_err)}")
         return []
    except requests.exceptions.Timeout as timeout_err:
        print(f"Request timed out fetching logs: {str(timeout_err)}")
        return []
    except requests.exceptions.RequestException as req_err:
        print(f"Network/Request Error fetching logs: {str(req_err)}")
        return []
    except Exception as e:
        print(f"An unexpected error occurred during log fetching: {str(e)}")
        traceback.print_exc()
        return [] # Return empty list on unexpected error


def format_log_summary(logs: List[Dict[str, Any]], limit: int = 10) -> str:
    """Format a list of log dictionaries into a readable summary table."""
    if not logs:
        return "No relevant logs found in the specified timeframe and criteria.\n"

    summary = f"Found {len(logs)} relevant log(s). Displaying top {min(len(logs), limit)}:\n\n"

    # Select key fields relevant for DNS/Network context (adjust as needed for your CommonSecurityLog schema)
    headers = [
        'TimeGenerated', 'DeviceVendor', 'Activity', 'SourceIP', 'SourceUserName',
        'DestinationIP', 'DestinationPort', 'DestinationHostName',
        'RequestURL', 'DeviceAction', 'SimplifiedDeviceAction',
        'FileName'
    ]
    # Ensure TimeGenerated is displayed first
    headers.sort(key=lambda x: 0 if x == 'TimeGenerated' else 1)

    table_data = []
    for i, log in enumerate(logs):
        if i >= limit:
            break
        row = []
        for header in headers:
            value = log.get(header, 'N/A')
            # Shorten long URLs or values if necessary
            if isinstance(value, str) and len(value) > 75:
                value = value[:72] + '...'
            # Format timestamp if it exists
            if header == 'TimeGenerated' and value != 'N/A':
                 try:
                     # Parse UTC time and convert to local
                     utc_time = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
                     value = utc_time.astimezone().strftime('%Y-%m-%d %H:%M:%S') # Local time
                 except ValueError:
                     value = str(value) # Keep original if parsing fails
            row.append(value)
        table_data.append(row)

    # Use tabulate for a clean table format
    try:
        summary += tabulate(table_data, headers=headers, tablefmt='grid')
        summary += "\n"
    except Exception as e:
        summary += f"(Error formatting logs into table: {e})\n"
        # Fallback to simple list if tabulate fails
        for i, log in enumerate(logs):
            if i >= limit:
                break
            summary += f"Log {i+1}: { {h: log.get(h, 'N/A') for h in headers} }\n"

    return summary

def summarize_user_domain_activity(logs: List[Dict[str, Any]], incident_domains: List[str]) -> str:
    """Analyze fetched logs to identify which users interacted with specific incident domains."""
    if not logs or not incident_domains:
        return "User-Domain Activity: No logs or incident domains provided for analysis.\n"

    # Normalize incident domains for easier matching (lowercase)
    incident_domains_lower = {domain.lower() for domain in incident_domains if domain}
    
    # Dictionary to store findings: {domain -> set(usernames)}
    domain_user_map = {domain: set() for domain in incident_domains_lower}
    found_activity = False

    for log in logs:
        # Extract potential domain/URL fields from the log
        log_url = log.get('RequestURL', '')
        log_dest_host = log.get('DestinationHostName', '')
        log_text = f"{log_url} {log_dest_host}".lower() # Combine and lower for searching
        
        # Extract user (prioritize SourceUserName)
        user = log.get('SourceUserName')
        # Add fallbacks if needed, e.g., log.get('UserName') or parsing other fields
        
        # Check if any incident domain is present in the log's URL/DestHost
        for domain in incident_domains_lower:
            if domain in log_text:
                found_activity = True
                if user and user != 'N/A': # Only add if user is identified
                    domain_user_map[domain].add(user)
                # Even if no user found, we know there was activity for this domain
                elif not domain_user_map[domain]: # Add a placeholder if no user found yet for this domain
                     domain_user_map[domain].add("Activity observed (User N/A)") 

    # Format the summary string
    summary_lines = ["User Activity Involving Incident Domains (from log sample):", "-----------------------------------------------------------"]
    if not found_activity:
         summary_lines.append("No specific activity involving incident domains found in the log sample.")
    else:
        for domain, users in domain_user_map.items():
            if users:
                user_str = ", ".join(sorted(list(users)))
                summary_lines.append(f"- Domain '{domain}': Associated users/activity: {{{user_str}}}")
            else:
                 # This case might occur if the domain was an indicator but no matching logs were found/processed
                 # Or if activity was seen but no user could be identified AND the placeholder wasn't added (shouldn't happen with current logic)
                 summary_lines.append(f"- Domain '{domain}': No associated user activity found in log sample.") 
                 
    return "\n".join(summary_lines) + "\n"

def analyze_comments(comments: List[str]) -> Dict[str, Any]:
    """Analyze incident comments to extract raw text and basic stats."""
    if not comments:
        return {
            "total_comments": 0,
            "raw_comments_text": "No comments available.",
            "first_comment_snippet": "",
            "last_comment_snippet": ""
        }
    
    combined_comments = "\n---\n".join(comments) # Join with separator for clarity
    first_comment = comments[0]
    last_comment = comments[-1]

    return {
        "total_comments": len(comments),
        "raw_comments_text": combined_comments,
        "first_comment_snippet": f"{first_comment[:100]}{'...' if len(first_comment) > 100 else ''}",
        "last_comment_snippet": f"{last_comment[:100]}{'...' if len(last_comment) > 100 else ''}"
    }

def create_incident_timeline(incident_data: pd.DataFrame) -> Dict[str, Any]:
    """Create a comprehensive timeline of incident changes"""
    
    # Sort data by timestamp to ensure chronological order
    incident_data = incident_data.sort_values('LastModifiedTime')
    
    # Get first and last rows
    first_row = incident_data.iloc[0]
    last_row = incident_data.iloc[-1]
    
    # Extract initial and current states
    incident_number = str(first_row['IncidentNumber'])
    first_detected = first_row['LastModifiedTime']
    first_status = first_row['Status']
    first_severity = first_row['Severity']
    current_status = last_row['Status']
    current_severity = last_row['Severity']
    
    # Create a detailed timeline of key changes
    key_milestones = []
    previous_row = None
    
    for idx, row in incident_data.iterrows():
        milestone = {
            'timestamp': row['LastModifiedTime'],
            'changes': []
        }
        
        if previous_row is not None:
            # Check for key field changes
            if row['Status'] != previous_row['Status']:
                milestone['changes'].append({
                    'field': 'Status',
                    'from': previous_row['Status'],
                    'to': row['Status']
                })
            
            if row['Severity'] != previous_row['Severity']:
                milestone['changes'].append({
                    'field': 'Severity',
                    'from': previous_row['Severity'],
                    'to': row['Severity']
                })
            
            if str(row['Owner']) != str(previous_row['Owner']):
                try:
                    new_owner = json.loads(row['Owner']) if isinstance(row['Owner'], str) else row['Owner']
                    previous_owner = json.loads(previous_row['Owner']) if isinstance(previous_row['Owner'], str) else previous_row['Owner']
                    
                    new_owner_name = new_owner.get('assignedTo', 'Unknown')
                    previous_owner_name = previous_owner.get('assignedTo', 'Unassigned')
                    
                    milestone['changes'].append({
                        'field': 'Owner',
                        'from': previous_owner_name,
                        'to': new_owner_name
                    })
                except:
                    milestone['changes'].append({
                        'field': 'Owner',
                        'from': str(previous_row['Owner']),
                        'to': str(row['Owner'])
                    })
            
            # Check for new comments
            if 'Comments' in row and 'Comments' in previous_row:
                try:
                    current_comments = json.loads(row['Comments']) if isinstance(row['Comments'], str) else row['Comments']
                    previous_comments = json.loads(previous_row['Comments']) if isinstance(previous_row['Comments'], str) else previous_row['Comments']
                    
                    if len(current_comments) > len(previous_comments):
                        # New comments were added
                        new_comment_count = len(current_comments) - len(previous_comments)
                        milestone['changes'].append({
                            'field': 'Comments',
                            'action': f'Added {new_comment_count} new comment(s)',
                            'summary': current_comments[-1].get('message', '')[:100] + '...' if len(current_comments) > 0 and len(current_comments[-1].get('message', '')) > 100 else ''
                        })
                except:
                    pass
        else:
            # This is the first entry - incident creation
            milestone['changes'].append({
                'field': 'Incident',
                'action': 'Created',
                'status': row['Status'],
                'severity': row['Severity']
            })
        
        if milestone['changes']:
            key_milestones.append(milestone)
        
        previous_row = row
    
    # Calculate response metrics
    triage_time = None
    resolution_time = None
    
    # Find first assignment milestone
    assignment_milestone = None
    for milestone in key_milestones:
        for change in milestone['changes']:
            if change.get('field') == 'Owner' and change.get('from') == 'Unassigned':
                assignment_milestone = milestone
                triage_time = (assignment_milestone['timestamp'] - first_detected).total_seconds() / 60  # minutes
                break
        if assignment_milestone:
            break
    
    # Check if incident was resolved
    if current_status in ['Closed', 'Resolved']:
        resolution_time = (last_row['LastModifiedTime'] - first_detected).total_seconds() / 3600  # hours
    
    # Create a summary of the timeline
    summary = f"Incident #{incident_number} was first detected on {first_detected} with {first_severity} severity and {first_status} status."
    
    if assignment_milestone:
        summary += f" Assigned after approximately {triage_time:.1f} minutes."
    
    if resolution_time:
        summary += f" Resolved in {resolution_time:.1f} hours."
    else:
        summary += f" Currently in {current_status} status with {current_severity} severity."
    
    summary += f" The incident had {len(key_milestones)} key updates."
    
    return {
        'incident_number': incident_number,
        'first_detected': first_detected,
        'first_status': first_status,
        'first_severity': first_severity,
        'current_status': current_status,
        'current_severity': current_severity,
        'total_updates': len(key_milestones),
        'key_milestones': key_milestones,
        'summary': summary,
        'triage_time_minutes': triage_time,
        'resolution_time_hours': resolution_time
    }

def format_incident_timeline(timeline: Dict[str, Any]) -> str:
    """Format timeline for display"""
    formatted = f"""INCIDENT TIMELINE ANALYSIS
========================

{timeline['summary']}

KEY MILESTONES:
"""
    
    for idx, milestone in enumerate(timeline['key_milestones'], 1):
        formatted += f"\n[{milestone['timestamp']}]\n"
        
        for change in milestone['changes']:
            if 'action' in change:
                if change['field'] == 'Incident':
                    formatted += f"• Incident Created (Status: {change['status']}, Severity: {change['severity']})\n"
                else:
                    formatted += f"• {change['action']}\n"
                    if 'summary' in change and change['summary']:
                        formatted += f"  Comment summary: {change['summary']}\n"
            else:
                formatted += f"• {change['field']} changed: {change['from']} -> {change['to']}\n"
    
    # Add response time metrics if available
    if timeline.get('triage_time_minutes'):
        formatted += f"\nTRIAGE METRICS:\n• Time to triage: {timeline['triage_time_minutes']:.1f} minutes\n"
        
    if timeline.get('resolution_time_hours'):
        formatted += f"• Time to resolution: {timeline['resolution_time_hours']:.1f} hours\n"
    
    return formatted

def analyze_incident_context(incident_data: pd.DataFrame, all_incidents: Dict[str, pd.DataFrame] = None) -> str:
    """Analyze incident data, fetch relevant logs, and provide context using an LLM."""

    # Sort data by timestamp to ensure chronological order
    incident_data = incident_data.sort_values('LastModifiedTime')

    # Get first and last rows
    first_row = incident_data.iloc[0]
    last_row = incident_data.iloc[-1]

    # Ensure timestamps are timezone-aware (assuming UTC)
    try:
        # Process first_detected_dt
        timestamp_input_first = first_row['LastModifiedTime']
        dt_first = pd.to_datetime(timestamp_input_first)
        if dt_first.tzinfo is None:
            # Timestamp is naive, localize to UTC
            first_detected_dt = dt_first.tz_localize('UTC')
            print(f"Debug: Localized naive first_detected timestamp: {timestamp_input_first}")
        else:
            # Timestamp is already tz-aware, convert to UTC to be sure
            first_detected_dt = dt_first.tz_convert('UTC')
            print(f"Debug: Converted tz-aware first_detected timestamp: {timestamp_input_first}")

        # Process last_updated_dt
        timestamp_input_last = last_row['LastModifiedTime']
        dt_last = pd.to_datetime(timestamp_input_last)
        if dt_last.tzinfo is None:
            # Timestamp is naive, localize to UTC
            last_updated_dt = dt_last.tz_localize('UTC')
            print(f"Debug: Localized naive last_updated timestamp: {timestamp_input_last}")
        else:
            # Timestamp is already tz-aware, convert to UTC
            last_updated_dt = dt_last.tz_convert('UTC')
            print(f"Debug: Converted tz-aware last_updated timestamp: {timestamp_input_last}")

    except Exception as e:
        print(f"Error converting incident timestamps: {e}. Log fetching might use incorrect window.")
        # Fallback or handle error appropriately - using current time as a rough fallback
        first_detected_dt = pd.Timestamp.now(tz='UTC') - timedelta(hours=1)
        last_updated_dt = pd.Timestamp.now(tz='UTC')

    first_detected_str = first_detected_dt.strftime('%Y-%m-%d %H:%M:%S %Z')
    last_updated_str = last_updated_dt.strftime('%Y-%m-%d %H:%M:%S %Z')

    # Extract key information for analysis
    incident_number = str(first_row['IncidentNumber'])
    tenant_id = first_row['TenantId']

    # Extract comments
    comments = []
    if 'Comments' in last_row and pd.notna(last_row['Comments']):
        try:
            comments_data = json.loads(last_row['Comments'])
            # Handle cases where comments_data might be a list of dicts or just a string
            if isinstance(comments_data, list):
                for comment in comments_data:
                    if isinstance(comment, dict) and 'message' in comment:
                        comments.append(comment['message'])
            elif isinstance(comments_data, str):
                 comments.append(comments_data) # Assume it's a single comment string if not list
        except json.JSONDecodeError:
            # Handle cases where comments column is a plain string not in JSON format
            comments = [str(last_row['Comments'])]
        except Exception as e:
             print(f"Error processing comments for incident {incident_number}: {e}")
             comments = [str(last_row['Comments'])] # Fallback to raw string

    # Extract entities from comments and title/description
    comments_text = "\n".join(comments)
    title_text = str(last_row.get('Title', ''))
    description_text = str(last_row.get('Description', ''))
    combined_text = f"{title_text}\n{description_text}\n{comments_text}"
    
    # Get enhanced security indicators
    indicators = extract_security_indicators(combined_text)
    
    # --- Fetch Relevant Logs ---
    fetched_logs = fetch_relevant_logs(first_detected_dt.strftime('%Y-%m-%dT%H:%M:%SZ'), last_updated_dt.strftime('%Y-%m-%dT%H:%M:%SZ'), indicators, limit=100)
    log_summary = format_log_summary(fetched_logs, limit=10) # Display top 10 in summary table
    # --- Analyze User-Domain Activity --- 
    user_domain_summary = summarize_user_domain_activity(fetched_logs, indicators.domains)
    # --- End Log Fetching & User Analysis ---
    
    # Check domain reputation with VirusTotal if available
    vt_results_text = "VirusTotal integration not available."
    if indicators.domains:
        print(f"Extracted domains from incident: {indicators.domains}")
        if not VIRUSTOTAL_AVAILABLE:
            raise RuntimeError("VirusTotal integration is required but not available. Please ensure the API key and module are set up.")
        try:
            print(f"Checking {len(indicators.domains)} domains with VirusTotal...")
            vt_results = analyze_domains(indicators.domains)
            print(f"VirusTotal API called for domains: {list(vt_results.keys())}")
            if vt_results:
                vt_results_text = format_vt_results(vt_results)
            else:
                vt_results_text = "No suspicious domains found or VirusTotal check failed."
        except Exception as e:
            print(f"Error checking domains with VirusTotal: {str(e)}")
            vt_results_text = f"Error checking domains with VirusTotal: {str(e)}"
    
    # Analyze comments for investigation progression
    comment_analysis = analyze_comments(comments)

    # --- Summarize Comments with LLM ---
    llm_comment_summary = "No comments to summarize or LLM summarization failed."
    if comment_analysis["total_comments"] > 0:
        print(f"Attempting to summarize {comment_analysis['total_comments']} comments using LLM...")
        try:
            comment_summary_prompt = (
                f"You are a helpful assistant summarizing investigation notes. "
                f"Please read the following sequence of comments related to a security incident. "
                f"Provide a concise summary (2-4 sentences) focusing on the key actions taken by analysts, significant findings, and the overall progression or status reflected in these comments. "
                f"Base your summary ONLY on the text provided.\n\n"
                f"Comments (separated by '---'):\n"
                f"------------------------------------\n"
                f"{comment_analysis['raw_comments_text']}\n"
                f"------------------------------------\n"
                f"Concise Summary:"
            )
            
            # Reuse the existing Ollama client
            client = ollama.Client(host=OLLAMA_API_BASE)
            response = client.chat(
                model=OLLAMA_MODEL,
                messages=[{"role": "user", "content": comment_summary_prompt}],
                stream=False # No streaming needed for short summary
                # No format='json' needed here, we want plain text
            )
            llm_comment_summary = response['message']['content'].strip()
            print("LLM comment summary generated successfully.")
        except Exception as llm_err:
            print(f"Error summarizing comments with LLM: {llm_err}")
            llm_comment_summary = f"Error during LLM comment summarization: {llm_err}" # Include error in summary
    # --- End LLM Comment Summarization ---

    # Calculate response metrics
    timeline = create_incident_timeline(incident_data)
    
    # Find related incidents if we have access to all incidents
    related_incidents = []
    if all_incidents:
        related_incidents = find_related_incidents(all_incidents, incident_data, indicators)
    
    # Format related incidents information
    related_incidents_text = ""
    if related_incidents:
        related_incidents_text = "Related Incidents:\n"
        for rel in related_incidents:
            common_iocs = ', '.join(rel['common_indicators']) if rel['common_indicators'] else 'None'
            related_incidents_text += (f"- Incident #{rel['incident_id']} ({rel['severity']} severity, {rel['status']}), "
                                      f"detected {rel['time_proximity']} from this incident\n")
            if rel['common_indicators']:
                related_incidents_text += f"  Common indicators: {common_iocs}\n"
    
    # Extract MITRE ATT&CK techniques from comments if mentioned
    mitre_pattern = r'(?:T|t)(?:\d{4})(?:\.\d{3})?'
    potential_techniques = re.findall(mitre_pattern, combined_text)
    
    # Add any CVEs to the incident info as they might be relevant
    cve_info = ""
    if indicators.cves:
        cve_info = f"CVEs Detected: {', '.join(indicators.cves)}\n"
        
    # Prepare information for the LLM
    incident_info = (
        f"Incident Number: {incident_number}\n"
        f"Tenant ID: {tenant_id}\n"
        f"Title: {title_text}\n"
        f"Description: {description_text}\n"
        f"Current Status: {last_row['Status']} (Initial: {first_row['Status']})\n"
        f"Current Severity: {last_row['Severity']} (Initial: {first_row['Severity']})\n"
        f"First Detected: {first_detected_str}\n"
        f"Last Updated: {last_updated_str}\n"
        f"Total Updates: {len(incident_data)}\n"
        f"Time to Triage: {timeline.get('triage_time_minutes', 'Unknown')} minutes\n"
        f"Time to Resolution: {timeline.get('resolution_time_hours', 'Unknown')} hours\n"
        f"Internal IPs: {', '.join(indicators.internal_ips) if indicators.internal_ips else 'None'}\n"
        f"External IPs: {', '.join(indicators.external_ips) if indicators.external_ips else 'None'}\n"
        f"Domains: {', '.join(indicators.domains) if indicators.domains else 'None'}\n"
        f"Domain Reputation: {'Suspicious domains detected - see VirusTotal results' if VIRUSTOTAL_AVAILABLE and indicators.domains else 'Not checked'}\n"
        f"URLs: {', '.join(indicators.urls) if indicators.urls else 'None'}\n"
        f"File Hashes: {', '.join(indicators.file_hashes) if indicators.file_hashes else 'None'}\n"
        f"{cve_info}"
        f"User Accounts: {', '.join(indicators.users) if indicators.users else 'None'}\n"
        f"Process Names: {', '.join(indicators.processes) if indicators.processes else 'None'}\n"
        f"Potential MITRE ATT&CK techniques mentioned: {', '.join(potential_techniques) if potential_techniques else 'None'}\n"
        f"{related_incidents_text}\n"
        f"VirusTotal Domain Analysis: {vt_results_text if len(vt_results_text) < 300 else 'Available - see full report'}\n\n"
        f"Comments:\n{comments_text if comments_text else 'No comments available.'}"
    )

    # Construct the prompt for the LLM
    prompt = (
        f"You are an experienced L1 SOC analyst reviewing security incidents. Your task is to provide preliminary analysis and triage recommendations.\n\n"
        f"Analyze the following security incident data AND the provided sample of relevant raw logs. "
        f"Focus on correlating information between the incident details and the logs. Identify key events observed in the logs (e.g., specific connections, actions, source/destination details related to the incident indicators). "
        f"Provide a structured analysis covering threat details (explain WHAT activity was observed in logs/data), significance (justify the level based on evidence), potential MITRE ATT&CK techniques (justify linkage to evidence), potential impact (what could happen if malicious), recommended immediate actions for L1, and severity assessment. "
        f"Be specific about what happened, who was targeted, what systems were involved, and what the attacker was trying to accomplish based ONLY on the provided information (incident data AND logs).\n\n"
        f"Pay special attention to the VirusTotal domain analysis results AND the raw log sample for corroborating evidence or additional context.\n\n"
        f"Incident Data:\n"
        f"--------------\n"
        f"{incident_info}\n"
        f"--------------\n\n"
        f"Relevant Raw Log Sample (Consider this evidence!):\n"
        f"-----------------------------------------------\n"
        f"{log_summary}\n"
        f"{user_domain_summary}\n"
        f"-----------------------------------------------\n\n"
        f"Think like a security analyst: What is the likely threat? How severe is it? What immediate actions should be taken? What additional information is needed? How time-sensitive is the response needed? \n"
        f"**Crucially, justify your analysis, recommended actions, and next steps by referencing specific, relevant details observed in the 'Relevant Raw Log Sample' whenever possible.** Generic recommendations are less helpful than those grounded in observed evidence. For example, if recommending a block, specify WHAT should be blocked (IP, URL, etc.) based on the log evidence. If suggesting investigation, mention WHICH user, host, or activity from the logs requires scrutiny.\n\n"
        f"When identifying MITRE ATT&CK techniques, please provide technique IDs like T1566 (Phishing) where applicable. For each technique you identify, provide a 'technique_details' dictionary with name, tactic, description and mitigation information for that technique - this is crucial as your information will be used directly in the report. Also, briefly explain WHY you chose each technique based on the incident data or logs.\n\n"
        f"Provide the analysis as a JSON object with keys: 'threat_details', 'significance', 'recommended_actions' (as a list of actionable, evidence-based strings), 'summary', 'attack_techniques' (as a list of strings like 'T1566', 'T1078'), 'technique_details' (as a nested dictionary with technique IDs as keys and details dictionaries as values), 'severity_assessment', 'next_steps_for_l1' (as a list of actionable, evidence-based strings), 'time_sensitivity' (how urgent this incident is), 'incident_type' (classification of incident - e.g. malware, phishing, unauthorized access), and 'potential_impact' (brief assessment of potential consequences)."
    )

    analysis_content = "Analysis could not be generated."
    try:
        print(f"\nAttempting to generate analysis for Incident #{incident_number} using Ollama model {OLLAMA_MODEL} with JSON format enforced...")

        # Configure ollama client with the right base URL
        client = ollama.Client(host=OLLAMA_API_BASE)

        # Make the API call to Ollama, enforcing JSON output
        response = client.chat(
            model=OLLAMA_MODEL,
            messages=[{"role": "user", "content": prompt}],
            stream=False,
            format='json'
        )

        # Extract the response content (should be JSON string)
        json_str = response['message']['content']
        print(f"Response received from model. Parsing JSON...")

        # Parse the JSON string (remove regex fallback)
        try:
            analysis_result = json.loads(json_str)

            # --- Pre-validation Type Conversion and Defaulting ---
            # 1. Convert unexpected simple types (int, float) from LLM to string for fields expecting str or dict
            fields_to_convert = [
                'threat_details', 'significance', 'summary', 
                'severity_assessment', 'time_sensitivity', 'incident_type',
                'potential_impact'
            ]
            for field in fields_to_convert:
                if field in analysis_result:
                    value = analysis_result[field]
                    if isinstance(value, (int, float, bool)) or value is None:
                         print(f"Warning: Converting LLM output field '{field}' from type {type(value).__name__} to string.")
                         analysis_result[field] = str(value)
            
            # 2. Add default values for required fields if missing from LLM response
            required_fields_defaults = {
                "threat_details": "Not Provided",
                "significance": "Not Provided",
                "recommended_actions": [],
                "summary": "Not Provided",
                "attack_techniques": [],
                "severity_assessment": "Not Provided",
                "next_steps_for_l1": [],
                "time_sensitivity": "Not Provided",
                "incident_type": "Unclassified",
                "potential_impact": "Not assessed"
            }
            for field, default_value in required_fields_defaults.items():
                if field not in analysis_result:
                    print(f"Warning: Required field '{field}' missing from LLM response. Using default value: {default_value}")
                    analysis_result[field] = default_value
            
            # 3. Ensure list fields are actually lists if they exist but are wrong type (e.g., string)
            list_fields = ['recommended_actions', 'attack_techniques', 'next_steps_for_l1']
            for field in list_fields:
                 if field in analysis_result and not isinstance(analysis_result[field], list):
                     print(f"Warning: Field '{field}' expected a list but got {type(analysis_result[field]).__name__}. Attempting correction or defaulting to empty list.")
                     # Attempt basic correction if it's a string that looks like a list (optional, can be risky)
                     # Simple default: analysis_result[field] = []
                     if isinstance(analysis_result[field], str):
                         # Basic check for list-like string, more robust parsing might be needed
                         if analysis_result[field].startswith('[') and analysis_result[field].endswith(']'):
                             try:
                                 # Attempt to parse string as JSON list
                                 potential_list = json.loads(analysis_result[field].replace("'", '"')) # Replace single with double quotes
                                 if isinstance(potential_list, list):
                                     analysis_result[field] = potential_list
                                 else:
                                     analysis_result[field] = [] # Default if not a list after parsing
                             except json.JSONDecodeError:
                                 analysis_result[field] = [] # Default if parsing fails
                         else:
                              analysis_result[field] = [] # Default if not list-like string
                     else:
                         analysis_result[field] = [] # Default if not a string or list

            # --- End Pre-validation ---

        except json.JSONDecodeError as e:
            print(f"Failed to decode JSON response even with format='json': {e}")
            print(f"Raw response content:\n{json_str}")
            raise ValueError("Ollama response was not valid JSON despite format='json' instruction")

        # Validate against our Pydantic model
        validated_result = IncidentAnalysisOutput(**analysis_result)
        print(f"Analysis generated successfully for Incident #{incident_number}.")

        # Get MITRE ATT&CK information if techniques were identified
        mitre_info = ""
        if validated_result.attack_techniques:
            mitre_info = get_mitre_attack_info(validated_result.attack_techniques, validated_result.technique_details)

        # Format threat_details based on its type (string or dict)
        threat_details_formatted = ""
        if isinstance(validated_result.threat_details, dict):
            # Simple formatting for a dict - convert key-value pairs to string
            threat_details_formatted = "\n".join([f"  - {k}: {v}" for k, v in validated_result.threat_details.items()])
        else:
            # Assume it's a string if not a dict
            threat_details_formatted = validated_result.threat_details
            
        # Format significance based on its type (string or dict)
        significance_formatted = ""
        if isinstance(validated_result.significance, dict):
            significance_formatted = "\n".join([f"  - {k}: {v}" for k, v in validated_result.significance.items()])
        else:
            significance_formatted = validated_result.significance
            
        # Get incident type for playbook reference
        if isinstance(validated_result.incident_type, dict):
            incident_type = validated_result.incident_type.get('name', "suspicious_activity")
        else:
            incident_type = validated_result.incident_type or "suspicious_activity"
            
        playbook_reference = get_playbook_reference(incident_type)
            
        # Format severity assessment based on type
        severity_assessment_formatted = ""
        if isinstance(validated_result.severity_assessment, dict):
            severity_assessment_formatted = ", ".join([f"{k}: {v}" for k, v in validated_result.severity_assessment.items()])
        else:
            severity_assessment_formatted = validated_result.severity_assessment or "Not provided"
            
        # Format time sensitivity based on type
        time_sensitivity_formatted = ""
        if isinstance(validated_result.time_sensitivity, dict):
            time_sensitivity_formatted = ", ".join([f"{k}: {v}" for k, v in validated_result.time_sensitivity.items()])
        else:
            time_sensitivity_formatted = validated_result.time_sensitivity or "Not specified"
            
        # Format incident_type based on its type
        incident_type_formatted = ""
        if isinstance(validated_result.incident_type, dict):
            incident_type_formatted = validated_result.incident_type.get('name', 'Unclassified')
        else:
            incident_type_formatted = validated_result.incident_type or 'Unclassified'
        
        # Quick assessment section with time sensitivity and domain reputation
        quick_assessment = (
            f"QUICK ASSESSMENT:\n"
            f"Incident Type: {incident_type_formatted}\n"
            f"Severity Assessment: {severity_assessment_formatted}\n"
            f"Time Sensitivity: {time_sensitivity_formatted}\n"
            f"Potential TTPs: {', '.join(validated_result.attack_techniques) if validated_result.attack_techniques else 'None identified'}\n"
        )

        # Add domain reputation summary to the quick assessment if available
        if VIRUSTOTAL_AVAILABLE and indicators.domains:
            quick_assessment += f"Domain Reputation: {'Suspicious domains detected - see VT analysis section' if 'HIGH RISK' in vt_results_text or 'MEDIUM RISK' in vt_results_text else 'No high-risk domains identified'}\n"

        # Format summary based on its type
        summary_formatted = ""
        if isinstance(validated_result.summary, dict):
            # Try common keys, otherwise convert dict to string
            summary_formatted = validated_result.summary.get('summary', 
                                validated_result.summary.get('description', 
                                validated_result.summary.get('content', str(validated_result.summary))))
        else:
            summary_formatted = validated_result.summary
            
        # Format L1 next steps section
        l1_steps = ""
        if validated_result.next_steps_for_l1:
            l1_steps = "L1 ANALYST NEXT STEPS:\n" + "\n".join([f"* {step}" for step in validated_result.next_steps_for_l1]) + "\n\n"

        analysis_content = (
            f"{quick_assessment}\n\n"
            f"THREAT DETAILS:\n* {threat_details_formatted}\n\n"
            f"SIGNIFICANCE:\n* {significance_formatted}\n\n"
            f"POTENTIAL IMPACT:\n* {validated_result.potential_impact or 'Not assessed'}\n\n"
            f"RECOMMENDED ACTIONS:\n" +
            "\n".join([f"* {action}" for action in validated_result.recommended_actions]) + "\n\n" +
            f"{l1_steps}" +
            f"SUMMARY:\n{summary_formatted}\n\n"
        )
        
        # Add MITRE ATT&CK information if available
        if mitre_info:
            analysis_content += f"{mitre_info}\n"
            
        # Add playbook reference
        analysis_content += f"{playbook_reference}"

        # --- ADD VIRUSTOTAL RESULTS TO L1 TRIAGE REPORT ---
        if VIRUSTOTAL_AVAILABLE and indicators.domains:
            analysis_content += (
                f"\nVIRUSTOTAL DOMAIN REPUTATION:\n"
                f"----------------------------\n"
                f"{vt_results_text}\n"
            )

    except Exception as e:
        print(f"\nError generating analysis with LLM for incident {incident_number}: {e}")
        traceback.print_exc() # Print full traceback for debugging LLM errors
        analysis_content = f"Error during AI analysis generation: {e}\nUsing generic analysis based on available data.\n\n"
        # Fallback to a simpler analysis if LLM fails
        analysis_content += (
             f"Based on the available data, this security incident is currently {last_row['Status']} with "
             f"{last_row['Severity']} severity. It was first detected on {first_detected_str} "
             f"and last updated on {last_updated_str}.\n\n"
             f"Detected Security Indicators:\n"
             f"Internal IPs: {', '.join(indicators.internal_ips) if indicators.internal_ips else 'None'}\n"
             f"External IPs: {', '.join(indicators.external_ips) if indicators.external_ips else 'None'}\n"
             f"Domains: {', '.join(indicators.domains) if indicators.domains else 'None'}\n"
        )
        
        # Add VirusTotal results to the fallback analysis if available
        if VIRUSTOTAL_AVAILABLE and 'HIGH RISK' in vt_results_text:
            analysis_content += f"\nWARNING: VirusTotal detected HIGH RISK domains - see detailed analysis section\n\n"
        
        analysis_content += (
             f"URLs: {', '.join(indicators.urls) if indicators.urls else 'None'}\n"
             f"File Hashes: {', '.join(indicators.file_hashes) if indicators.file_hashes else 'None'}\n"
             f"CVEs: {', '.join(indicators.cves) if indicators.cves else 'None'}\n\n"
             f"Further investigation is needed.\n\n" +
             get_playbook_reference("suspicious_activity")
        )

    # Generate the final analysis string including the base summary and the AI part
    analysis = (
        f"INCIDENT SUMMARY:\n"
        f"----------------\n"
        f"Incident #{incident_number} detected from TenantID {tenant_id}\n"
        f"Current Status: {last_row['Status']} (initially {first_row['Status']})\n"
        f"Current Severity: {last_row['Severity']} (initially {first_row['Severity']})\n"
        f"First Detected: {first_detected_str}\n"
        f"Last Updated: {last_updated_str}\n"
        f"Number of Updates: {len(incident_data)}\n\n"
        f"DETECTED SECURITY INDICATORS:\n"
        f"--------------------------\n"
        f"Internal IPs: {', '.join(indicators.internal_ips) if indicators.internal_ips else 'None identified'}\n"
        f"External IPs: {', '.join(indicators.external_ips) if indicators.external_ips else 'None identified'}\n"
        f"Domains: {', '.join(indicators.domains) if indicators.domains else 'None identified'}\n"
        f"URLs: {', '.join(indicators.urls) if indicators.urls else 'None identified'}\n"
        f"File Hashes: {', '.join(indicators.file_hashes) if indicators.file_hashes else 'None identified'}\n"
        f"CVEs: {', '.join(indicators.cves) if indicators.cves else 'None identified'}\n"
        f"User Accounts: {', '.join(indicators.users) if indicators.users else 'None identified'}\n"
        f"Process Names: {', '.join(indicators.processes) if indicators.processes else 'None identified'}\n\n"
    )
    
    # Add Raw Log Summary section
    analysis += (
        f"RELEVANT RAW LOGS (Sample from {first_detected_dt.strftime('%Y-%m-%dT%H:%M:%SZ')} to {last_updated_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}):\n"
        f"--------------------------------------------------------\n"
        f"{log_summary}\n"
        f"{user_domain_summary}\n"
    )

    # Add VirusTotal results section
    if VIRUSTOTAL_AVAILABLE and indicators.domains:
        analysis += (
            f"VIRUSTOTAL DOMAIN REPUTATION:\n"
            f"----------------------------\n"
            f"{vt_results_text}\n\n"
        )
    
    # Add related incidents section if available
    if related_incidents:
        analysis += (
            f"RELATED INCIDENTS:\n"
            f"------------------\n"
            f"{related_incidents_text}\n"
        )
    
    # Add comment analysis and progression section
    analysis += (
        f"INVESTIGATION CONTEXT (Based on Comments):\n"
        f"-----------------------------------------\n"
        f"Total Comments: {comment_analysis['total_comments']}\n"
        f"LLM Summary: {llm_comment_summary}\n\n"
        f"SOC ANALYST L1 TRIAGE REPORT:\n"
        f"--------------------------------\n"
        f"{analysis_content}"
    )

    return analysis

def analyze_security_incidents(excel_path: str, tenant_id: str = None) -> None:
    """Main function to analyze security incidents and their changes"""
    try:
        print(f"Reading Excel file: {excel_path}")
        df = pd.read_excel(excel_path)
        print(f"Successfully loaded the Excel file. Shape: {df.shape}")
        
        if tenant_id:
            df = df[df['TenantId'] == tenant_id]
            print(f"Filtered by tenant_id. Remaining rows: {len(df)}")
        
        # Sort by LastModifiedTime
        df = df.sort_values('LastModifiedTime')
        
        # Group by IncidentNumber
        incident_groups = df.groupby('IncidentNumber')
        print(f"Found {len(incident_groups)} unique incidents")
        
        # Create a dictionary of all incident groups for cross-reference
        all_incidents = {str(incident_id): group for incident_id, group in incident_groups}
        
        # Analyze each incident
        for incident_number, group in incident_groups:
            print(f"\nAnalyzing incident: {incident_number}")
            print("="*100)
            print(f"SECURITY INCIDENT ANALYSIS - #{incident_number}")
            print("="*100)
            
            try:
                # Create timeline analysis
                timeline = create_incident_timeline(group)
                formatted_timeline = format_incident_timeline(timeline)
                print(f"\n{formatted_timeline}")
                
                # Get contextual analysis with access to all incidents for cross-reference
                context_analysis = analyze_incident_context(group, all_incidents)
                print("\nSOC ANALYST L1 TRIAGE REPORT:") # Updated title
                print("="*35) # Adjusted length
                print(context_analysis)
                print("\n" + "="*100)
                
                # Save analysis to file
                report_time = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = f"incident_analysis_{incident_number}_{report_time}.txt"
                
                try:
                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write(f"SECURITY INCIDENT ANALYSIS - #{incident_number}\n")
                        f.write("="*100 + "\n\n")
                        f.write(formatted_timeline + "\n\n")
                        f.write("SOC ANALYST L1 TRIAGE REPORT:\n") # Updated title in file
                        f.write("="*35 + "\n") # Adjusted length in file
                        f.write(context_analysis + "\n\n")
                        f.write("="*100 + "\n")
                    
                    print(f"\nAnalysis saved to: {output_path}")
                except Exception as e:
                    print(f"Error saving report: {str(e)}")
                
                # Ask if user wants to see raw data
                user_input = input("\nWould you like to see the raw incident data? (y/n): ")
                if user_input.lower() == 'y':
                    print("\nRAW INCIDENT DATA:")
                    print("-" * 20)
                    for idx, row in group.iterrows():
                        print(f"\nEntry {idx+1}:")
                        print(f"Timestamp: {row['LastModifiedTime']}")
                        print(f"Status: {row['Status']}")
                        print(f"Severity: {row['Severity']}")
                        print("-" * 40)
            
            except Exception as e:
                print(f"Error analyzing incident {incident_number}: {str(e)}")
                traceback.print_exc()
            
    except Exception as e:
        print(f"Error analyzing security incidents: {str(e)}")
        traceback.print_exc()

if __name__ == "__main__":
    excel_path = os.path.join('03 extracted data', 'data_15aprl', 'security_incidents_20250415_124725.xlsx')
    # Make sure Ollama server is running before executing this script
    analyze_security_incidents(excel_path) 