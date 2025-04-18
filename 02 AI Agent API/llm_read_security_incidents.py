import pandas as pd
import os
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Union, Set, Callable, TypeVar, cast
import re
import traceback
import ollama  # Using ollama client directly
from pydantic import BaseModel, Field, field_validator, model_validator, ValidationInfo
import requests  # Added for API calls
import adal      # Added for Azure AD Authentication
from dotenv import load_dotenv # Added for environment variables
from tabulate import tabulate # Added for formatting log output
import pydantic
import argparse
import sys

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

# Using LLM at runtime to fetch MITRE ATT&CK technique information instead of hardcoding

class IncidentAnalysisOutput(BaseModel):
    # Add new fields for enhanced report
    executive_summary: str = Field(default="", description="A 2-3 sentence executive summary of incident criticality, impact, and required actions")
    severity_indicator: str = Field(default="Medium", description="Simple severity indicator (Critical/High/Medium/Low)")
    correlation_matrix: Dict[str, List[Dict[str, Any]]] = Field(default_factory=dict, description="Matrix showing which logs directly support incident findings")
    attack_chain: List[Dict[str, Any]] = Field(default_factory=list, description="Chronological reconstruction of attack with MITRE mapping")
    risk_score: Dict[str, Any] = Field(default_factory=dict, description="Standardized risk assessment combining threat, asset value, and exposure")
    business_impact: Dict[str, Any] = Field(default_factory=dict, description="Assessment of business impact based on affected systems")
    # New fields for further enhancements
    metrics_panel: Dict[str, Any] = Field(default_factory=dict, description="At‑a‑glance metrics panel with critical stats for executive dashboard")
    threat_intel_context: Union[str, Dict[str, Any]] = Field(default="Not provided", description="Known threat actor associations and campaign information")
    asset_impact_analysis: Union[str, Dict[str, Any]] = Field(default="Not provided", description="Impacted business units, systems, and data types")
    historical_context: Union[str, Dict[str, Any]] = Field(default="Not provided", description="Previous incidents with same indicators or techniques")
    
    # Existing fields with default values to prevent missing field errors
    threat_details: Union[str, Dict[str, Any]] = Field(default="Not provided", description="Details about the identified threat")
    significance: Union[str, Dict[str, Any]] = Field(default="Not provided", description="Significance of the findings")
    recommended_actions: List[str] = Field(default_factory=list, description="Recommended actions to take")
    summary: Union[str, Dict[str, Any]] = Field(default="Not provided", description="Summary of the incident")
    attack_techniques: List[str] = Field(default_factory=list, description="MITRE ATT&CK techniques identified")
    technique_details: Dict[str, Dict[str, str]] = Field(default_factory=dict, description="Details about identified MITRE ATT&CK techniques")
    severity_assessment: Union[str, Dict[str, Any]] = Field(default="Not provided", description="Assessment of the incident severity")
    next_steps_for_l1: List[str] = Field(default_factory=list, description="Next steps for L1 analyst")
    time_sensitivity: Union[str, Dict[str, Any]] = Field(default="Not provided", description="Time sensitivity of the incident")
    incident_type: Union[str, Dict[str, Any]] = Field(default="Unknown", description="Type of security incident")
    potential_impact: Union[str, Dict[str, Any]] = Field(default="Not assessed", description="Potential impact of the incident")
    
    @model_validator(mode='before')
    @classmethod
    def validate_and_transform_input(cls, data: Any) -> Dict[str, Any]:
        """Validates and transforms the input data to match the expected format."""
        if not isinstance(data, dict):
            return data
        
        # Make a copy of the data to avoid modifying the original
        transformed_data = data.copy()
        
        # Helper function to convert lists to either string or dict
        def fix_list_format(field_name, list_value):
            if not list_value:
                return "Not provided"
            
            # If list contains dictionaries, convert to a single dictionary
            if all(isinstance(item, dict) for item in list_value):
                return list_value[0] if len(list_value) == 1 else {f"item_{i}": item for i, item in enumerate(list_value)}
            
            # If list contains strings, join them
            if all(isinstance(item, str) for item in list_value):
                return ", ".join(list_value)
                
            # Default: convert to string representation
            return str(list_value)
        
        # Fields that expect Union[str, Dict[str, Any]]
        union_fields = [
            'threat_intel_context', 'asset_impact_analysis', 'historical_context', 
            'threat_details', 'significance', 'summary', 'severity_assessment',
            'time_sensitivity', 'incident_type', 'potential_impact'
        ]
        
        # Fields that expect Dict[str, Any]
        dict_fields = [
            'risk_score', 'business_impact', 'metrics_panel', 'technique_details'
        ]
        
        # Check and fix union fields
        for field in union_fields:
            if field in transformed_data:
                value = transformed_data[field]
                if isinstance(value, list):
                    print(f"Fixing {field} format: list to str/dict")
                    transformed_data[field] = fix_list_format(field, value)
                elif isinstance(value, int) or isinstance(value, float):
                    print(f"Converting {field} from {type(value).__name__} to str")
                    transformed_data[field] = str(value)
        
        # Check and fix dict fields
        for field in dict_fields:
            if field in transformed_data:
                value = transformed_data[field]
                if isinstance(value, list):
                    print(f"Fixing {field} format: list to dict")
                    # Convert list to dictionary
                    if all(isinstance(item, dict) for item in value):
                        transformed_data[field] = value[0] if len(value) == 1 else {f"item_{i}": item for i, item in enumerate(value)}
                    else:
                        transformed_data[field] = {f"item_{i}": item for i, item in enumerate(value)}
                elif isinstance(value, str):
                    print(f"Converting {field} from str to dict")
                    transformed_data[field] = {"value": value}
                elif isinstance(value, int) or isinstance(value, float):
                    print(f"Converting {field} from {type(value).__name__} to dict")
                    transformed_data[field] = {"value": value}
        
        # Ensure required fields are present with default values
        if "severity_assessment" not in transformed_data or not transformed_data["severity_assessment"]:
            print("Adding missing required field: severity_assessment")
            transformed_data["severity_assessment"] = "Not provided"
            
        if "next_steps_for_l1" not in transformed_data or not transformed_data["next_steps_for_l1"]:
            print("Adding missing required field: next_steps_for_l1")
            transformed_data["next_steps_for_l1"] = []
            
        if "time_sensitivity" not in transformed_data or not transformed_data["time_sensitivity"]:
            print("Adding missing required field: time_sensitivity")
            transformed_data["time_sensitivity"] = "Not provided"
            
        if "incident_type" not in transformed_data or not transformed_data["incident_type"]:
            print("Adding missing required field: incident_type")
            transformed_data["incident_type"] = "Unknown"
        
        return transformed_data


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
    user_domain_access: Dict[str, List[Dict[str, Any]]] = Field(
        default_factory=dict, 
        description="Map of domains to users who accessed them with timestamps and activity details"
    )


def get_mitre_attack_info(technique_ids: List[str], technique_details: Dict[str, Dict[str, str]] = None) -> str:
    """Provide information about MITRE ATT&CK techniques using the LLM at runtime"""
    # We'll use the LLM to generate information about all techniques that aren't in technique_details
    
    # First, collect all techniques that need information
    techniques_needing_info = []
    for technique_id in technique_ids:
        # Clean up technique ID format
        clean_id = technique_id.strip().upper()
        if not clean_id.startswith("T"):
            clean_id = f"T{clean_id}"
        
        # If we don't have details for this technique, add it to the list
        if not technique_details or clean_id not in technique_details:
            techniques_needing_info.append(clean_id)
    
    # Get information for techniques that need it
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
            # If there's an error, create a generic placeholder for missing techniques
            if technique_details is None:
                technique_details = {}
            
            for tech_id in techniques_needing_info:
                if tech_id not in technique_details:
                    technique_details[tech_id] = {
                        "name": f"Technique {tech_id}",
                        "tactic": "Unknown",
                        "description": "Information could not be retrieved. Please refer to the MITRE ATT&CK website.",
                        "mitigation": "Refer to the MITRE ATT&CK website (https://attack.mitre.org/techniques/) for more information."
                    }
    
    # Format the info for each technique
    formatted_info = "MITRE ATT&CK TECHNIQUES:\n"
    
    for technique_id in technique_ids:
        # Clean up technique ID format
        technique_id = technique_id.strip().upper()
        if not technique_id.startswith("T"):
            technique_id = f"T{technique_id}"
        
        # Get technique details
        if technique_details and technique_id in technique_details:
            technique_info = technique_details[technique_id]
            name = technique_info.get("name", f"Technique {technique_id}")
            tactic = technique_info.get("tactic", "Unknown")
            description = technique_info.get("description", "No description provided")
            mitigation = technique_info.get("mitigation", "No mitigation details provided")
        else:
            # This should not happen as we should have fetched all techniques by now
            name = f"Technique {technique_id}"
            tactic = "Unknown"
            description = "Information could not be retrieved. Please refer to the MITRE ATT&CK website."
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
    3. Clear escalation criteria
    
    Format as a JSON object with keys: 'name', 'key_steps' (list), and 'escalation_criteria' (string).
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
        if not all(k in playbook for k in ['name', 'key_steps', 'escalation_criteria']):
            raise ValueError("LLM response missing required playbook fields")
        
        # Format the playbook reference
        formatted_playbook = (
            f"PLAYBOOK REFERENCE: {playbook['name']}\n"
            f"Key Investigation Steps:\n"
        )
        
        for idx, step in enumerate(playbook['key_steps'], 1):
            formatted_playbook += f"  {idx}. {step}\n"
        
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
        generic_criteria = "Critical systems affected, evidence of data exfiltration, or widespread impact"
        
        # Format the generic playbook
        formatted_playbook = (
            f"PLAYBOOK REFERENCE: {generic_name}\n"
            f"Key Investigation Steps:\n"
        )
        
        for idx, step in enumerate(generic_steps, 1):
            formatted_playbook += f"  {idx}. {step}\n"
        
        formatted_playbook += f"Escalation Criteria: {generic_criteria}\n"
        
        return formatted_playbook


def extract_security_indicators(text: str) -> SecurityIndicators:
    """Extract security indicators from text"""
    # Pattern for IPv4 addresses
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    
    # Simple pattern for domains
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    
    # Pattern for Microsoft service names (like Microsoft.OperationalInsights)
    ms_service_pattern = r'\bMicrosoft\.[A-Za-z]+\b'
    
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
    ms_services = re.findall(ms_service_pattern, str(text))
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
    
    # Combine domains and Microsoft service names
    all_domains = list(set(domains + ms_services))
    
    return SecurityIndicators(
        ips=valid_ips,
        domains=all_domains,
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

        # If we have domains, prioritize domain-specific queries
        if indicators.domains:
            print(f"Creating domain-specific KQL query for: {indicators.domains}")
            domain_conditions = []
            for domain in indicators.domains:
                escaped_domain = domain.replace('"', '\"').replace("'","\'") # Escape both quote types
                
                # For Microsoft service domains, use a more specific approach
                if "Microsoft." in domain:
                    # Check operations related to this specific Microsoft service
                    domain_conditions.append(f'OperationName has \'{escaped_domain}\'')
                    domain_conditions.append(f'Resource has \'{escaped_domain}\'')
                else:
                    # Standard domain checks for web/network traffic
                    domain_conditions.append(f'RequestURL has \'{escaped_domain}\'')
                    domain_conditions.append(f'DestinationHostName has \'{escaped_domain}\'')
            
            if domain_conditions:
                # Add domain filtering as a WHERE clause
                query_parts.append(f"| where {' or '.join(domain_conditions)}")
                
                # For Microsoft service domains, extend with a union to Azure Activity logs if available
                if any("Microsoft." in domain for domain in indicators.domains):
                    # Create a separate query for Azure Activity logs to capture Microsoft service operations
                    ms_domains = [d for d in indicators.domains if "Microsoft." in d]
                    ms_domain_conditions = []
                    for domain in ms_domains:
                        escaped_domain = domain.replace('"', '\"').replace("'","\'")
                        ms_domain_conditions.append(f'ResourceProvider has \'{escaped_domain}\'')
                    
                    azure_activity_query = [
                        "union AzureActivity",
                        f"| where TimeGenerated >= datetime('{start_time_iso}') and TimeGenerated <= datetime('{end_time_iso}')",
                        f"| where {' or '.join(ms_domain_conditions)}",
                        "| project TimeGenerated, ResourceProvider, OperationName, Caller, ResourceGroup, Level, ActivityStatus"
                    ]
                    
                    # Add the union query
                    query_parts = ["\n".join(query_parts), "\n".join(azure_activity_query)]
                    query_parts = ["union (", "),\n(", ")"]
        else:
            # If no domains, fall back to IP-based filtering
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
                
            # Combine indicator filters with OR logic
            if indicator_filters:
                query_parts.append(f"| where {' or '.join(indicator_filters)}")

        # Common parts for all queries
        query_parts.append("| order by TimeGenerated desc")
        query_parts.append(f"| take {limit}")

        # Join all query parts
        query = "\n".join(query_parts)
        print(f"Executing KQL query:\n-------\n{query}\n-------")

        # --- Execute Query ---
        url = f"https://api.loganalytics.io/v1/workspaces/{WORKSPACE_ID}/query"
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        request_body = {'query': query}

        response = requests.post(url, headers=headers, json=request_body, timeout=90)

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

def analyze_log_patterns(logs: List[Dict[str, Any]], domain: str = None) -> Dict[str, Dict[str, Any]]:
    """
    Analyze security logs for common patterns and statistics.
    
    Args:
        logs: List of log dictionaries
        domain: Optional domain to include in the output
        
    Returns:
        Dictionary with pattern categories, each containing label and data
    """
    if not logs:
        return {}
    
    patterns = {}
    
    # DestinationIP analysis
    dest_ips = [log.get('DestinationIP') for log in logs if log.get('DestinationIP') and log.get('DestinationIP') != 'N/A']
    if dest_ips:
        # Count occurrences
        ip_counts = {}
        for ip in dest_ips:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        # Sort by count and get top entries
        top_ips = dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5])
        patterns['destination_ip'] = {
            'data': top_ips,
            'label': 'Most Common Destination IPs'
        }
    
    # DestinationPort analysis
    dest_ports = [log.get('DestinationPort') for log in logs if log.get('DestinationPort') and log.get('DestinationPort') != 'N/A']
    if dest_ports:
        port_counts = {}
        for port in dest_ports:
            port_counts[port] = port_counts.get(port, 0) + 1
        # Sort by count and get top entries
        top_ports = dict(sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:5])
        patterns['destination_port'] = {
            'data': top_ports,
            'label': 'Most Common Destination Ports'
        }
    
    # SourceUserName analysis
    usernames = [log.get('SourceUserName') for log in logs if log.get('SourceUserName') and log.get('SourceUserName') != 'N/A']
    if usernames:
        user_counts = {}
        for user in usernames:
            user_counts[user] = user_counts.get(user, 0) + 1
        # Sort by count and get top entries
        top_users = dict(sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:5])
        patterns['source_username'] = {
            'data': top_users,
            'label': 'Most Active Users'
        }
    
    # DeviceName analysis
    devices = [log.get('DeviceName') for log in logs if log.get('DeviceName') and log.get('DeviceName') != 'N/A']
    # If DeviceName isn't available, try DeviceVendor
    if not devices:
        devices = [log.get('DeviceVendor') for log in logs if log.get('DeviceVendor') and log.get('DeviceVendor') != 'N/A']
    
    if devices:
        device_counts = {}
        for device in devices:
            device_counts[device] = device_counts.get(device, 0) + 1
        # Sort by count and get top entries
        top_devices = dict(sorted(device_counts.items(), key=lambda x: x[1], reverse=True)[:5])
        patterns['device_name'] = {
            'data': top_devices,
            'label': 'Most Common Device Names'
        }
    
    # Add default message for empty categories
    categories = ['destination_ip', 'destination_port', 'source_username', 'device_name']
    for category in categories:
        if category not in patterns:
            patterns[category] = {
                'data': {'No data available': 0},
                'label': {
                    'destination_ip': 'Most Common Destination IPs',
                    'destination_port': 'Most Common Destination Ports',
                    'source_username': 'Most Active Users',
                    'device_name': 'Most Common Device Names'
                }[category]
            }
    
    return patterns


def format_log_patterns(patterns: Dict[str, Dict[str, Any]], domain: str = None) -> str:
    """
    Format log patterns into a readable string.
    
    Args:
        patterns: Dictionary with pattern categories
        domain: Optional domain to include in the output
        
    Returns:
        Formatted string with pattern information
    """
    if not patterns:
        return "No log patterns available for analysis.\n"
    
    # Start with domain if provided
    output = []
    if domain:
        output.append(f"Related Security Logs for domain: {domain}")
    else:
        output.append("Security Log Patterns:")
    
    # Add each pattern category
    for category, info in patterns.items():
        output.append(f"\n{info['label']}:")
        for item, count in info['data'].items():
            output.append(f"- {item}: {count} occurrences")
        output.append("")  # Add empty line between categories
    
    return "\n".join(output)

def summarize_log_patterns_with_llm(patterns: Dict[str, Dict[str, Any]], domain: str = None, incident_info: Dict[str, Any] = None) -> str:
    """
    Use the LLM to interpret log patterns and provide a human-readable explanation.
    
    Args:
        patterns: Dictionary with pattern categories
        domain: Optional domain being analyzed
        incident_info: Optional contextual information about the incident
        
    Returns:
        LLM-generated explanation of the log patterns
    """
    if not patterns:
        return "No log patterns available for LLM interpretation."

    try:
        # Format patterns into a readable format for the LLM prompt
        pattern_text = []
        if domain:
            pattern_text.append(f"Security Log Patterns for domain: {domain}")
        else:
            pattern_text.append("Security Log Patterns:")
        
        # Add each pattern category
        for category, info in patterns.items():
            pattern_text.append(f"\n{info['label']}:")
            for item, count in info['data'].items():
                pattern_text.append(f"- {item}: {count} occurrences")
        
        pattern_text_str = "\n".join(pattern_text)
        
        # Include basic incident context if available
        incident_context = ""
        if incident_info:
            incident_context = (
                f"Incident Information:\n"
                f"- Severity: {incident_info.get('severity', 'Unknown')}\n"
                f"- Status: {incident_info.get('status', 'Unknown')}\n"
                f"- Incident Type: {incident_info.get('incident_type', 'Unknown')}\n"
                f"- Title: {incident_info.get('title', 'Unknown')}\n"
                f"- Incident Number: {incident_info.get('incident_number', 'Unknown')}\n"
            )
        
        # Create prompt for the LLM
        prompt = (
            f"You are a cybersecurity analyst interpreting security log patterns. "
            f"Please analyze these log patterns and provide a highly specific interpretation that avoids generic statements. "
            f"Focus on concrete observations and specific technical details about this particular security incident.\n\n"
            f"{incident_context}\n"
            f"{pattern_text_str}\n\n"
            f"Provide your analysis with these specific elements:\n"
            f"1. For each destination IP and port, identify the exact service or protocol it represents and its security relevance\n"
            f"2. For user activity, evaluate the specific behavior patterns and whether they match known attack techniques\n"
            f"3. Identify specific network traffic anomalies with technical details about why they're suspicious\n"
            f"4. Provide concrete risk assessment based on the actual log data, not general statements\n"
            f"5. Include specific technical recommendations tailored to the exact patterns observed\n\n"
            f"Format your response with precise technical details that a SOC analyst could immediately act upon. "
            f"Use specific CVEs, attack techniques, or IOCs where possible. Avoid phrases like 'might indicate' or 'could suggest' "
            f"unless absolutely necessary - instead provide definitive analysis where the evidence allows."
        )
        
        # Configure ollama client with the right base URL
        client = ollama.Client(host=OLLAMA_API_BASE)
        
        # Make the API call to Ollama
        response = client.chat(
            model=OLLAMA_MODEL,
            messages=[{"role": "user", "content": prompt}],
            stream=False
        )
        
        # Extract the explanation from the response
        explanation = response['message']['content'].strip()
        
        # Return the LLM-generated explanation
        return f"LLM INTERPRETATION OF LOG PATTERNS:\n{'-' * 35}\n{explanation}\n"
        
    except Exception as e:
        print(f"Error generating LLM interpretation of log patterns: {str(e)}")
        return f"Error generating LLM interpretation: {str(e)}"

def summarize_user_domain_activity(logs: List[Dict[str, Any]], incident_domains: List[str]) -> tuple:
    """
    Analyze fetched logs to identify which users interacted with specific incident domains.
    Returns both a summary text and structured data for tracking user-domain relationships.
    """
    if not logs or not incident_domains:
        return "User-Domain Activity: No logs or incident domains provided for analysis.\n", {}

    # Normalize incident domains for easier matching (lowercase)
    incident_domains_lower = {domain.lower() for domain in incident_domains if domain}
    
    # Dictionary to store findings: {domain -> set(usernames)}
    domain_user_map = {domain: set() for domain in incident_domains_lower}
    
    # Enhanced tracking - store detailed information about each access: {domain -> [{user, timestamp, action, source_ip, etc}]}
    domain_user_details = {domain: [] for domain in incident_domains_lower}
    
    found_activity = False

    for log in logs:
        # Extract potential domain/URL fields from the log
        log_url = log.get('RequestURL', '')
        log_dest_host = log.get('DestinationHostName', '')
        log_text = f"{log_url} {log_dest_host}".lower() # Combine and lower for searching
        
        # Extract user (prioritize SourceUserName)
        user = log.get('SourceUserName', log.get('UserName', 'Unknown User'))
        
        # Extract timestamp
        timestamp = log.get('TimeGenerated', 'Unknown Time')
        
        # Extract action 
        action = log.get('DeviceAction', log.get('SimplifiedDeviceAction', log.get('Activity', 'Unknown Action')))
        
        # Extract source IP
        source_ip = log.get('SourceIP', 'Unknown Source')
        
        # Check if any incident domain is present in the log's URL/DestHost
        for domain in incident_domains_lower:
            if domain in log_text:
                found_activity = True
                
                # Add to simple domain-user map
                if user and user != 'N/A': 
                    domain_user_map[domain].add(user)
                elif not domain_user_map[domain]:
                    domain_user_map[domain].add("Activity observed (User N/A)") 
                
                # Add detailed access information
                domain_user_details[domain].append({
                    'user': user if user and user != 'N/A' else 'Unknown User',
                    'timestamp': timestamp,
                    'action': action,
                    'source_ip': source_ip,
                    'details': log_text[:100] + ('...' if len(log_text) > 100 else '')
                })

    # Format the summary string
    summary_lines = ["User Activity Involving Incident Domains (from log sample):", "-----------------------------------------------------------"]
    if not found_activity:
        summary_lines.append("No specific activity involving incident domains found in the log sample.")
    else:
        for domain, users in domain_user_map.items():
            if users:
                user_str = ", ".join(sorted(list(users)))
                summary_lines.append(f"- Domain '{domain}': Associated users/activity: {{{user_str}}}")
                
                # Add detailed accesses if available
                if domain_user_details[domain]:
                    for i, access in enumerate(sorted(domain_user_details[domain], 
                                                  key=lambda x: x.get('timestamp', ''), reverse=True)[:5]):  # Show most recent 5
                        summary_lines.append(f"  Access {i+1}: User '{access['user']}' at {access['timestamp']} - {access['action']}")
            else:
                summary_lines.append(f"- Domain '{domain}': No associated user activity found in log sample.") 
                
    return "\n".join(summary_lines) + "\n", domain_user_details

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
    
    # Ensure timestamps are datetime objects, not strings
    try:
        first_detected = pd.to_datetime(first_row['LastModifiedTime'])
        last_modified = pd.to_datetime(last_row['LastModifiedTime'])
    except Exception as e:
        print(f"Warning: Error converting timestamps to datetime objects: {str(e)}")
        # Create placeholder datetime objects if conversion fails
        first_detected = pd.Timestamp.now()
        last_modified = pd.Timestamp.now()
    
    first_status = first_row['Status']
    first_severity = first_row['Severity']
    current_status = last_row['Status']
    current_severity = last_row['Severity']
    
    # Create a detailed timeline of key changes
    key_milestones = []
    previous_row = None
    
    for idx, row in incident_data.iterrows():
        # Ensure timestamp is a datetime object
        try:
            current_timestamp = pd.to_datetime(row['LastModifiedTime'])
        except Exception as e:
            print(f"Warning: Could not convert timestamp to datetime: {str(e)}")
            current_timestamp = pd.Timestamp.now()
            
        milestone = {
            'timestamp': current_timestamp,
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
                try:
                    # Ensure both timestamps are datetime objects before subtraction
                    milestone_time = pd.to_datetime(milestone['timestamp'])
                    triage_time = (milestone_time - first_detected).total_seconds() / 60  # minutes
                except Exception as e:
                    print(f"Warning: Error calculating triage time: {str(e)}")
                    triage_time = 0
                break
        if assignment_milestone:
            break
    
    # Check if incident was resolved
    if current_status in ['Closed', 'Resolved']:
        try:
            # Ensure timestamps are datetime objects before subtraction
            resolution_time = (last_modified - first_detected).total_seconds() / 3600  # hours
        except Exception as e:
            print(f"Warning: Error calculating resolution time: {str(e)}")
            resolution_time = 0
    
    # Create a summary of the timeline
    formatted_first_detected = first_detected.strftime('%Y-%m-%d %H:%M:%S')
    summary = f"Incident #{incident_number} was first detected on {formatted_first_detected} with {first_severity} severity and {first_status} status."
    
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
        # Format timestamp properly
        try:
            if isinstance(milestone['timestamp'], pd.Timestamp) or isinstance(milestone['timestamp'], datetime):
                timestamp_str = milestone['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            else:
                timestamp_str = str(milestone['timestamp'])
        except Exception as e:
            print(f"Warning: Error formatting timestamp: {str(e)}")
            timestamp_str = str(milestone['timestamp'])
            
        formatted += f"\n[{timestamp_str}]\n"
        
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
    if timeline.get('triage_time_minutes') is not None:
        formatted += f"\nTRIAGE METRICS:\n• Time to triage: {timeline['triage_time_minutes']:.1f} minutes\n"
        
    if timeline.get('resolution_time_hours') is not None:
        formatted += f"• Time to resolution: {timeline['resolution_time_hours']:.1f} hours\n"
    
    return formatted

def analyze_incident_context(incident_data: pd.DataFrame, all_incidents: Dict[str, pd.DataFrame] = None, log_window_days: int = 7) -> str:
    """Analyze incident data, fetch relevant logs, and provide context using an LLM."""

    # Sort data by timestamp to ensure chronological order
    try:
        if 'LastModifiedTime' in incident_data.columns:
            incident_data = incident_data.sort_values('LastModifiedTime')
        else:
            print("Warning: 'LastModifiedTime' column not found. Using unsorted data.")
    except Exception as e:
        print(f"Warning: Error sorting incident data: {str(e)}")

    # Get first and last rows
    first_row = incident_data.iloc[0]
    last_row = incident_data.iloc[-1]

    # Ensure timestamps are timezone-aware (assuming UTC)
    try:
        # Process first_detected_dt
        timestamp_input_first = first_row.get('LastModifiedTime', first_row.get('TimeGenerated', None))
        if timestamp_input_first is None:
            print("Warning: No timestamp found for first detection. Using current time.")
            first_detected_dt = pd.Timestamp.now(tz='UTC') - timedelta(hours=1)
        else:
            dt_first = pd.to_datetime(timestamp_input_first)
            if dt_first.tzinfo is None:
                # Timestamp is naive, localize to UTC
                first_detected_dt = dt_first.tz_localize('UTC')
            else:
                # Timestamp is already tz-aware, convert to UTC
                first_detected_dt = dt_first.tz_convert('UTC')

        # Process last_updated_dt
        timestamp_input_last = last_row.get('LastModifiedTime', last_row.get('TimeGenerated', None))
        if timestamp_input_last is None:
            print("Warning: No timestamp found for last update. Using current time.")
            last_updated_dt = pd.Timestamp.now(tz='UTC')
        else:
            dt_last = pd.to_datetime(timestamp_input_last)
            if dt_last.tzinfo is None:
                # Timestamp is naive, localize to UTC
                last_updated_dt = dt_last.tz_localize('UTC')
            else:
                # Timestamp is already tz-aware, convert to UTC
                last_updated_dt = dt_last.tz_convert('UTC')

    except Exception as e:
        print(f"Error converting incident timestamps: {e}. Log fetching might use incorrect window.")
        # Fallback to current time as a rough estimate
        first_detected_dt = pd.Timestamp.now(tz='UTC') - timedelta(hours=1)
        last_updated_dt = pd.Timestamp.now(tz='UTC')

    try:
        first_detected_str = first_detected_dt.strftime('%Y-%m-%d %H:%M:%S %Z')
        last_updated_str = last_updated_dt.strftime('%Y-%m-%d %H:%M:%S %Z')
    except Exception as e:
        print(f"Error formatting timestamps: {e}. Using ISO format.")
        first_detected_str = first_detected_dt.isoformat()
        last_updated_str = last_updated_dt.isoformat()
    
    # If we're using a custom log window, adjust the start time
    try:
        if log_window_days > 0:
            log_start_dt = first_detected_dt - timedelta(days=log_window_days)
            log_start_str = log_start_dt.strftime('%Y-%m-%dT%H:%M:%SZ')
            log_end_str = last_updated_dt.strftime('%Y-%m-%dT%H:%M:%SZ')
            log_window_description = f"{log_window_days}-day window ({log_start_dt.strftime('%Y-%m-%d')} to {last_updated_dt.strftime('%Y-%m-%d')})"
        else:
            # Default to using incident timeframe
            log_start_str = first_detected_dt.strftime('%Y-%m-%dT%H:%M:%SZ')
            log_end_str = last_updated_dt.strftime('%Y-%m-%dT%H:%M:%SZ')
            log_window_description = f"incident timeframe ({first_detected_dt.strftime('%Y-%m-%d')} to {last_updated_dt.strftime('%Y-%m-%d')})"
    except Exception as e:
        print(f"Error calculating log window: {e}. Using default time range.")
        # Use a default time range as fallback
        now = pd.Timestamp.now(tz='UTC')
        log_start_dt = now - timedelta(days=log_window_days if log_window_days > 0 else 1)
        log_start_str = log_start_dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        log_end_str = now.strftime('%Y-%m-%dT%H:%M:%SZ')
        log_window_description = f"fallback {log_window_days}-day window (error in original timestamps)"

    # Extract key information for analysis
    incident_number = str(first_row.get('IncidentNumber', 'Unknown'))
    tenant_id = first_row.get('TenantId', 'Unknown')

    # Extract comments with error handling
    comments = []
    try:
        if 'Comments' in last_row and pd.notna(last_row['Comments']):
            try:
                comments_data = json.loads(last_row['Comments']) if isinstance(last_row['Comments'], str) else last_row['Comments']
                # Handle cases where comments_data might be a list of dicts or just a string
                if isinstance(comments_data, list):
                    for comment in comments_data:
                        if isinstance(comment, dict) and 'message' in comment:
                            comments.append(comment['message'])
                        elif isinstance(comment, str):
                            comments.append(comment)
                elif isinstance(comments_data, str):
                    comments.append(comments_data) # Assume it's a single comment string if not list
                elif isinstance(comments_data, dict) and 'message' in comments_data:
                    comments.append(comments_data['message'])
            except json.JSONDecodeError:
                # Handle cases where comments column is a plain string not in JSON format
                comments = [str(last_row['Comments'])]
            except Exception as e:
                print(f"Error processing comments for incident {incident_number}: {e}")
                comments = [str(last_row['Comments'])] # Fallback to raw string
    except Exception as e:
        print(f"Error accessing comments: {e}")
        comments = []

    # Extract entities from comments and title/description with error handling
    try:
        comments_text = "\n".join(comments)
        title_text = str(last_row.get('Title', ''))
        description_text = str(last_row.get('Description', ''))
        combined_text = f"{title_text}\n{description_text}\n{comments_text}"
    except Exception as e:
        print(f"Error combining text for analysis: {e}")
        combined_text = "Error extracting text from incident data."
    
    # Get enhanced security indicators
    try:
        indicators = extract_security_indicators(combined_text)
    except Exception as e:
        print(f"Error extracting security indicators: {e}")
        indicators = SecurityIndicators()
    
    # --- Fetch Relevant Logs ---
    fetched_logs = []
    try:
        fetched_logs = fetch_relevant_logs(log_start_str, log_end_str, indicators, limit=100)
        log_summary = format_log_summary(fetched_logs, limit=10) # Display top 10 in summary table
    except Exception as e:
        print(f"Error fetching logs: {e}")
        log_summary = "Error fetching logs. See details in the error message."
    
    # --- Analyze User-Domain Activity --- 
    user_domain_summary = ""
    try:
        user_domain_summary, user_domain_details = summarize_user_domain_activity(fetched_logs, indicators.domains)
        # Add the user domain details to the indicators object
        indicators.user_domain_access = user_domain_details
    except Exception as e:
        print(f"Error analyzing user-domain activity: {e}")
        user_domain_summary = "Error analyzing user-domain activity."
    
    # Check domain reputation with VirusTotal if available
    vt_results_text = "VirusTotal integration not available."
    if indicators.domains:
        print(f"Extracted domains from incident: {indicators.domains}")
        if VIRUSTOTAL_AVAILABLE:
            try:
                print(f"Checking {len(indicators.domains)} domains with VirusTotal...")
                # Limit to 5 domains to avoid rate limits
                domains_to_check = indicators.domains[:5] if len(indicators.domains) > 5 else indicators.domains
                vt_results = analyze_domains(domains_to_check)
                print(f"VirusTotal API called for domains: {list(vt_results.keys())}")
                if vt_results:
                    vt_results_text = format_vt_results(vt_results)
                else:
                    vt_results_text = "No suspicious domains found or VirusTotal check failed."
            except Exception as e:
                print(f"Error checking domains with VirusTotal: {str(e)}")
                vt_results_text = f"Error checking domains with VirusTotal: {str(e)}"
    
    # Analyze comments for investigation progression
    try:
        comment_analysis = analyze_comments(comments)
    except Exception as e:
        print(f"Error analyzing comments: {e}")
        comment_analysis = {"total_comments": len(comments), "raw_comments_text": "\n---\n".join(comments[:3] + ["..."])}

    # --- Summarize Comments with LLM ---
    llm_comment_summary = "No comments to summarize or LLM summarization failed."
    if comment_analysis.get("total_comments", 0) > 0:
        print(f"Attempting to summarize {comment_analysis.get('total_comments', 0)} comments using LLM...")
        try:
            comment_summary_prompt = (
                f"You are a helpful assistant summarizing investigation notes. "
                f"Please read the following sequence of comments related to a security incident. "
                f"Provide a concise summary (2-4 sentences) focusing on the key actions taken by analysts, significant findings, and the overall progression or status reflected in these comments. "
                f"Base your summary ONLY on the text provided.\n\n"
                f"Comments (separated by '---'):\n"
                f"------------------------------------\n"
                f"{comment_analysis.get('raw_comments_text', 'No comment text available.')}\n"
                f"------------------------------------\n"
                f"Concise Summary:"
            )
            
            # Reuse the existing Ollama client
            client = ollama.Client(host=OLLAMA_API_BASE)
            response = client.chat(
                model=OLLAMA_MODEL,
                messages=[{"role": "user", "content": comment_summary_prompt}],
                stream=False # No streaming needed for short summary
            )
            llm_comment_summary = response['message']['content'].strip()
            print("LLM comment summary generated successfully.")
        except Exception as llm_err:
            print(f"Error summarizing comments with LLM: {llm_err}")
            llm_comment_summary = f"Error during LLM comment summarization: {llm_err}" # Include error in summary
    # --- End LLM Comment Summarization ---

    # Calculate response metrics
    try:
        timeline = create_incident_timeline(incident_data)
    except Exception as e:
        print(f"Error creating incident timeline: {e}")
        timeline = {
            "summary": f"Error creating timeline: {e}",
            "key_milestones": []
        }
    
    # Find related incidents if we have access to all incidents
    related_incidents = []
    related_incidents_text = "No related incidents found."
    try:
        if all_incidents:
            related_incidents = find_related_incidents(all_incidents, incident_data, indicators)
            # Format related incidents information
            if related_incidents:
                related_incidents_text = "Related Incidents:\n"
                for rel in related_incidents:
                    common_iocs = ', '.join(rel.get('common_indicators', [])) if rel.get('common_indicators') else 'None'
                    related_incidents_text += (
                        f"• #{rel.get('incident_number', 'Unknown')}: {rel.get('title', 'Untitled')}\n"
                        f"  Created: {rel.get('created_time', 'Unknown')}, Status: {rel.get('status', 'Unknown')}\n"
                        f"  Common IOCs: {common_iocs}\n"
                    )
    except Exception as e:
        print(f"Error finding related incidents: {e}")
        related_incidents_text = f"Error finding related incidents: {e}"

    # Get MITRE ATT&CK analysis
    mitre_techniques = []
    technique_details = {}
    
    # Extract MITRE ATT&CK techniques from comments if mentioned
    try:
        mitre_pattern = r'(?:T|t)(?:\d{4})(?:\.\d{3})?'
        potential_techniques = re.findall(mitre_pattern, combined_text)
        mitre_techniques = [tech.upper() for tech in potential_techniques] if potential_techniques else []
    except Exception as e:
        print(f"Error extracting MITRE techniques: {e}")
        mitre_techniques = []
        
    # Add any CVEs to the incident info as they might be relevant
    cve_info = ""
    if indicators.cves:
        cve_info = f"CVEs Detected: {', '.join(indicators.cves)}\n"
         
    # Prepare information for the LLM - safely extract values using .get()
    try:
        incident_info = {
            "incident_number": incident_number,
            "tenant_id": tenant_id,
            "title": title_text,
            "description": description_text,
            "current_status": last_row.get('Status', 'Unknown'),
            "initial_status": first_row.get('Status', 'Unknown'),
            "current_severity": last_row.get('Severity', 'Unknown'),
            "initial_severity": first_row.get('Severity', 'Unknown'),
            "first_detected": first_detected_str,
            "last_updated": last_updated_str,
            "total_updates": len(incident_data),
            "internal_ips": indicators.internal_ips,
            "external_ips": indicators.external_ips,
            "domains": indicators.domains,
            "users": indicators.users,
            "processes": indicators.processes
        }
    except Exception as e:
        print(f"Error preparing incident info: {e}")
        incident_info = {
            "incident_number": incident_number,
            "error": f"Error preparing complete incident information: {e}"
        }

    # Generate log patterns analysis with error handling
    log_patterns = {}
    log_patterns_text = "No log patterns analyzed."
    log_patterns_llm_analysis = "No log pattern interpretation available."
    
    try:
        if fetched_logs:
            log_patterns = analyze_log_patterns(fetched_logs, domain=indicators.domains[0] if indicators.domains else None)
            log_patterns_text = format_log_patterns(log_patterns)
            
            # Get LLM interpretation of log patterns
            log_patterns_llm_analysis = summarize_log_patterns_with_llm(
                log_patterns, 
                domain=indicators.domains[0] if indicators.domains else None, 
                incident_info=incident_info
            )
    except Exception as e:
        print(f"Error analyzing log patterns: {e}")
        log_patterns_text = f"Error analyzing log patterns: {e}"

    # Build the final analysis - adding error handling for each section
    try:
        # Generate the final analysis string including the base summary and the AI part
        analysis = (
            f"INCIDENT SUMMARY:\n"
            f"----------------\n"
            f"Incident #{incident_number} detected from TenantID {tenant_id}\n"
            f"Current Status: {last_row.get('Status', 'Unknown')} (initially {first_row.get('Status', 'Unknown')})\n"
            f"Current Severity: {last_row.get('Severity', 'Unknown')} (initially {first_row.get('Severity', 'Unknown')})\n"
            f"First Detected: {first_detected_str}\n"
            f"Last Updated: {last_updated_str}\n"
            f"Number of Updates: {len(incident_data)}\n\n"
        )
    except Exception as e:
        print(f"Error creating incident summary: {e}")
        analysis = (
            f"INCIDENT SUMMARY:\n"
            f"----------------\n"
            f"Incident #{incident_number}\n"
            f"Error creating complete summary: {e}\n\n"
        )
    
    try:
        # Add security indicators section
        analysis += (
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
    except Exception as e:
        print(f"Error adding security indicators section: {e}")
        analysis += (
            f"DETECTED SECURITY INDICATORS:\n"
            f"--------------------------\n"
            f"Error creating security indicators section: {e}\n\n"
        )
    
    try:
        # Add Raw Log Summary section
        analysis += (
            f"RELEVANT RAW LOGS ({log_window_description}):\n"
            f"--------------------------------------------------------\n"
            f"{log_summary}\n"
        )
    except Exception as e:
        print(f"Error adding raw logs section: {e}")
        analysis += (
            f"RELEVANT RAW LOGS:\n"
            f"--------------------------------------------------------\n"
            f"Error creating raw logs section: {e}\n\n"
        )
    
    try:
        # Add log pattern analysis section
        analysis += (
            f"\nSECURITY LOG PATTERNS:\n"
            f"----------------------\n"
            f"{log_patterns_text}\n"
            f"\n{log_patterns_llm_analysis}\n"
        )
    except Exception as e:
        print(f"Error adding log patterns section: {e}")
        analysis += (
            f"\nSECURITY LOG PATTERNS:\n"
            f"----------------------\n"
            f"Error creating log patterns section: {e}\n\n"
        )
    
    try:
        # Add VirusTotal results section
        if VIRUSTOTAL_AVAILABLE and indicators.domains:
            analysis += (
                f"VIRUSTOTAL DOMAIN REPUTATION:\n"
                f"----------------------------\n"
                f"{vt_results_text}\n\n"
            )
    except Exception as e:
        print(f"Error adding VirusTotal section: {e}")
        analysis += (
            f"VIRUSTOTAL DOMAIN REPUTATION:\n"
            f"----------------------------\n"
            f"Error creating VirusTotal section: {e}\n\n"
        )
    
    try:
        # Add related incidents section if available
        if related_incidents:
            analysis += (
                f"RELATED INCIDENTS:\n"
                f"------------------\n"
                f"{related_incidents_text}\n"
            )
    except Exception as e:
        print(f"Error adding related incidents section: {e}")
        analysis += (
            f"RELATED INCIDENTS:\n"
            f"------------------\n"
            f"Error creating related incidents section: {e}\n\n"
        )
    
    try:
        # Add comment analysis and progression section
        analysis += (
            f"INVESTIGATION CONTEXT (Based on Comments):\n"
            f"-----------------------------------------\n"
            f"Total Comments: {comment_analysis.get('total_comments', 0)}\n"
            f"LLM Summary: {llm_comment_summary}\n\n"
        )
    except Exception as e:
        print(f"Error adding investigation context section: {e}")
        analysis += (
            f"INVESTIGATION CONTEXT (Based on Comments):\n"
            f"-----------------------------------------\n"
            f"Error creating investigation context section: {e}\n\n"
        )
    
    try:
        # Add MITRE ATT&CK section if techniques found
        if mitre_techniques:
            mitre_info = get_mitre_attack_info(mitre_techniques, technique_details)
            analysis += (
                f"MITRE ATT&CK TECHNIQUES:\n"
                f"------------------------\n"
                f"{mitre_info}\n\n"
            )
    except Exception as e:
        print(f"Error adding MITRE ATT&CK section: {e}")
        analysis += (
            f"MITRE ATT&CK TECHNIQUES:\n"
            f"------------------------\n"
            f"Error creating MITRE section: {e}\n\n"
        )
    
    # Add SOC Analyst L1 Triage Report section
    try:
        # Generate a basic analysis if LLM fails
        soc_analysis = (
            f"SOC ANALYST L1 TRIAGE REPORT:\n"
            f"--------------------------------\n"
            f"Based on the available data, this security incident is currently {last_row.get('Status', 'Unknown')} with "
            f"{last_row.get('Severity', 'Unknown')} severity. It was first detected on {first_detected_str} "
            f"and last updated on {last_updated_str}.\n\n"
        )
        
        # Add warning if high risk domains were found
        if VIRUSTOTAL_AVAILABLE and indicators.domains and 'HIGH RISK' in vt_results_text:
            soc_analysis += f"⚠️ WARNING: VirusTotal detected HIGH RISK domains - see detailed analysis section above\n\n"
            
        # Add recommendations
        incident_type = "suspicious_activity"  # Default type
        soc_analysis += (
            f"Recommended Actions:\n"
            f"* Review the security indicators above for potential threats\n"
            f"* Analyze any suspicious domains and IP addresses\n"
            f"* Check related incidents for patterns of malicious activity\n"
            f"* Consider escalating to L2 for more detailed investigation\n\n"
            f"{get_playbook_reference(incident_type)}"
        )
        
        analysis += soc_analysis
    except Exception as e:
        print(f"Error adding SOC Analysis section: {e}")
        analysis += (
            f"SOC ANALYST L1 TRIAGE REPORT:\n"
            f"--------------------------------\n"
            f"Error creating SOC Analysis section: {e}\n"
            f"Please review the raw incident data for details.\n\n"
        )

    return analysis

def get_security_incidents_from_api(days_back=30, include_title_filter=True, tenant_id=None, verbose=True):
    """
    Retrieve security incidents directly from Microsoft Sentinel API
    
    Args:
        days_back (int): Number of days back to look for incidents
        include_title_filter (bool): Whether to filter for specific DNS TI incidents
        tenant_id (str): Tenant ID to filter incidents by
        verbose (bool): Whether to print detailed information
    
    Returns:
        List of incident dictionaries or None if error
    """
    try:
        if not AZURE_CREDS_LOADED:
            print("Error: Azure credentials not found in environment variables.")
            return None
            
        if verbose:
            print("Authenticating with Azure AD...")
        
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
        if verbose:
            print("Authentication successful!")

        # Build KQL query
        query = f"""
        SecurityIncident
        | where TimeGenerated > ago({days_back}d)
        """
        
        # Add tenant filter if specified
        if tenant_id:
            query += f"| where TenantId == '{tenant_id}'\n"
        
        # Add title filter if specified
        if include_title_filter:
            query += """| where Title == "[Custom]-[TI]-DNS with TI Domain Correlation"\n"""
            
        # Add sorting and limit
        query += """| order by TimeGenerated desc"""

        if verbose:
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
        traceback.print_exc()
        return None

def display_and_select_incident(incidents):
    """
    Display list of incidents and let user select one to analyze
    
    Args:
        incidents (list): List of incident dictionaries
        
    Returns:
        tuple: Selected incident group DataFrame and incident number
    """
    if not incidents:
        print("No incidents available to select.")
        return None, None
    
    # Convert to DataFrame
    df = pd.DataFrame(incidents)
    
    # Group by IncidentNumber
    incident_groups = df.groupby('IncidentNumber')
    unique_incidents = len(incident_groups)
    
    print(f"\nFound {unique_incidents} unique security incidents:")
    print("-" * 80)
    
    # Create a list of incidents with key information for display
    incident_list = []
    for i, (incident_number, group) in enumerate(incident_groups, 1):
        # Use the most recent entry for each incident
        latest = group.sort_values('TimeGenerated', ascending=False).iloc[0]
        
        # Format creation time
        creation_time = pd.to_datetime(latest.get('CreatedTime', latest.get('TimeGenerated')))
        formatted_time = creation_time.strftime("%Y-%m-%d %H:%M:%S") if not pd.isna(creation_time) else "Unknown"
        
        # Get title and severity
        title = latest.get('Title', 'Unknown Title')
        severity = latest.get('Severity', 'Unknown')
        status = latest.get('Status', 'Unknown')
        
        incident_list.append({
            'Index': i,
            'Incident #': str(incident_number),  # Convert to string to ensure consistency
            'Title': title,
            'Created': formatted_time,
            'Severity': severity,
            'Status': status
        })
    
    # Display the incidents as a table
    headers = ['Index', 'Incident #', 'Title', 'Created', 'Severity', 'Status']
    rows = [[item[h] for h in headers] for item in incident_list]
    print(tabulate(rows, headers=headers, tablefmt='grid'))
    
    # Get user selection
    while True:
        try:
            selection = input("\nSelect an incident to analyze (enter index number, or 'a' for all): ")
            
            if selection.lower() == 'a':
                print("Analyzing all incidents...")
                return df, None
            
            idx = int(selection) - 1
            if 0 <= idx < len(incident_list):
                selected_incident_number = str(incident_list[idx]['Incident #'])  # Ensure it's a string
                selected_group = df[df['IncidentNumber'].astype(str) == selected_incident_number]
                print(f"\nSelected incident #{selected_incident_number}: {incident_list[idx]['Title']}")
                return selected_group, selected_incident_number
            else:
                print(f"Invalid selection. Please enter a number between 1 and {len(incident_list)}.")
        except ValueError:
            print("Please enter a valid number or 'a' for all incidents.")

def analyze_security_incidents(excel_path: str = None, tenant_id: str = None, fetch_time: datetime = None, 
                               log_window_days: int = 7, use_api: bool = False, api_days: int = 30,
                               include_title_filter: bool = True) -> None:
    """Main function to analyze security incidents and their changes"""
    try:
        df = None
        all_incidents = None
        incident_groups = None
        selected_incident = None
        selected_incident_number = None
        
        if use_api:
            # Fetch incidents from API
            print(f"Fetching security incidents from Microsoft Sentinel API for the past {api_days} days...")
            incidents = get_security_incidents_from_api(days_back=api_days, tenant_id=tenant_id,
                                                      include_title_filter=include_title_filter)
            
            if not incidents:
                print("No incidents found or error occurred. Exiting.")
                return
                
            # Let user select incident to analyze
            df, selected_incident_number = display_and_select_incident(incidents)
            
            if df is None:
                print("No incident selected. Exiting.")
                return
                
            # Set fetch time to now
            fetch_time = datetime.now()
            
        else:
            # Read from Excel file
            if not excel_path:
                print("Error: Excel file path not provided.")
                return
                
            print(f"Reading Excel file: {excel_path}")
            try:
                df = pd.read_excel(excel_path)
                print(f"Successfully loaded the Excel file. Shape: {df.shape}")
            except Exception as e:
                print(f"Error reading Excel file: {str(e)}")
                print("Please verify the Excel file exists and is properly formatted.")
                return
            
            if tenant_id:
                df = df[df['TenantId'] == tenant_id]
                print(f"Filtered by tenant_id. Remaining rows: {len(df)}")
        
        # Add real-time confirmation
        if fetch_time:
            fetch_time_str = fetch_time.strftime("%Y-%m-%d %H:%M:%S")
            print(f"\nREAL-TIME CONFIRMATION:")
            print(f"Security incidents fetched on: {fetch_time_str}")
            print(f"Analysis is using {'API' if use_api else 'Excel'} data as of this timestamp")
        else:
            # Estimate fetch time if not provided (for backwards compatibility)
            fetch_time = datetime.now()
            fetch_time_str = fetch_time.strftime("%Y-%m-%d %H:%M:%S")
            print(f"\nNOTE: Using current analysis time as fetch timestamp: {fetch_time_str}")
        
        # Log window days confirmation
        if log_window_days > 0:
            print(f"Using {log_window_days}-day log analysis window for broader context")
        else:
            print("Using default log window limited to incident timeframe")
            
        # Ensure required columns exist
        required_columns = ['IncidentNumber', 'LastModifiedTime', 'CreatedTime']
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            print(f"Warning: Missing required columns: {missing_columns}")
            print("Will attempt to continue with available columns...")
            for col in missing_columns:
                if col == 'IncidentNumber':
                    print("Creating temporary IncidentNumber column...")
                    df['IncidentNumber'] = range(1, len(df) + 1)
                elif col == 'LastModifiedTime':
                    print("Creating LastModifiedTime column from available timestamp...")
                    df['LastModifiedTime'] = df.get('TimeGenerated', pd.Timestamp.now())
                elif col == 'CreatedTime':
                    print("Creating CreatedTime column from available timestamp...")
                    df['CreatedTime'] = df.get('TimeGenerated', pd.Timestamp.now())
            
        # Sort by LastModifiedTime if available
        if 'LastModifiedTime' in df.columns:
            df = df.sort_values('LastModifiedTime')
        
        # Group by IncidentNumber
        incident_groups = df.groupby('IncidentNumber')
        print(f"Found {len(incident_groups)} unique incidents")
        
        # Create a dictionary of all incident groups for cross-reference
        all_incidents = {str(incident_id): group for incident_id, group in incident_groups}
        
        # Analyze each incident
        incidents_to_analyze = []
        
        if selected_incident_number:
            # Analyze only the selected incident
            selected_incident_number_str = str(selected_incident_number)
            if selected_incident_number_str in all_incidents:
                incidents_to_analyze = [(selected_incident_number_str, all_incidents[selected_incident_number_str])]
            else:
                # Try to find the incident in case of type mismatch
                print(f"Looking for incident #{selected_incident_number} in available incidents...")
                for incident_id, group in all_incidents.items():
                    if str(incident_id) == str(selected_incident_number):
                        incidents_to_analyze = [(incident_id, group)]
                        break
                
                if not incidents_to_analyze:
                    print(f"Error: Selected incident #{selected_incident_number} not found in data.")
                    print(f"Available incident numbers: {list(all_incidents.keys())}")
                    return
        else:
            # Analyze all incidents
            incidents_to_analyze = list(incident_groups)
        
        for incident_number, group in incidents_to_analyze:
            print(f"\nAnalyzing incident: {incident_number}")
            print("="*100)
            print(f"SECURITY INCIDENT ANALYSIS - #{incident_number}")
            print("="*100)
            
            # Initialize variables for all analysis components
            formatted_timeline = ""
            indicators = None
            logs = []
            vt_results = None
            patterns = {}
            related_incidents_data = []
            related_incidents_text = ""
            context_analysis = ""
            
            try:
                # The following components are wrapped in try/except blocks to ensure
                # the analysis continues even if individual components fail
                
                # 1. Create timeline analysis
                try:
                    print("\n1. GENERATING INCIDENT TIMELINE...")
                    timeline = create_incident_timeline(group)
                    formatted_timeline = format_incident_timeline(timeline)
                    print(f"\n{formatted_timeline}")
                except Exception as e:
                    print(f"Warning: Could not generate timeline: {str(e)}")
                    formatted_timeline = "Timeline generation failed. Please check log for details."
                
                # 2. Extract security indicators
                try:
                    print("\n2. EXTRACTING SECURITY INDICATORS...")
                    incident_text = ' '.join([str(val) for val in group.iloc[0].values if pd.notna(val)])
                    indicators = extract_security_indicators(incident_text)
                    print(f"Found: {len(indicators.domains)} domains, {len(indicators.ips)} IPs, {len(indicators.users)} users")
                except Exception as e:
                    print(f"Warning: Could not extract security indicators: {str(e)}")
                    indicators = SecurityIndicators()
                
                # 3. Fetch related logs
                try:
                    print("\n3. FETCHING RELATED LOGS...")
                    if 'CreatedTime' in group.columns and 'LastModifiedTime' in group.columns:
                        start_time = group['CreatedTime'].min() - timedelta(days=log_window_days)
                        end_time = group['LastModifiedTime'].max() + timedelta(days=1)
                        start_time_iso = start_time.isoformat()
                        end_time_iso = end_time.isoformat()
                        
                        if AZURE_CREDS_LOADED and indicators:
                            logs = fetch_relevant_logs(start_time_iso, end_time_iso, indicators)
                            print(f"Retrieved {len(logs)} relevant log entries")
                        else:
                            print("Azure credentials not loaded or no indicators - skipping log fetching")
                    else:
                        print("Missing timestamp columns - skipping log fetching")
                except Exception as e:
                    print(f"Warning: Could not fetch logs: {str(e)}")
                
                # 4. Check domain reputation
                try:
                    print("\n4. CHECKING DOMAIN REPUTATION...")
                    if VIRUSTOTAL_AVAILABLE and indicators and indicators.domains:
                        vt_results = analyze_domains(indicators.domains[:5])  # Limit to 5 domains to avoid rate limits
                        print(f"Retrieved VirusTotal information for {len(vt_results) if vt_results else 0} domains")
                    else:
                        print("VirusTotal not available or no domains found - skipping reputation check")
                except Exception as e:
                    print(f"Warning: Could not check domain reputation: {str(e)}")
                
                # 5. Analyze attack chain
                try:
                    print("\n5. ANALYZING ATTACK CHAIN...")
                    if logs:
                        patterns = analyze_log_patterns(logs)
                        print(f"Identified {len(patterns)} log patterns")
                    else:
                        print("No logs available - skipping attack chain analysis")
                except Exception as e:
                    print(f"Warning: Could not analyze attack chain: {str(e)}")
                
                # 6. Calculate risk assessment
                try:
                    print("\n6. CALCULATING RISK ASSESSMENT...")
                    if all_incidents and indicators:
                        related_incidents_data = find_related_incidents(all_incidents, group, indicators)
                        if related_incidents_data:
                            related_incidents_text = f"Found {len(related_incidents_data)} related incidents\n"
                            for ri in related_incidents_data:
                                related_incidents_text += f"• #{ri['incident_number']} - {ri['title']} ({ri['created_time']})\n"
                            print(related_incidents_text)
                        else:
                            print("No related incidents found")
                    else:
                        print("Missing incidents data or indicators - skipping related incident search")
                except Exception as e:
                    print(f"Warning: Could not calculate risk assessment: {str(e)}")
                
                # 7. Generate comprehensive analysis - CRITICAL COMPONENT
                print("\n7. GENERATING COMPREHENSIVE ANALYSIS...")
                try:
                    context_analysis = analyze_incident_context(group, all_incidents, log_window_days=log_window_days)
                    print("\nSOC ANALYST L1 TRIAGE REPORT:")
                    print("="*35)
                    print(context_analysis)
                    print("\n" + "="*100)
                except Exception as e:
                    print(f"Error: Could not generate comprehensive analysis: {str(e)}")
                    traceback.print_exc()
                    # Create a minimal analysis if the main one fails
                    context_analysis = (
                        f"Error generating full SOC analysis. Basic information:\n"
                        f"Incident: #{incident_number}\n"
                        f"Severity: {group.iloc[0].get('Severity', 'Unknown')}\n"
                        f"Status: {group.iloc[0].get('Status', 'Unknown')}\n"
                        f"Title: {group.iloc[0].get('Title', 'Unknown')}\n"
                        f"Created: {group.iloc[0].get('CreatedTime', 'Unknown')}\n"
                        f"\nPlease check the logs for error details."
                    )
                
                # Always generate a report, even if some components failed
                report_time = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = f"incident_analysis_{incident_number}_{report_time}.txt"
                
                try:
                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write(f"SECURITY INCIDENT ANALYSIS - #{incident_number}\n")
                        f.write("="*100 + "\n\n")
                        
                        # Add real-time data confirmation
                        f.write(f"REAL-TIME ANALYSIS CONFIRMATION:\n")
                        f.write(f"Security incidents fetched on: {fetch_time_str}\n")
                        f.write(f"Analysis time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write(f"Log analysis window: {log_window_days} days\n\n")
                        
                        # Include all analysis components in the report
                        f.write("1. INCIDENT TIMELINE\n")
                        f.write("-" * 20 + "\n")
                        f.write(formatted_timeline + "\n\n")
                        
                        f.write("2. SECURITY INDICATORS\n")
                        f.write("-" * 20 + "\n")
                        if indicators:
                            f.write(f"Domains: {', '.join(indicators.domains) if indicators.domains else 'None'}\n")
                            f.write(f"IPs: {', '.join(indicators.ips) if indicators.ips else 'None'}\n")
                            f.write(f"Users: {', '.join(indicators.users) if indicators.users else 'None'}\n")
                            f.write(f"Processes: {', '.join(indicators.processes) if indicators.processes else 'None'}\n\n")
                        else:
                            f.write("No indicators extracted.\n\n")
                        
                        # Include VirusTotal results if available
                        if VIRUSTOTAL_AVAILABLE and vt_results:
                            f.write("3. VIRUSTOTAL DOMAIN REPUTATION\n")
                            f.write("-" * 20 + "\n")
                            vt_formatted = format_vt_results(vt_results)
                            f.write(vt_formatted + "\n\n")
                        
                        # Include log patterns if available
                        if patterns:
                            f.write("4. ATTACK CHAIN RECONSTRUCTION\n") 
                            f.write("-" * 20 + "\n")
                            f.write(format_log_patterns(patterns) + "\n\n")
                        
                        # Include related incidents if found
                        if related_incidents_data:
                            f.write("5. RELATED INCIDENTS\n")
                            f.write("-" * 20 + "\n")
                            f.write(related_incidents_text + "\n\n")
                        
                        # SOC Analyst's comprehensive analysis
                        f.write("6. SOC ANALYST L1 TRIAGE REPORT:\n")
                        f.write("="*35 + "\n")
                        f.write(context_analysis + "\n\n")
                        
                        # End of report
                        f.write("="*100 + "\n")
                    
                    print(f"\nComprehensive analysis saved to: {output_path}")
                    print(f"SOC analysis report successfully generated!")
                except Exception as e:
                    print(f"Error saving report: {str(e)}")
                    traceback.print_exc()
                
                # Ask if user wants to see raw data
                user_input = input("\nWould you like to see the raw incident data? (y/n): ")
                if user_input.lower() == 'y':
                    print("\nRAW INCIDENT DATA:")
                    print("-" * 20)
                    for idx, row in group.iterrows():
                        print(f"\nEntry {idx+1}:")
                        print(f"Timestamp: {row.get('LastModifiedTime', 'Unknown')}")
                        print(f"Status: {row.get('Status', 'Unknown')}")
                        print(f"Severity: {row.get('Severity', 'Unknown')}")
                        print("-" * 40)
            
            except Exception as e:
                print(f"Error analyzing incident {incident_number}: {str(e)}")
                traceback.print_exc()
                print("\nAttempting to generate a basic report despite errors...")
                
                # Create a very basic report even in case of catastrophic failure
                try:
                    # Ensure we have a unique output filename
                    report_time = datetime.now().strftime("%Y%m%d_%H%M%S")
                    output_path = f"incident_analysis_{incident_number}_{report_time}_basic.txt"
                    
                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write(f"BASIC INCIDENT REPORT - #{incident_number}\n")
                        f.write("="*100 + "\n\n")
                        f.write(f"Error occurred during analysis: {str(e)}\n")
                        f.write(f"Analysis time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                        
                        # Include any basic info we can extract safely
                        try:
                            first_row = group.iloc[0]
                            f.write(f"Incident: #{incident_number}\n")
                            f.write(f"Title: {first_row.get('Title', 'Unknown')}\n")
                            f.write(f"Severity: {first_row.get('Severity', 'Unknown')}\n")
                            f.write(f"Status: {first_row.get('Status', 'Unknown')}\n")
                            f.write(f"Created: {first_row.get('CreatedTime', 'Unknown')}\n")
                        except:
                            f.write("Could not extract basic incident data.\n")
                        
                        f.write("\nPlease check the logs for detailed error information.\n")
                        f.write("="*100 + "\n")
                    
                    print(f"\nBasic analysis saved to: {output_path}")
                except Exception as nested_e:
                    print(f"Critical error: Could not generate even a basic report: {str(nested_e)}")
            
    except Exception as e:
        print(f"Error analyzing security incidents: {str(e)}")
        traceback.print_exc()

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Analyze security incidents from Excel file or directly from API')
    parser.add_argument('--excel', dest='excel_path', help='Path to Excel file with security incidents', 
                        default=os.path.join('03 extracted data', 'data_15aprl', 'security_incidents_20250415_124725.xlsx'))
    parser.add_argument('--tenant', dest='tenant_id', help='Filter by tenant ID')
    parser.add_argument('--window', dest='log_window', type=int, default=7, 
                        help='Number of days for log analysis window (default: 7, use 30 for extended analysis)')
    parser.add_argument('--api', dest='use_api', action='store_true', help='Fetch incidents directly from API instead of Excel file')
    parser.add_argument('--days', dest='api_days', type=int, default=30, 
                        help='Number of days to fetch from API (default: 30, only used with --api)')
    parser.add_argument('--no-filter', dest='no_filter', action='store_true', 
                        help='Disable title filtering (fetch all incident types, not just DNS TI incidents)')
    
    args = parser.parse_args()
    
    print(f"Using log window of {args.log_window} days for analysis")
    # Make sure Ollama server is running before executing this script
    if args.use_api:
        print("Fetching incidents directly from Microsoft Sentinel API")
        # Pass the filter setting based on the no_filter argument
        include_title_filter = not args.no_filter
        
        if args.no_filter:
            print("Title filtering disabled - fetching all incident types")
        else:
            print("Title filtering enabled - fetching only DNS TI correlation incidents")
            
        analyze_security_incidents(tenant_id=args.tenant_id, log_window_days=args.log_window, 
                                  use_api=True, api_days=args.api_days,
                                  include_title_filter=include_title_filter)
    else:
        print("Reading incidents from Excel file")
        analyze_security_incidents(args.excel_path, args.tenant_id, log_window_days=args.log_window)
    
    print("\nAnalysis complete. Check the generated text files for detailed SOC reports.")