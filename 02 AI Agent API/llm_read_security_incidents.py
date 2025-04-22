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
import ast

# Load environment variables from .env file
load_dotenv()

# Import VirusTotal integration if available
VIRUSTOTAL_AVAILABLE = False
try:
    from virustotal_integration import analyze_domains, format_vt_results
    VIRUSTOTAL_AVAILABLE = True
except ImportError:
    pass  # VirusTotal integration not available

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
    
    # New fields for SOC analyst immediate actions and future steps format
    immediate_actions: List[Dict[str, Any]] = Field(
        default_factory=list, 
        description="List of immediate actions to take in first 1-2 hours, each with action description and recommended status"
    )
    future_steps: List[Dict[str, Any]] = Field(
        default_factory=list, 
        description="List of future investigation steps to take in next 24 hours with relevant data points"
    )
    
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
    # Add missing fields to align with IncidentAnalysisOutput
    metrics_panel: Dict[str, Any] = Field(default_factory=dict, description="At-a-glance metrics panel with critical stats")
    attack_techniques: List[str] = Field(default_factory=list, description="MITRE ATT&CK techniques identified")
    technique_details: Dict[str, Dict[str, str]] = Field(default_factory=dict, description="Details about MITRE ATT&CK techniques")
    asset_impact_analysis: Union[str, Dict[str, Any]] = Field(default="Not provided", description="Impacted assets")
    threat_intel_context: Union[str, Dict[str, Any]] = Field(default="Not provided", description="Threat intelligence context")


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
    """Fetch relevant logs from Azure Log Analytics (CommonSecurityLog_Enrich) based on incident indicators, WITHOUT time limit."""
    if not AZURE_CREDS_LOADED:
        print("Skipping log fetching as Azure credentials are not loaded.")
        return []

    # Remove print statement mentioning time window as it's no longer used
    print(f"Attempting to fetch relevant logs based on indicators (limit: {limit})...")

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
        # print("Authentication successful!")

        # --- Build KQL Query ---
        kql_table = "CommonSecurityLog_Enrich"
        # Start query parts with just the table name (NO time filter)
        query_parts = [kql_table]

        non_ms_domain_query_built = False
        final_query = ""

        # Domain-based filtering
        if indicators.domains:
            print(f"Filtering logs based on domains: {indicators.domains}")
            searchable_domains = [d for d in indicators.domains if d and not d.startswith('Microsoft.')]

            if searchable_domains:
                domain_conditions = []
                for domain in searchable_domains:
                    escaped_domain = domain.replace("'", "\\'")
                    domain_conditions.append(f'DestinationHostName has "{escaped_domain}"')
                    domain_conditions.append(f'RequestURL has "{escaped_domain}"')

                if domain_conditions:
                    domain_where_clause = f"| where {' or '.join(domain_conditions)}"
                    query_parts.append(domain_where_clause) # Append WHERE directly after table
                    print(f"Added specific WHERE clause for domains: {domain_where_clause}")
                    non_ms_domain_query_built = True

            ms_domains = [d for d in indicators.domains if d and d.startswith('Microsoft.')]
            if ms_domains:
                print(f"Found Microsoft service domains, adding AzureActivity union: {ms_domains}")
                ms_domain_conditions = []
                for domain in ms_domains:
                    escaped_domain = domain.replace("'", "\\'")
                    ms_domain_conditions.append(f'ResourceProvider has \'{escaped_domain}\'')

                base_query_str = ""
                if non_ms_domain_query_built:
                    base_parts = query_parts.copy()
                    base_query_str = "\n".join(base_parts)
                else:
                    # If ONLY MS domains, base query is just the table name
                    base_query_str = kql_table

                # Construct AzureActivity part (NO time filter)
                azure_activity_query_parts = [
                    "AzureActivity",
                    # No time filter needed here
                    f"| where {' or '.join(ms_domain_conditions)}",
                    "| project TimeGenerated, ResourceProvider, OperationName, Caller, ResourceGroup, Level, ActivityStatus"
                ]
                azure_activity_query_str = "\n".join(azure_activity_query_parts)

                if non_ms_domain_query_built:
                     final_query = f"union kind=outer ({base_query_str}), ({azure_activity_query_str})"
                else:
                    final_query = azure_activity_query_str

                final_query += f"\n| order by TimeGenerated desc\n| take {limit}"
                print(f"Executing KQL query (Union - No Time Filter):\\n-------\\n{final_query}\\n-------")

            elif non_ms_domain_query_built:
                 query_parts.append(f"| order by TimeGenerated desc")
                 query_parts.append(f"| take {limit}")
                 final_query = "\n".join(query_parts)
                 print(f"Executing KQL query (Standard - Domain - No Time Filter):\\n-------\\n{final_query}\\n-------")

            else:
                 print("No valid domains found to filter on.")
                 pass

        # IP-based filtering (only if no domain query was built)
        if not final_query and (indicators.external_ips or indicators.internal_ips):
            print("No domain filters applied or built, attempting IP-based filtering (No Time Filter)...")
            indicator_filters = []
            if indicators.external_ips:
                ips_quoted = [f'"{ip}"' for ip in indicators.external_ips]
                ips_str = ",".join(ips_quoted)
                indicator_filters.append(f'(DestinationIP in ({ips_str}) or SourceIP in ({ips_str}))')
            if indicators.internal_ips:
                 ips_quoted = [f'"{ip}"' for ip in indicators.internal_ips]
                 ips_str = ",".join(ips_quoted)
                 indicator_filters.append(f'(DestinationIP in ({ips_str}) or SourceIP in ({ips_str}))')

            if indicator_filters:
                # Start query parts with just the table name
                query_parts = [kql_table]
                query_parts.append(f"| where {' or '.join(indicator_filters)}")
                query_parts.append(f"| order by TimeGenerated desc")
                query_parts.append(f"| take {limit}")
                final_query = "\n".join(query_parts)
                print(f"Executing KQL query (IP Based - No Time Filter):\\n-------\\n{final_query}\\n-------")
            else:
                 print("No domain or IP indicators provided for log fetching.")
                 return []
        elif not final_query and not (indicators.domains or indicators.external_ips or indicators.internal_ips):
             print("No domain or IP indicators provided for log fetching.")
             return []

        # --- Execute Query ---
        if final_query:
            url = f"https://api.loganalytics.io/v1/workspaces/{WORKSPACE_ID}/query"
            headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
            request_body = {'query': final_query}

            response = requests.post(url, headers=headers, json=request_body, timeout=180) # Consider if timeout needs adjustment for potentially larger queries

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
                        return []
                else:
                    print("No 'tables' data found in the API response.")
                    return []
            else:
                print(f"Error fetching logs: {response.status_code}")
                print(f"Error details: {response.text}")
                return []
        else:
             print("Failed to construct a valid KQL query.")
             return []


    except adal.AdalError as auth_err:
         print(f"Authentication Error: {str(auth_err)}")
         return []
    except requests.exceptions.Timeout as timeout_err:
        print(f"Request timed out fetching logs: {str(timeout_err)}")
        # No time window to reduce now, might need to increase timeout or rely on limit
        print("Consider increasing the timeout or relying on the log limit if timeouts persist.")
        return []
    except requests.exceptions.RequestException as req_err:
        print(f"Network/Request Error fetching logs: {str(req_err)}")
        return []
    except Exception as e:
        print(f"An unexpected error occurred during log fetching: {str(e)}")
        traceback.print_exc()
        return []

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
    Format log patterns into a human-readable format.
    
    Args:
        patterns: Dictionary with pattern categories
        domain: Optional domain being analyzed
        
    Returns:
        Formatted string with pattern information
    """
    if not patterns:
        return "No log patterns available."

    result = []
    if domain:
        result.append(f"Security Log Patterns for domain: {domain}")
    else:
        result.append("Security Log Patterns:")
    
    # Add each pattern category
    for category, info in patterns.items():
        result.append(f"\n{info['label']}:")
        for item, count in info['data'].items():
            result.append(f"- {item}: {count} occurrences")
    
    return "\n".join(result)

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
    """Analyzes comments to extract key information and context"""
    # For simple comment analysis, just extract the first comment as a sample
    comment_info = {
        "total_comments": len(comments),
        "summary": ""
    }
    
    if comments:
        # Take the first 3 comments for summary
        sample_comments = comments[:3]
        comment_info["summary"] = "Here is a concise summary of the investigation notes:\n\n"
        for i, comment in enumerate(sample_comments):
            # Truncate long comments
            if len(comment) > 500:
                comment_info["summary"] += f"{comment[:500]}..."
            else:
                comment_info["summary"] += comment
                
            if i < len(sample_comments) - 1:
                comment_info["summary"] += "\n\n"
        
    return comment_info

def analyze_incident_context(incident_data: pd.DataFrame, all_incidents: Dict[str, pd.DataFrame] = None, log_window_days: int = 7) -> str:
    """Analyze the context of the incident"""
    context = ""
    
    # Start time for the analysis
    start_time = datetime.now()
    
    # Dictionary to store all incidents dataframes by sheet name
    all_incidents = {}
    
    # Flag to track if real-time data is being used
    real_time_data = False
    
    try:
        if use_api:
            # Fetch incidents directly from API
            print("Fetching security incidents from Microsoft Sentinel API...")
            
            # Set tenant_id from environment variable if not provided
            if not tenant_id:
                tenant_id = TENANT_ID
                
            if not tenant_id:
                print("Error: Tenant ID not provided. Please provide tenant_id parameter or set TENANT_ID environment variable.")
                return
                
            api_incidents = get_security_incidents_from_api(
                days_back=api_days,
                include_title_filter=include_title_filter,
                tenant_id=tenant_id,
                verbose=True
            )
            
            if not api_incidents or len(api_incidents) == 0:
                print("No incidents found or error retrieving incidents from API.")
                return
                
            print(f"\nFound {len(api_incidents)} incidents from API.")
            
            # Convert list of incidents to DataFrame
            incidents_df = pd.DataFrame(api_incidents)
            
            # Set fetch time if not provided
            if not fetch_time:
                fetch_time = datetime.now()
                
            # Set flag for real-time data
            real_time_data = True
            
            # Store in all_incidents dictionary
            all_incidents['API_Incidents'] = incidents_df
            
            # Filter to keep only the most recent entry for each incident
            print("\nFiltering incidents to keep only the most recent entry for each unique incident...")
            incidents_df = incidents_df.sort_values('LastModifiedTime', ascending=False)
            original_count = len(incidents_df)
            incidents_df = incidents_df.drop_duplicates(subset=['IncidentNumber'], keep='first')
            filtered_count = len(incidents_df)
            print(f"Filtered from {original_count} to {filtered_count} unique incidents (keeping only the most recent entry for each)")
            
            # Show incident selection dialog and get user's selection
            incident_df, selected_incident_number = display_and_select_incident(incidents_df)
            if incident_df is None:
                print("No incident selected for analysis.")
                return
        else:
            # Check if Excel file path is provided
            if not excel_path:
                print("Error: Excel file path not provided.")
                return
                
            # Check if Excel file exists
            if not os.path.isfile(excel_path):
                print(f"Error: Excel file not found at {excel_path}")
                return
                
            # Get file creation time as fetch time if not provided
            if not fetch_time:
                fetch_time = datetime.fromtimestamp(os.path.getctime(excel_path))
                
            print(f"Reading security incidents from Excel file: {excel_path}")
            
            # Load Excel file with pandas
            excel = pd.ExcelFile(excel_path)
            
            # Load each sheet into a DataFrame and store in all_incidents dictionary
            for sheet_name in excel.sheet_names:
                print(f"Reading sheet: {sheet_name}")
                df = pd.read_excel(excel, sheet_name=sheet_name)
                
                # Filter to keep only the most recent entry for each incident
                if 'LastModifiedTime' in df.columns and 'IncidentNumber' in df.columns:
                    print(f"\nFiltering sheet {sheet_name} to keep only the most recent entry for each unique incident...")
                    original_count = len(df)
                    df = df.sort_values('LastModifiedTime', ascending=False)
                    df = df.drop_duplicates(subset=['IncidentNumber'], keep='first')
                    filtered_count = len(df)
                    print(f"Filtered from {original_count} to {filtered_count} unique incidents (keeping only the most recent entry for each)")
                
                all_incidents[sheet_name] = df
                
            # Check if any incidents were found
            if not all_incidents:
                print("No incidents found in Excel file.")
                return
                
            # Get the first sheet for analysis if not specified
            incident_sheet = list(all_incidents.keys())[0]
            incident_df = all_incidents[incident_sheet]
            
            # Display incidents and let user select one if multiple are found
            if len(incident_df) > 1:
                # Show incident selection dialog
                incident_df, selected_incident_number = display_and_select_incident(incident_df)
            
        # Ensure the incident DataFrame has necessary columns
        required_cols = ['Title', 'IncidentNumber', 'Severity', 'Status', 'Owner']
        missing_cols = [col for col in required_cols if col not in incident_df.columns]
        
        if missing_cols:
            print(f"Warning: Incident data is missing required columns: {', '.join(missing_cols)}")
            print("Available columns:", incident_df.columns.tolist())
            
        # Check if incidents were found
        if incident_df.empty:
            print("No incidents found for analysis.")
            return
        
        # Analyze each incident
        for incident_number, group in incident_df.groupby('IncidentNumber'):
            print(f"\nAnalyzing incident: {incident_number}")
            print("="*100)
            
            # Extracts data about the incident
            try:
                output_file = os.path.join(os.path.dirname(excel_path) if excel_path else ".", 
                                         f"incident_analysis_{incident_number}_{start_time.strftime('%Y%m%d_%H%M%S')}.txt")
                
                # Get basic incident info
                incident_title = group['Title'].iloc[0] if 'Title' in group.columns else 'Unknown'
                incident_severity = group['Severity'].iloc[0] if 'Severity' in group.columns else 'Unknown'
                incident_status = group['Status'].iloc[0] if 'Status' in group.columns else 'Unknown'
                
                print(f"Incident #{incident_number}: {incident_title}")
                print(f"Status: {incident_status}, Severity: {incident_severity}")
                
                # Get incident description
                incident_description = ''
                if 'Description' in group.columns:
                    incident_description = group['Description'].iloc[0]
                    if incident_description and len(incident_description) > 0:
                        print(f"\nDescription: {incident_description[:100]}...")
                
                # Extract comments if available
                comments = []
                if 'Comments' in group.columns:
                    # Get all non-null comments
                    all_comments = group['Comments'].dropna().tolist()
                    comments = [c for c in all_comments if c]
                        
                # Analyze comments
                comment_analysis = analyze_comments(comments)
                
                # Remove the incident timeline generation section 
                print("\n1. EXTRACTING SECURITY INDICATORS...")
                
                # Extract security indicators
                raw_text = " ".join([
                    str(val) for col in group.columns 
                    for val in group[col].fillna('').astype(str).tolist()
                ])
                
                indicators = extract_security_indicators(raw_text)
                if indicators:
                    print(f"Found: {len(indicators.domains)} domains, {len(indicators.ips)} IPs, {len(indicators.users)} users")
                
                # Extract AlertIds from the incident and retrieve corresponding alerts
                print("\n1.1 RETRIEVING ASSOCIATED SECURITY ALERTS...")
                alert_ids = extract_alert_ids(group)
                
                if alert_ids:
                    print(f"Found {len(alert_ids)} alert IDs associated with this incident")
                    # Query for the alerts with these IDs
                    alerts = get_security_alerts_for_incident(
                        alert_ids=alert_ids,
                        days_back=log_window_days * 2,  # Use wider window to ensure alerts are found
                        tenant_id=tenant_id,
                        verbose=True
                    )
                    
                    if alerts:
                        print(f"Retrieved {len(alerts)} security alerts for correlation")
                        
                        # Enhance indicators with alert entities
                        print("\n1.2 ENHANCING INDICATORS WITH ALERT ENTITIES...")
                        indicators = enhance_indicators_with_entities(alerts, indicators)
                        print(f"Enhanced indicators: {len(indicators.domains)} domains, {len(indicators.ips)} IPs, {len(indicators.users)} users")
                    else:
                        print("No matching security alerts found")
                else:
                    print("No alert IDs found in the incident data")
                    alerts = []
                
                # Fetch related logs
                print("\n2. FETCHING RELATED LOGS...")
                logs = []
                
                # Get time range for logs
                try:
                    if 'CreatedTime' in group.columns and not group['CreatedTime'].isnull().all():
                        # Use the incident creation time
                        start_time_dt = pd.to_datetime(group['CreatedTime'].iloc[0])
                        # If log_window_days is provided, use that as the window
                        if log_window_days > 0:
                            end_time_dt = start_time_dt + timedelta(days=log_window_days)
                        else:
                            # Otherwise use the incident resolution time if available
                            if 'TimeToResolve' in group.columns and not group['TimeToResolve'].isnull().all():
                                resolve_time = group['TimeToResolve'].iloc[0]
                                if isinstance(resolve_time, (int, float)):
                                    # If TimeToResolve is a number of hours
                                    end_time_dt = start_time_dt + timedelta(hours=resolve_time)
                                elif isinstance(resolve_time, str):
                                    # Try to parse as duration string (e.g., "5 hours")
                                    try:
                                        hours = float(resolve_time.split()[0])
                                        end_time_dt = start_time_dt + timedelta(hours=hours)
                                    except:
                                        # If parsing fails, use default log window
                                        end_time_dt = start_time_dt + timedelta(days=log_window_days or 7)
                                else:
                                    # Use default log window if TimeToResolve is in an unknown format
                                    end_time_dt = start_time_dt + timedelta(days=log_window_days or 7)
                            else:
                                # If no resolution time, use default log window
                                end_time_dt = start_time_dt + timedelta(days=log_window_days or 7)
                        
                        # Format times for API call
                        start_time_iso = start_time_dt.isoformat()
                        end_time_iso = end_time_dt.isoformat()
                        
                        # Fetch logs
                        logs = fetch_relevant_logs(start_time_iso, end_time_iso, indicators)
                    else:
                        print("Warning: Could not determine time range for logs. Using fixed window.")
                        # Use a fixed window based on current time
                        end_time_dt = datetime.now()
                        start_time_dt = end_time_dt - timedelta(days=log_window_days or 7)
                        
                        # Format times for API call
                        start_time_iso = start_time_dt.isoformat()
                        end_time_iso = end_time_dt.isoformat()
                        
                        # Fetch logs
                        logs = fetch_relevant_logs(start_time_iso, end_time_iso, indicators)
                except Exception as e:
                    print(f"Warning: Could not fetch logs: {e}")
                
                # Format log output
                log_summary = format_log_summary(logs)
                
                # Analyze log patterns
                patterns = None
                log_pattern_summary = ""
                if logs:
                    print("\n3. ANALYZING LOG PATTERNS...")
                    try:
                        # Get primary domain
                        primary_domain = indicators.domains[0] if indicators.domains else None
                        
                        # Get incident information for context
                        incident_info = {
                            "title": incident_title,
                            "number": incident_number,
                            "severity": incident_severity,
                            "status": incident_status,
                            "description": incident_description
                        }
                        
                        # Analyze patterns
                        patterns = analyze_log_patterns(logs, primary_domain)
                        
                        # Format patterns
                        formatted_patterns = format_log_patterns(patterns, primary_domain)
                        
                        # Skip LLM interpretation
                        log_pattern_summary = ""
                    except Exception as e:
                        print(f"Error analyzing log patterns: {e}")
                        log_pattern_summary = "Error analyzing log patterns."
                    
                # Check for VirusTotal domain data
                vt_results = ""
                if VIRUSTOTAL_AVAILABLE and indicators.domains:
                    print("\n4. CHECKING DOMAIN REPUTATION...")
                    try:
                        domains_data = analyze_domains(indicators.domains)
                        vt_results = format_vt_results(domains_data)
                    except Exception as e:
                        print(f"Error retrieving VirusTotal data: {e}")
                        vt_results = "Error retrieving VirusTotal data."
                    
                # Generate output file
                print(f"\nWriting analysis to {output_file}...")
                with open(output_file, 'w') as f:
                    # Format output
                    f.write(f"SECURITY INCIDENT ANALYSIS - #{incident_number}\n")
                    f.write("====================================================================================================\n\n")
                    
                    # Add real-time analysis confirmation
                    f.write("REAL-TIME ANALYSIS CONFIRMATION:\n")
                    fetch_time_str = fetch_time.strftime("%Y-%m-%d %H:%M:%S") if fetch_time else start_time.strftime("%Y-%m-%d %H:%M:%S")
                    analysis_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    f.write(f"Security incidents fetched on: {fetch_time_str}\n")
                    f.write(f"Analysis time: {analysis_time_str}\n")
                    f.write(f"Log analysis window: {log_window_days} days\n\n")
                    
                    f.write("1. SECURITY INDICATORS\n")
                    f.write("--------------------\n")
                    f.write(f"Domains: {', '.join(indicators.domains) if indicators.domains else 'None'}\n")
                    f.write(f"IPs: {', '.join(indicators.ips) if indicators.ips else 'None'}\n")
                    f.write(f"Users: {', '.join(indicators.users) if indicators.users else 'None'}\n")
                    f.write(f"Processes: {', '.join(indicators.processes) if indicators.processes else 'None'}\n")
                    
                    # Add alert correlation section
                    if alerts:
                        f.write("\n2. CORRELATED SECURITY ALERTS\n")
                        f.write("---------------------------\n")
                        f.write(f"Number of correlated alerts: {len(alerts)}\n\n")
                        
                        for i, alert in enumerate(alerts[:5], 1):  # Show top 5 alerts
                            f.write(f"Alert {i}:\n")
                            f.write(f"  Title: {alert.get('AlertName', 'Unknown')}\n")
                            f.write(f"  Severity: {alert.get('AlertSeverity', 'Unknown')}\n")
                            f.write(f"  Time: {alert.get('TimeGenerated', 'Unknown')}\n")
                            f.write(f"  Description: {alert.get('Description', 'No description')[:150]}...\n\n")
                        
                        if len(alerts) > 5:
                            f.write(f"... {len(alerts) - 5} more alerts not shown ...\n\n")
                    f.write("\n")
                    
                    # Add security indicators section
                    f.write("3. VIRUSTOTAL DOMAIN REPUTATION\n")
                    f.write("----------------------------\n")
                    f.write(vt_results + "\n\n")
                    
                    # Add log patterns section
                    f.write("4. ATTACK CHAIN RECONSTRUCTION\n")
                    f.write("---------------------------\n")
                    f.write(formatted_patterns + "\n\n")
                    
                    # Add related incidents section
                    if related_incidents_data:
                        f.write("5. RELATED INCIDENTS\n")
                        f.write("-------------------\n")
                        f.write(related_incidents_text + "\n\n")
                    
                    # Add comment analysis and progression section
                    f.write("6. INVESTIGATION CONTEXT (Based on Comments):\n")
                    f.write("-----------------------------------------\n")
                    f.write(f"Total Comments: {comment_analysis.get('total_comments', 0)}\n")
                    f.write(f"LLM Summary: {llm_comment_summary}\n\n")
                    
                    # Add MITRE ATT&CK section if techniques found
                    if mitre_techniques:
                        mitre_info = get_mitre_attack_info(mitre_techniques, technique_details)
                        f.write("7. MITRE ATT&CK TECHNIQUES:\n")
                        f.write("-------------------------\n")
                        f.write(mitre_info + "\n\n")
                    
                    # Generate Enhanced SOC Analyst Report
                    print("\n8. GENERATING ENHANCED SOC ANALYST REPORT...")
                    try:
                        # Prepare incident data for the report
                        incident_info = {
                            "title": incident_title,
                            "number": incident_number,
                            "severity": incident_severity,
                            "status": incident_status,
                            "description": incident_description
                        }
                        
                        # Generate the enhanced SOC analyst report
                        soc_analyst_report = generate_soc_analyst_report(
                            incident_data=incident_info,
                            logs=logs,
                            indicators=indicators,
                            alerts=alerts if 'alerts' in locals() else []
                        )
                    except Exception as e:
                        print(f"Error generating enhanced SOC analyst report: {str(e)}")
                        soc_analyst_report = f"Error generating enhanced SOC analyst report: {str(e)}"
                    
                    # Add SOC Analyst L1 Triage Report section
                    f.write("8. SOC ANALYST L1 TRIAGE REPORT:\n")
                    f.write("===============================\n")
                    f.write(context_analysis + "\n\n")
                    
                    # Add Enhanced SOC Analyst Report section
                    f.write("9. ENHANCED SOC ANALYST REPORT:\n")
                    f.write("==============================\n")
                    # Format the IncidentAnalysisOutput object if it's not already a string
                    if isinstance(soc_analyst_report, IncidentAnalysisOutput):
                        formatted_report = format_soc_analyst_report(soc_analyst_report)
                        f.write(formatted_report + "\n\n")
                    else:
                        f.write(str(soc_analyst_report) + "\n\n")
                    
                    # End of report
                    f.write("="*100 + "\n")
                    
                    print(f"\nComprehensive analysis saved to: {output_file}")
                    print(f"SOC analysis report successfully generated!")
            except Exception as e:
                print(f"Error saving report: {str(e)}")
                traceback.print_exc()
                
                # Create a very basic report even in case of catastrophic failure
                try:
                    # Ensure we have a unique output filename
                    report_time = datetime.now().strftime("%Y%m%d_%H%M%S")
                    output_path = f"incident_analysis_{incident_number}_{report_time}_basic.txt"
                    
                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write(f"BASIC INCIDENT REPORT - #{incident_number}\n")
                        f.write("="*100 + "\n\n")
                        f.write(f"Error occurred during analysis: {str(e)}\n")
                        
                        # Add basic incident details if available
                        if 'Title' in group.columns:
                            f.write(f"Title: {group['Title'].iloc[0]}\n")
                        if 'Severity' in group.columns:
                            f.write(f"Severity: {group['Severity'].iloc[0]}\n")
                        if 'Status' in group.columns:
                            f.write(f"Status: {group['Status'].iloc[0]}\n")
                        if 'CreatedTime' in group.columns:
                            f.write(f"Created: {group['CreatedTime'].iloc[0]}\n")
                        
                        print(f"Basic report saved to {output_path}")
                except Exception as e2:
                    print(f"Failed to create basic report: {str(e2)}")
                
                # Ask if user wants to see raw data
                try:
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
                except Exception as e3:
                    print(f"Error displaying raw data: {str(e3)}")
            
    except Exception as e:
        print(f"Error analyzing security incidents: {str(e)}")
        traceback.print_exc()

def get_security_incidents_from_api(days_back=30, include_title_filter=True, tenant_id=None, verbose=True):
    """
    Retrieve security incidents from Microsoft Sentinel
    
    Args:
        days_back (int): Number of days back to look for incidents
        include_title_filter (bool): Whether to filter for specific DNS TI incidents
        tenant_id (str): Optional tenant ID to filter incidents
        verbose (bool): Whether to print detailed information
    
    Returns:
        List of incident dictionaries or None if error
    """
    try:
        if verbose:
            print("Authenticating with Azure AD...")
        
        # Authentication
        authority_url = f"https://login.microsoftonline.com/{tenant_id or TENANT_ID}"
        resource = "https://api.loganalytics.io"

        context = adal.AuthenticationContext(authority_url)
        token = context.acquire_token_with_client_credentials(resource, CLIENT_ID, CLIENT_SECRET)
        access_token = token.get('accessToken')
        if not access_token:
            print("Error: Failed to acquire access token.")
            return []
        # Commenting out success message for brevity during normal operation
        # print("Authentication successful!")

        # Build KQL query
        query = f"""
        SecurityIncident
        | where TimeGenerated > ago({days_back}d)"""
        
        # Add title filter if specified - ensure this is in the initial query
        if include_title_filter:
            query += """
        | where Title == "[Custom]-[TI]-DNS with TI Domain Correlation" """
            
        # Add sorting and limit
        query += """
        | order by TimeGenerated desc"""

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
                # Remove the verbose column display
                pass
            
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
        incidents (list or DataFrame): List of incident dictionaries or DataFrame of incidents
        
    Returns:
        tuple: Selected incident group DataFrame and incident number
    """
    # Check if the incidents object is empty - handle both DataFrame and list cases
    if isinstance(incidents, pd.DataFrame):
        if incidents.empty:
            print("No incidents available to select.")
            return None, None
    elif not incidents:  # Handle list or None case
        print("No incidents available to select.")
        return None, None
    
    # Convert to DataFrame if it's not already one
    if not isinstance(incidents, pd.DataFrame):
        df = pd.DataFrame(incidents)
    else:
        df = incidents
    
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
    """
    Main entry point for security incident analysis.
    
    Args:
        excel_path (str): Path to Excel file with incidents
        tenant_id (str): Tenant ID (optional, can be passed to override env var)
        fetch_time (datetime): Time when incidents were fetched (for real-time confirmation)
        log_window_days (int): Number of days to include in log analysis window
        use_api (bool): Whether to fetch incidents directly from API
        api_days (int): Number of days to fetch when using API
        include_title_filter (bool): Whether to filter for specific DNS TI incidents
    """
    # Start time for the analysis
    start_time = datetime.now()
    
    # Dictionary to store all incidents dataframes by sheet name
    all_incidents = {}
    
    # Flag to track if real-time data is being used
    real_time_data = False
    
    try:
        if use_api:
            # Fetch incidents directly from API
            print("Fetching security incidents from Microsoft Sentinel API...")
            
            # Set tenant_id from environment variable if not provided
            if not tenant_id:
                tenant_id = TENANT_ID
                
            if not tenant_id:
                print("Error: Tenant ID not provided. Please provide tenant_id parameter or set TENANT_ID environment variable.")
                return
                
            api_incidents = get_security_incidents_from_api(
                days_back=api_days,
                include_title_filter=include_title_filter,
                tenant_id=tenant_id,
                verbose=True
            )
            
            if not api_incidents or len(api_incidents) == 0:
                print("No incidents found or error retrieving incidents from API.")
                return
                
            print(f"\nFound {len(api_incidents)} incidents from API.")
            
            # Convert list of incidents to DataFrame
            incidents_df = pd.DataFrame(api_incidents)
            
            # Set fetch time if not provided
            if not fetch_time:
                fetch_time = datetime.now()
                
            # Set flag for real-time data
            real_time_data = True
            
            # Store in all_incidents dictionary
            all_incidents['API_Incidents'] = incidents_df
            
            # Filter to keep only the most recent entry for each incident
            print("\nFiltering incidents to keep only the most recent entry for each unique incident...")
            incidents_df = incidents_df.sort_values('LastModifiedTime', ascending=False)
            original_count = len(incidents_df)
            incidents_df = incidents_df.drop_duplicates(subset=['IncidentNumber'], keep='first')
            filtered_count = len(incidents_df)
            print(f"Filtered from {original_count} to {filtered_count} unique incidents (keeping only the most recent entry for each)")
            
            # Show incident selection dialog and get user's selection
            incident_df, selected_incident_number = display_and_select_incident(incidents_df)
            if incident_df is None:
                print("No incident selected for analysis.")
                return
        else:
            # Check if Excel file path is provided
            if not excel_path:
                print("Error: Excel file path not provided.")
                return
                
            # Check if Excel file exists
            if not os.path.isfile(excel_path):
                print(f"Error: Excel file not found at {excel_path}")
                return
                
            # Get file creation time as fetch time if not provided
            if not fetch_time:
                fetch_time = datetime.fromtimestamp(os.path.getctime(excel_path))
                
            print(f"Reading security incidents from Excel file: {excel_path}")
            
            # Load Excel file with pandas
            excel = pd.ExcelFile(excel_path)
            
            # Load each sheet into a DataFrame and store in all_incidents dictionary
            for sheet_name in excel.sheet_names:
                print(f"Reading sheet: {sheet_name}")
                df = pd.read_excel(excel, sheet_name=sheet_name)
                
                # Filter to keep only the most recent entry for each incident
                if 'LastModifiedTime' in df.columns and 'IncidentNumber' in df.columns:
                    print(f"\nFiltering sheet {sheet_name} to keep only the most recent entry for each unique incident...")
                    original_count = len(df)
                    df = df.sort_values('LastModifiedTime', ascending=False)
                    df = df.drop_duplicates(subset=['IncidentNumber'], keep='first')
                    filtered_count = len(df)
                    print(f"Filtered from {original_count} to {filtered_count} unique incidents (keeping only the most recent entry for each)")
                
                all_incidents[sheet_name] = df
                
            # Check if any incidents were found
            if not all_incidents:
                print("No incidents found in Excel file.")
                return
                
            # Get the first sheet for analysis if not specified
            incident_sheet = list(all_incidents.keys())[0]
            incident_df = all_incidents[incident_sheet]
            
            # Display incidents and let user select one if multiple are found
            if len(incident_df) > 1:
                # Show incident selection dialog
                incident_df, selected_incident_number = display_and_select_incident(incident_df)
            
        # Ensure the incident DataFrame has necessary columns
        required_cols = ['Title', 'IncidentNumber', 'Severity', 'Status', 'Owner']
        missing_cols = [col for col in required_cols if col not in incident_df.columns]
        
        if missing_cols:
            print(f"Warning: Incident data is missing required columns: {', '.join(missing_cols)}")
            print("Available columns:", incident_df.columns.tolist())
            
        # Check if incidents were found
        if incident_df.empty:
            print("No incidents found for analysis.")
            return
        
        # Analyze each incident
        for incident_number, group in incident_df.groupby('IncidentNumber'):
            print(f"\nAnalyzing incident: {incident_number}")
            print("="*100)
            
            # Extracts data about the incident
            try:
                output_file = os.path.join(os.path.dirname(excel_path) if excel_path else ".", 
                                         f"incident_analysis_{incident_number}_{start_time.strftime('%Y%m%d_%H%M%S')}.txt")
                
                # Get basic incident info
                incident_title = group['Title'].iloc[0] if 'Title' in group.columns else 'Unknown'
                incident_severity = group['Severity'].iloc[0] if 'Severity' in group.columns else 'Unknown'
                incident_status = group['Status'].iloc[0] if 'Status' in group.columns else 'Unknown'
                
                print(f"Incident #{incident_number}: {incident_title}")
                print(f"Status: {incident_status}, Severity: {incident_severity}")
                
                # Get incident description
                incident_description = ''
                if 'Description' in group.columns:
                    incident_description = group['Description'].iloc[0]
                    if incident_description and len(incident_description) > 0:
                        print(f"\nDescription: {incident_description[:100]}...")
                
                # Extract comments if available
                comments = []
                if 'Comments' in group.columns:
                    # Get all non-null comments
                    all_comments = group['Comments'].dropna().tolist()
                    comments = [c for c in all_comments if c]
                        
                # Analyze comments
                comment_analysis = analyze_comments(comments)
                
                print("\n1. EXTRACTING SECURITY INDICATORS...")
                
                # Extract security indicators
                raw_text = " ".join([
                    str(val) for col in group.columns 
                    for val in group[col].fillna('').astype(str).tolist()
                ])
                
                indicators = extract_security_indicators(raw_text)
                if indicators:
                    print(f"Found: {len(indicators.domains)} domains, {len(indicators.ips)} IPs, {len(indicators.users)} users")
                
                # Extract AlertIds from the incident and retrieve corresponding alerts
                print("\n1.1 RETRIEVING ASSOCIATED SECURITY ALERTS...")
                alert_ids = extract_alert_ids(group)
                
                if alert_ids:
                    print(f"Found {len(alert_ids)} alert IDs associated with this incident")
                    # Query for the alerts with these IDs
                    alerts = get_security_alerts_for_incident(
                        alert_ids=alert_ids,
                        days_back=log_window_days * 2,  # Use wider window to ensure alerts are found
                        tenant_id=tenant_id,
                        verbose=True
                    )
                    
                    if alerts:
                        print(f"Retrieved {len(alerts)} security alerts for correlation")
                        
                        # Enhance indicators with alert entities
                        print("\n1.2 ENHANCING INDICATORS WITH ALERT ENTITIES...")
                        indicators = enhance_indicators_with_entities(alerts, indicators)
                        print(f"Enhanced indicators: {len(indicators.domains)} domains, {len(indicators.ips)} IPs, {len(indicators.users)} users")
                    else:
                        print("No matching security alerts found")
                else:
                    print("No alert IDs found in the incident data")
                    alerts = []
                
                # Fetch related logs
                print("\n2. FETCHING RELATED LOGS...")
                logs = []
                
                # Get time range for logs
                try:
                    if 'CreatedTime' in group.columns and not group['CreatedTime'].isnull().all():
                        # Use the incident creation time
                        start_time_dt = pd.to_datetime(group['CreatedTime'].iloc[0])
                        # If log_window_days is provided, use that as the window
                        if log_window_days > 0:
                            end_time_dt = start_time_dt + timedelta(days=log_window_days)
                        else:
                            # Otherwise use the incident resolution time if available
                            if 'TimeToResolve' in group.columns and not group['TimeToResolve'].isnull().all():
                                resolve_time = group['TimeToResolve'].iloc[0]
                                if isinstance(resolve_time, (int, float)):
                                    # If TimeToResolve is a number of hours
                                    end_time_dt = start_time_dt + timedelta(hours=resolve_time)
                                elif isinstance(resolve_time, str):
                                    # Try to parse as duration string (e.g., "5 hours")
                                    try:
                                        hours = float(resolve_time.split()[0])
                                        end_time_dt = start_time_dt + timedelta(hours=hours)
                                    except:
                                        # If parsing fails, use default log window
                                        end_time_dt = start_time_dt + timedelta(days=log_window_days or 7)
                                else:
                                    # Use default log window if TimeToResolve is in an unknown format
                                    end_time_dt = start_time_dt + timedelta(days=log_window_days or 7)
                            else:
                                # If no resolution time, use default log window
                                end_time_dt = start_time_dt + timedelta(days=log_window_days or 7)
                        
                        # Format times for API call
                        start_time_iso = start_time_dt.isoformat()
                        end_time_iso = end_time_dt.isoformat()
                        
                        # Fetch logs
                        logs = fetch_relevant_logs(start_time_iso, end_time_iso, indicators)
                    else:
                        print("Warning: Could not determine time range for logs. Using fixed window.")
                        # Use a fixed window based on current time
                        end_time_dt = datetime.now()
                        start_time_dt = end_time_dt - timedelta(days=log_window_days or 7)
                        
                        # Format times for API call
                        start_time_iso = start_time_dt.isoformat()
                        end_time_iso = end_time_dt.isoformat()
                        
                        # Fetch logs
                        logs = fetch_relevant_logs(start_time_iso, end_time_iso, indicators)
                except Exception as e:
                    print(f"Warning: Could not fetch logs: {e}")
                
                # Format log output
                log_summary = format_log_summary(logs)
                
                # Analyze log patterns
                patterns = None
                log_pattern_summary = ""
                if logs:
                    print("\n3. ANALYZING LOG PATTERNS...")
                    try:
                        # Get primary domain
                        primary_domain = indicators.domains[0] if indicators.domains else None
                        
                        # Get incident information for context
                        incident_info = {
                            "title": incident_title,
                            "number": incident_number,
                            "severity": incident_severity,
                            "status": incident_status,
                            "description": incident_description
                        }
                        
                        # Analyze patterns
                        patterns = analyze_log_patterns(logs, primary_domain)
                        
                        # Format patterns
                        formatted_patterns = format_log_patterns(patterns, primary_domain)
                        
                        # Skip LLM interpretation
                        log_pattern_summary = ""
                    except Exception as e:
                        print(f"Error analyzing log patterns: {e}")
                        log_pattern_summary = "Error analyzing log patterns."
                    
                # Check for VirusTotal domain data
                vt_results = ""
                if VIRUSTOTAL_AVAILABLE and indicators.domains:
                    print("\n4. CHECKING DOMAIN REPUTATION...")
                    try:
                        domains_data = analyze_domains(indicators.domains)
                        vt_results = format_vt_results(domains_data)
                    except Exception as e:
                        print(f"Error retrieving VirusTotal data: {e}")
                        vt_results = "Error retrieving VirusTotal data."
                    
                # Generate output file
                print(f"\nWriting analysis to {output_file}...")
                with open(output_file, 'w') as f:
                    # Format output
                    f.write(f"SECURITY INCIDENT ANALYSIS - #{incident_number}\n")
                    f.write("====================================================================================================\n\n")
                    
                    # Add real-time analysis confirmation
                    f.write("REAL-TIME ANALYSIS CONFIRMATION:\n")
                    fetch_time_str = fetch_time.strftime("%Y-%m-%d %H:%M:%S") if fetch_time else start_time.strftime("%Y-%m-%d %H:%M:%S")
                    analysis_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    f.write(f"Security incidents fetched on: {fetch_time_str}\n")
                    f.write(f"Analysis time: {analysis_time_str}\n")
                    f.write(f"Log analysis window: {log_window_days} days\n\n")
                    
                    f.write("1. SECURITY INDICATORS\n")
                    f.write("--------------------\n")
                    f.write(f"Domains: {', '.join(indicators.domains) if indicators.domains else 'None'}\n")
                    f.write(f"IPs: {', '.join(indicators.ips) if indicators.ips else 'None'}\n")
                    f.write(f"Users: {', '.join(indicators.users) if indicators.users else 'None'}\n")
                    f.write(f"Processes: {', '.join(indicators.processes) if indicators.processes else 'None'}\n")
                    
                    # Add alert correlation section
                    if alerts:
                        f.write("\n2. CORRELATED SECURITY ALERTS\n")
                        f.write("---------------------------\n")
                        f.write(f"Number of correlated alerts: {len(alerts)}\n\n")
                        
                        for i, alert in enumerate(alerts[:5], 1):  # Show top 5 alerts
                            f.write(f"Alert {i}:\n")
                            f.write(f"  Title: {alert.get('AlertName', 'Unknown')}\n")
                            f.write(f"  Severity: {alert.get('AlertSeverity', 'Unknown')}\n")
                            f.write(f"  Time: {alert.get('TimeGenerated', 'Unknown')}\n")
                            f.write(f"  Description: {alert.get('Description', 'No description')[:150]}...\n\n")
                        
                        if len(alerts) > 5:
                            f.write(f"... {len(alerts) - 5} more alerts not shown ...\n\n")
                    f.write("\n")
                    
                    # Add security indicators section
                    f.write("3. VIRUSTOTAL DOMAIN REPUTATION\n")
                    f.write("----------------------------\n")
                    f.write(vt_results + "\n\n")
                    
                    # Add log patterns section
                    f.write("4. ATTACK CHAIN RECONSTRUCTION\n")
                    f.write("---------------------------\n")
                    f.write(formatted_patterns + "\n\n")
                    
                    # Add related incidents section
                    if related_incidents_data:
                        f.write("5. RELATED INCIDENTS\n")
                        f.write("-------------------\n")
                        f.write(related_incidents_text + "\n\n")
                    
                    # Add comment analysis and progression section
                    f.write("6. INVESTIGATION CONTEXT (Based on Comments):\n")
                    f.write("-----------------------------------------\n")
                    f.write(f"Total Comments: {comment_analysis.get('total_comments', 0)}\n")
                    f.write(f"LLM Summary: {llm_comment_summary}\n\n")
                    
                    # Add MITRE ATT&CK section if techniques found
                    if mitre_techniques:
                        mitre_info = get_mitre_attack_info(mitre_techniques, technique_details)
                        f.write("7. MITRE ATT&CK TECHNIQUES:\n")
                        f.write("-------------------------\n")
                        f.write(mitre_info + "\n\n")
                    
                    # Add SOC Analyst L1 Triage Report section
                    f.write("8. SOC ANALYST L1 TRIAGE REPORT:\n")
                    f.write("===============================\n")
                    f.write(context_analysis + "\n\n")
                    
                    # Add Enhanced SOC Analyst Report section
                    f.write("9. ENHANCED SOC ANALYST REPORT:\n")
                    f.write("==============================\n")
                    # Format the IncidentAnalysisOutput object if it's not already a string
                    if isinstance(soc_analyst_report, IncidentAnalysisOutput):
                        formatted_report = format_soc_analyst_report(soc_analyst_report)
                        f.write(formatted_report + "\n\n")
                    else:
                        f.write(str(soc_analyst_report) + "\n\n")
                    
                    # End of report
                    f.write("="*100 + "\n")
                    
                    print(f"\nComprehensive analysis saved to: {output_file}")
                    print(f"SOC analysis report successfully generated!")
            except Exception as e:
                print(f"Error saving report: {str(e)}")
                traceback.print_exc()
                
                # Create a very basic report even in case of catastrophic failure
                try:
                    # Ensure we have a unique output filename
                    report_time = datetime.now().strftime("%Y%m%d_%H%M%S")
                    output_path = f"incident_analysis_{incident_number}_{report_time}_basic.txt"
                    
                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write(f"BASIC INCIDENT REPORT - #{incident_number}\n")
                        f.write("="*100 + "\n\n")
                        f.write(f"Error occurred during analysis: {str(e)}\n")
                        
                        # Add basic incident details if available
                        if 'Title' in group.columns:
                            f.write(f"Title: {group['Title'].iloc[0]}\n")
                        if 'Severity' in group.columns:
                            f.write(f"Severity: {group['Severity'].iloc[0]}\n")
                        if 'Status' in group.columns:
                            f.write(f"Status: {group['Status'].iloc[0]}\n")
                        if 'CreatedTime' in group.columns:
                            f.write(f"Created: {group['CreatedTime'].iloc[0]}\n")
                        
                        print(f"Basic report saved to {output_path}")
                except Exception as e2:
                    print(f"Failed to create basic report: {str(e2)}")
                
                # Ask if user wants to see raw data
                try:
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
                except Exception as e3:
                    print(f"Error displaying raw data: {str(e3)}")
            
    except Exception as e:
        print(f"Error analyzing security incidents: {str(e)}")
        traceback.print_exc()

def get_security_alerts_for_incident(alert_ids=None, days_back=30, tenant_id=None, workspace_id=None, verbose=True):
    """
    Retrieve security alerts from Microsoft Sentinel
    
    Args:
        alert_ids (list): Optional list of alert IDs to filter by
        days_back (int): Number of days back to look for alerts
        tenant_id (str): Optional tenant ID to filter alerts
        workspace_id (str): Optional workspace ID for Log Analytics
        verbose (bool): Whether to print detailed information
    
    Returns:
        List of alert dictionaries or None if error
    """
    try:
        if verbose:
            print("Authenticating with Azure AD for SecurityAlert retrieval...")
        
        # Authentication
        authority_url = f"https://login.microsoftonline.com/{tenant_id or TENANT_ID}"
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

        if verbose:
            print(f"\nExecuting SecurityAlert query:\n{query}\n")

        # API endpoint
        url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id or WORKSPACE_ID}/query"

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
            alerts = []
            
            # Remove column information display
            
            for table in results['tables']:
                column_names = [col['name'] for col in table['columns']]
                rows = table['rows']
                
                for row in rows:
                    alert_entry = dict(zip(column_names, row))
                    alerts.append(alert_entry)
            
            if verbose:
                print(f"\nFound {len(alerts)} security alerts")
            
            return alerts
        else:
            print(f"Error: {response.status_code}")
            print(f"Error details: {response.text}")
            return None

    except Exception as e:
        print(f"An error occurred retrieving alerts: {str(e)}")
        return None

def extract_alert_ids(incident_data):
    """
    Extract AlertIds from incident data and clean them
    
    Args:
        incident_data (pd.DataFrame): DataFrame containing incident data
    
    Returns:
        list: List of cleaned alert IDs
    """
    alert_ids = []
    
    if 'AlertIds' in incident_data.columns:
        # Get all AlertIds from the incident data
        all_alert_ids = incident_data['AlertIds'].dropna().tolist()
        
        for alert_id_str in all_alert_ids:
            try:
                # Handle different formats of AlertIds
                if isinstance(alert_id_str, str):
                    # Remove brackets, quotes, and spaces if in JSON array format ["id1", "id2"]
                    if alert_id_str.startswith('[') and alert_id_str.endswith(']'):
                        # Try to parse as JSON array
                        import json
                        try:
                            parsed_ids = json.loads(alert_id_str)
                            if isinstance(parsed_ids, list):
                                alert_ids.extend(parsed_ids)
                            continue
                        except:
                            pass
                        
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
                print(f"Error parsing AlertId {alert_id_str}: {str(e)}")
    
    # Remove duplicates
    return list(set(alert_ids))

def enhance_indicators_with_entities(alerts, indicators):
    """
    Enhance SecurityIndicators with data from alert entities
    
    Args:
        alerts (list): List of alert dictionaries
        indicators (SecurityIndicators): Existing security indicators
    
    Returns:
        SecurityIndicators: Enhanced indicators
    """
    if not alerts:
        return indicators
    
    # Keep track of new items found
    new_domains = []
    new_ips = []
    new_file_hashes = []
    new_urls = []
    new_users = []
    
    for alert in alerts:
        if 'Entities' in alert and alert['Entities']:
            try:
                # Try to parse Entities as JSON
                import json
                entities = None
                
                if isinstance(alert['Entities'], str):
                    try:
                        entities = json.loads(alert['Entities'])
                    except:
                        # If parsing fails, try to extract using regex
                        import re
                        # Extract domains
                        domains = re.findall(r'DomainName":\s*"([^"]+)"', alert['Entities'])
                        new_domains.extend(domains)
                        
                        # Extract IPs
                        ips = re.findall(r'Address":\s*"([^"]+)"', alert['Entities'])
                        new_ips.extend(ips)
                        
                        # Extract URLs
                        urls = re.findall(r'Url":\s*"([^"]+)"', alert['Entities'])
                        new_urls.extend(urls)
                        
                        # Extract users
                        users = re.findall(r'Name":\s*"([^"]+)"', alert['Entities'])
                        new_users.extend(users)
                        
                        # Extract file hashes
                        hashes = re.findall(r'FileHash":\s*"([^"]+)"', alert['Entities'])
                        new_file_hashes.extend(hashes)
                else:
                    entities = alert['Entities']
                
                if entities and isinstance(entities, list):
                    for entity in entities:
                        if isinstance(entity, dict):
                            # Extract domains
                            if 'DomainName' in entity and entity['DomainName']:
                                new_domains.append(entity['DomainName'])
                            
                            # Extract IPs
                            if 'Address' in entity and entity['Address']:
                                new_ips.append(entity['Address'])
                            
                            # Extract URLs
                            if 'Url' in entity and entity['Url']:
                                new_urls.append(entity['Url'])
                            
                            # Extract users
                            if 'Name' in entity and entity['Type'] == 'account' and entity['Name']:
                                new_users.append(entity['Name'])
                            
                            # Extract file hashes
                            if 'FileHash' in entity and entity['FileHash']:
                                new_file_hashes.append(entity['FileHash'])
            except Exception as e:
                print(f"Error parsing entities: {str(e)}")
    
    # Add the new items to the indicators
    indicators.domains.extend([d for d in new_domains if d not in indicators.domains])
    indicators.ips.extend([ip for ip in new_ips if ip not in indicators.ips])
    indicators.file_hashes.extend([h for h in new_file_hashes if h not in indicators.file_hashes])
    indicators.urls.extend([u for u in new_urls if u not in indicators.urls])
    indicators.users.extend([u for u in new_users if u not in indicators.users])
    
    return indicators

def display_security_table_mapping():
    """
    Display a mapping between the most important columns in SecurityIncident and SecurityAlert tables
    """
    print("\n=== Security Table Column Mapping ===\n")
    print("This mapping shows the relationship between key columns in SecurityIncident and SecurityAlert tables.")
    
    # Create a table-like format for the mapping
    mapping = [
        ["Incident Column", "Alert Column", "Description"],
        ["-------------", "------------", "------------"],
        ["IncidentNumber", "N/A", "Unique identifier for the incident"],
        ["Title", "DisplayName/AlertName", "Name of the incident/alert"],
        ["Description", "Description", "Detailed description of the incident/alert"],
        ["Severity", "AlertSeverity", "Severity level (High, Medium, Low)"],
        ["Status", "Status", "Current status (New, Active, Closed)"],
        ["Classification", "N/A", "Incident classification"],
        ["ClassificationReason", "N/A", "Reason for classification"],
        ["ClassificationComment", "N/A", "Additional comments on classification"],
        ["Owner", "N/A", "Owner of the incident"],
        ["CreatedTimeUTC", "TimeGenerated", "When the incident/alert was created"],
        ["LastModifiedTimeUTC", "N/A", "When the incident was last modified"],
        ["FirstActivityTimeUTC", "StartTime", "When the activity first started"],
        ["LastActivityTimeUTC", "EndTime", "When the activity ended"],
        ["ProviderName", "ProviderName", "Provider that generated the incident/alert"],
        ["AlertIds", "SystemAlertId", "Alert IDs associated with incident / Alert ID"],
        ["Tactics", "Tactics", "MITRE ATT&CK tactics"],
        ["Techniques", "Techniques", "MITRE ATT&CK techniques"],
        ["N/A", "AlertType", "Type of the alert"],
        ["N/A", "Entities", "Entities involved in the alert (JSON)"],
        ["AdditionalData", "ExtendedProperties", "Additional JSON data"]
    ]
    
    # Display the mapping in a tabular format
    for row in mapping:
        print(f"{row[0]:<25} {row[1]:<25} {row[2]}")
    
    print("\n=== Key Relationships ===")
    print("• SecurityIncident.AlertIds contains SystemAlertId values from SecurityAlert table")
    print("• Alerts can be correlated to incidents using: SecurityAlert.SystemAlertId ∈ SecurityIncident.AlertIds")
    print("• Multiple alerts can be associated with a single incident")

def display_incident_with_alerts(incident, alerts):
    """
    Display a security incident with its corresponding alerts
    
    Args:
        incident (pd.DataFrame): DataFrame containing the incident data
        alerts (list): List of alert dictionaries
    """
    # Convert DataFrame to dictionary if needed
    if isinstance(incident, pd.DataFrame):
        if len(incident) > 0:
            incident = incident.iloc[0].to_dict()
        else:
            print("Empty incident data provided")
            return

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
        ("Created", incident.get('CreatedTimeUTC', incident.get('TimeGenerated', 'Unknown'))),
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
    alert_ids_from_incident = extract_alert_ids(pd.DataFrame([incident]))
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

def investigate_incident_alerts(incident_data, tenant_id=None, workspace_id=None):
    """
    Investigate a specific incident by retrieving and displaying its related alerts
    
    Args:
        incident_data (pd.DataFrame or tuple): DataFrame containing the incident to investigate, 
                                              or a tuple of (DataFrame, incident_number)
        tenant_id (str): Optional tenant ID
        workspace_id (str): Optional workspace ID
    """
    try:
        print("\n=== Investigating Incident Alerts ===\n")
        
        # Handle both tuple and DataFrame inputs
        if isinstance(incident_data, tuple):
            # Extract DataFrame from tuple (display_and_select_incident returns (df, incident_number))
            incident_df, incident_number = incident_data
            if incident_df is None or incident_df.empty:
                print("No incident data provided for investigation.")
                return
        else:
            # Direct DataFrame input
            incident_df = incident_data
            if incident_df.empty:
                print("No incident data provided for investigation.")
                return
            incident_number = None  # We'll extract it below if needed
        
        # Get the incident (first row if multiple)
        incident_row = incident_df.iloc[0]
        if not incident_number:
            incident_number = incident_row.get('IncidentNumber', 'Unknown')
        
        print(f"Investigating alerts for incident #{incident_number}...")
        
        # Extract alert IDs
        alert_ids = extract_alert_ids(incident_df)
        
        if not alert_ids:
            print("No alert IDs found in incident. Investigation cannot proceed.")
            return
        
        print(f"Found {len(alert_ids)} alert ID(s) to investigate")
        
        # Get security alerts for these IDs
        alerts = get_security_alerts_for_incident(
            alert_ids=alert_ids,
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            verbose=True
        )
        
        if not alerts:
            print("No matching security alerts found for this incident.")
            return
        
        # Extract domains from alert entities
        print("\nExtracting domains from alert entities...")
        domains = extract_domains_from_alerts(alerts)
        
        # Display incident with its alerts
        display_incident_with_alerts(incident_row, alerts)
        
        # Check domain reputation AFTER displaying the main incident/alert info
        print("\n=== VirusTotal Domain Reputation Check ===")
        vt_checked = False # Flag to track if VT check was performed
        vt_info = {} # Initialize vt_info dictionary
        if domains:
            if VIRUSTOTAL_AVAILABLE:
                print("Checking domain reputation with VirusTotal...")
                try:
                    vt_results = analyze_domains(domains)
                    print(f"VirusTotal analysis complete. Found results for {len(vt_results)} domain(s).")
                    vt_info = vt_results # Store results
                    # Display VirusTotal results
                    if vt_results:
                        print("\n" + format_vt_results(vt_results))
                    else:
                        print("No suspicious domains found in VirusTotal.")
                except Exception as e:
                    print(f"Error checking domains with VirusTotal: {str(e)}")
                    # vt_info remains empty on error
                vt_checked = True # Mark that VT check was attempted/completed
            else:
                print("VirusTotal integration not available. Skipping domain reputation checks.")
                # vt_info remains empty
        else:
            print("No domains found in alert entities to check with VirusTotal.")
            # vt_info remains empty
        
        # Fetch and display relevant logs AFTER VirusTotal check
        print("\n=== Relevant Log Fetching (Based on Alert Domains) ===")
        if domains:
            try:
                # Determine time window (e.g., +/- 1 hour around incident creation)
                incident_time_str = incident_row.get('TimeGenerated', incident_row.get('CreatedTimeUTC'))
                if incident_time_str:
                    incident_time = pd.to_datetime(incident_time_str)
                    start_time_log = incident_time - timedelta(hours=1)
                    end_time_log = incident_time + timedelta(hours=1)
                    start_time_iso = start_time_log.isoformat()
                    end_time_iso = end_time_log.isoformat()
                    
                    print(f"Defining log time window: {start_time_iso} to {end_time_iso}")
                    
                    # Create indicators object with only the domains
                    log_indicators = SecurityIndicators(domains=domains)
                    
                    # Fetch logs
                    print("Fetching relevant logs (limit 100)...")
                    relevant_logs = fetch_relevant_logs(start_time_iso, end_time_iso, log_indicators, limit=100)
                    
                    # Format and print log summary
                    log_summary = format_log_summary(relevant_logs, limit=100)
                    print("\nRAW LOG SUMMARY (Top 10):") # Renamed for clarity
                    print(log_summary)
                    
                    # Analyze patterns in the fetched logs
                    print("\nAnalyzing log patterns...")
                    patterns = analyze_log_patterns(relevant_logs, domain=domains[0] if domains else None)
                    
                    # Format and print log patterns
                    formatted_patterns = format_log_patterns(patterns, domain=domains[0] if domains else None)
                    print("\nLOG PATTERNS:")
                    print(formatted_patterns)
                    
                    # Generate and display SOC analyst report
                    print("\n=== Generating SOC Analyst Report ===")
                    
                    # Prepare incident data for the report
                    incident_info = {
                        "incident_number": incident_row.get('IncidentNumber', 'Unknown'),
                        "title": incident_row.get('Title', '[Custom]-[TI]-DNS with TI Domain Correlation'),
                        "severity": incident_row.get('Severity', 'Low'),
                        "status": incident_row.get('Status', 'Closed'),
                        "owner": incident_row.get('Owner', 'Azhar Hassan'),
                        "description": incident_row.get('Description', '')
                    }
                    
                    # Create a comprehensive indicators object for the report
                    indicators = SecurityIndicators(domains=domains)
                    
                    # Enhance the indicators with domain details
                    if domains:
                        # Add VirusTotal reputation if available
                        vt_info = {}
                        if 'vt_results' in locals() and vt_results:
                            for domain, data in vt_results.items():
                                if isinstance(data, dict):
                                    if domain in domains:
                                        vt_info = {
                                            "domain": domain,
                                            "virustotal_reputation": data.get('reputation_score', 'Unknown'),
                                            "malicious_votes": data.get('malicious_votes', 'Unknown'),
                                            "total_engines": data.get('total_engines', 'Unknown')
                                        }
                        
                        # Add threat intel context with domain and VT info
                        if vt_info:
                            indicators.threat_intel_context = vt_info
                        else:
                            indicators.threat_intel_context = {"domain": domains[0]}
                    
                    # Generate asset impact info from logs
                    affected_devices = {}
                    active_users = {}
                    affected_ips = []
                    
                    for log in relevant_logs:
                        # Track device occurrences
                        device = log.get('Computer', log.get('DeviceName', log.get('HostName')))
                        if device:
                            affected_devices[device] = affected_devices.get(device, 0) + 1
                        
                        # Track user activity
                        user = log.get('SourceUserName', log.get('UserName', log.get('User')))
                        if user:
                            active_users[user] = active_users.get(user, 0) + 1
                        
                        # Track IPs
                        ip = log.get('SourceIP', log.get('DestinationIP'))
                        if ip and ip not in affected_ips:
                            affected_ips.append(ip)
                    
                    # Get most active device and user
                    most_active_device = None
                    most_device_hits = 0
                    for device, hits in affected_devices.items():
                        if hits > most_device_hits:
                            most_active_device = device
                            most_device_hits = hits
                    
                    most_active_user = None
                    most_user_hits = 0
                    for user, hits in active_users.items():
                        if hits > most_user_hits:
                            most_active_user = user
                            most_user_hits = hits
                    
                    # Set asset impact analysis
                    if most_active_device or most_active_user:
                        asset_info = {}
                        if most_active_device:
                            asset_info["affected_device"] = f"{most_active_device} ({most_device_hits} occurrences)"
                        if most_active_user:
                            asset_info["most_active_user"] = f"{most_active_user} ({most_user_hits} hits)"
                        indicators.asset_impact_analysis = asset_info
                    
                    # Set metrics panel with incident details
                    metrics = {
                        "incident_number": incident_row.get('IncidentNumber', 'Unknown'),
                        "status": incident_row.get('Status', 'Open'),
                        "owner": incident_row.get('Owner', 'Unassigned'),
                        "detection_source": "ASI Scheduled Alerts"
                    }
                    
                    # Assign metrics to the indicators object
                    indicators.metrics_panel = metrics
                    
                    # Add MITRE ATT&CK techniques for DNS with TI correlation (T1071 Command and Control)
                    indicators.attack_techniques = ["T1071 (Command and Control)"]
                    indicators.technique_details = {
                        "T1071": {
                            "name": "Application Layer Protocol",
                            "tactic": "Command and Control",
                            "description": "Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic.",
                            "mitigation": "Monitor for unusual DNS/HTTP patterns, analyze traffic for suspicious domains, implement protocol whitelisting."
                        }
                    }
                    
                    # Add format examples for the report
                    # These only guide the LLM on structure, not specific actions to recommend
                    example_actions = [
                        {"description": "Block suspicious domains at network level", "status": "Apply"},
                        {"description": "Isolate affected systems", "status": "Apply"},
                        {"description": "Monitor suspicious user activity", "status": "Apply"},
                        {"description": "Restrict access if suspicious behavior is confirmed", "status": "Pending"},
                        {"description": "Collect forensic data from affected systems", "status": "Apply"},
                        {"description": "Review relevant system logs", "status": "Apply"},
                        {"description": "Escalate to appropriate response team", "status": "Escalate"}
                    ]
                    
                    # Format examples for future steps
                    example_future_steps = [
                        {"description": "Review relevant DNS activity", 
                         "data_points": ["[EVIDENCE POINT 1]", 
                                         "[EVIDENCE POINT 2]"]},
                        {"description": "Investigate blocked security events", 
                         "data_points": ["[EVIDENCE POINT 1]", 
                                        "[EVIDENCE POINT 2]"]},
                        {"description": "Analyze network traffic for suspicious patterns", 
                         "data_points": ["[EVIDENCE POINT 1]", 
                                        "[EVIDENCE POINT 2]"]},
                        {"description": "Monitor for lateral movement", 
                         "data_points": ["[EVIDENCE POINT 1]",
                                        "[EVIDENCE POINT 2]"]},
                        {"description": "Enrich findings with threat intelligence", 
                         "data_points": ["[EVIDENCE POINT 1]", 
                                        "[EVIDENCE POINT 2]"]}
                    ]
                    
                    # Generate the SOC analyst report
                    soc_report = generate_soc_analyst_report(
                        incident_info, 
                        relevant_logs, 
                        indicators, 
                        alerts,
                        example_actions=example_actions,
                        example_future_steps=example_future_steps,
                        threat_intel_context=vt_info
                    )
                    
                    # Display the report
                    if isinstance(soc_report, IncidentAnalysisOutput):
                        formatted_report = format_soc_analyst_report(soc_report)
                        print(formatted_report)
                    else:
                        print(soc_report)
                    
                    # Optionally save the report to a file
                    report_file = f"incident_{incident_row.get('IncidentNumber', 'unknown')}_report.txt"
                    try:
                        with open(report_file, 'w', encoding='utf-8') as f:
                            if isinstance(soc_report, IncidentAnalysisOutput):
                                formatted_report = format_soc_analyst_report(soc_report)
                                f.write(formatted_report)
                            else:
                                f.write(str(soc_report))
                        print(f"\nReport saved to {report_file}")
                    except Exception as e:
                        print(f"Could not save report to file: {str(e)}")
                
                else:
                    print("Could not determine incident time for log fetching.")
                    
            except Exception as log_e:
                print(f"Error fetching or processing logs: {str(log_e)}")
        else:
            print("No domains extracted from alerts, skipping log fetch.")
            
    except Exception as e:
        print(f"Error investigating incident alerts: {str(e)}")
        traceback.print_exc()

def extract_domains_from_alerts(alerts):
    """
    Extract domains from alert entities
    
    Args:
        alerts (list): List of alert dictionaries
    
    Returns:
        list: List of unique domains
    """
    import ast
    # Helper: normalise and validate domains before returning
    def _normalise(domain: str):
        if not domain or not isinstance(domain, str):
            return None
        d = domain.strip().lower().rstrip('.')  # strip space / trailing dot
        # Very small sanity check: must contain a dot and at least 2‑char TLD
        if '.' not in d:
            return None
        if len(d.split('.')[-1]) < 2:
            return None
        return d

    domains = []
    
    print(f"\nStarting domain extraction from {len(alerts)} alerts")
    for i, alert in enumerate(alerts):
        print(f"\nProcessing alert #{i+1}:")
        if 'Entities' in alert and alert['Entities']:
            print(f"  Found Entities field. Type: {type(alert['Entities'])}")
            print(f"  Raw value preview: {str(alert['Entities'])[:100]}..." if len(str(alert['Entities'])) > 100 else str(alert['Entities']))
            
            try:
                # Try to parse Entities – handle JSON, literal lists or already‑parsed list
                raw_entities = alert['Entities']

                entities = None
                if isinstance(raw_entities, list):
                    entities = raw_entities
                    print(f"  Entities is already a list with {len(entities)} items")
                elif isinstance(raw_entities, str):
                    # First try JSON, then python literal (for single quotes)
                    try:
                        print("  Trying JSON parse...")
                        entities = json.loads(raw_entities)
                        print(f"  JSON parse succeeded: {str(entities)[:100]}...")
                    except Exception as e1:
                        print(f"  JSON parse failed: {str(e1)}")
                        try:
                            print("  Trying literal_eval...")
                            entities = ast.literal_eval(raw_entities)
                            print(f"  literal_eval succeeded: {str(entities)[:100]}...")
                        except Exception as e2:
                            print(f"  literal_eval failed: {str(e2)}")
                            entities = None
                            # Fallback regex search
                            import re
                            print("  Falling back to regex extraction...")
                            extracted_domains = re.findall(r'DomainName":\s*"([^"]+)"', raw_entities)
                            print(f"  Regex found {len(extracted_domains)} domains: {extracted_domains}")
                            domains.extend(extracted_domains)
                
                # Extract domain-like values from structured entity list
                if entities and isinstance(entities, list):
                    from urllib.parse import urlparse
                    print(f"  Processing {len(entities)} entities...")
                    for entity in entities:
                        if not isinstance(entity, dict):
                            continue
                        possible_values = [
                            entity.get('DomainName'),
                            entity.get('Fqdn'),
                            entity.get('HostName'),
                            entity.get('Host')
                        ]

                        # Handle Url separately to parse netloc
                        if 'Url' in entity and entity['Url']:
                            try:
                                parsed = urlparse(entity['Url'])
                                if parsed.netloc:
                                    possible_values.append(parsed.netloc)
                            except Exception:
                                pass

                        for val in possible_values:
                            nv = _normalise(val)
                            if nv:
                                print(f"  Found domain: {nv}")
                                domains.append(nv)
            except Exception as e:
                print(f"  Error extracting domains: {str(e)}")
        else:
            print("  No Entities field found in this alert")

    # Filter out common benign Microsoft domains
    benign_suffixes = ('.microsoft.com', '.windows.com', '.office.com')
    filtered = [d for d in domains if d and not d.startswith('microsoft.') and not any(d.endswith(sfx) for sfx in benign_suffixes)]
    
    print(f"\nDomain extraction complete. Found {len(filtered)} domains: {filtered}")
    # De‑duplicate & return
    return list(set(filtered))

def format_soc_analyst_report(analysis_output: IncidentAnalysisOutput) -> str:
    """
    Format the incident analysis output into a SOC analyst report with immediate actions and future steps.
    
    Args:
        analysis_output: The IncidentAnalysisOutput object containing analysis results
        
    Returns:
        Formatted report string for display
    """
    # Start building the report string
    report = []
    
    # Add report header without emoji
    report.append(f"Security Incident Report: #{analysis_output.metrics_panel.get('incident_number', 'N/A')}")
    
    # Add incident classification details
    if analysis_output.summary:
        # Extract the title if it's in the summary
        if isinstance(analysis_output.summary, dict) and analysis_output.summary.get('title'):
            report.append(f"{analysis_output.summary.get('title')}")
        elif isinstance(analysis_output.summary, str):
            # Try to get the first line as the title
            first_line = analysis_output.summary.split('\n')[0] if '\n' in analysis_output.summary else analysis_output.summary
            report.append(f"{first_line}")
    
    # Add classification, detection source, etc.
    report.append(f"Classification: {analysis_output.significance if analysis_output.significance != 'Not provided' else 'True Positive'}")
    report.append(f"Severity: {analysis_output.severity_indicator}")
    report.append(f"Detection Source: {analysis_output.metrics_panel.get('detection_source', 'ASI Scheduled Alerts')}")
    
    # Add MITRE ATT&CK details if available
    if analysis_output.attack_techniques:
        if len(analysis_output.attack_techniques) > 0:
            # Format: Tactic: CommandAndControl
            tactic = None
            if '(' in analysis_output.attack_techniques[0]:
                tactic_part = analysis_output.attack_techniques[0].split('(')[1]
                if ')' in tactic_part:
                    tactic = tactic_part.split(')')[0]
            
            if not tactic:
                # Check technique_details for tactic
                tech_id = analysis_output.attack_techniques[0].split(' ')[0] if ' ' in analysis_output.attack_techniques[0] else analysis_output.attack_techniques[0]
                if tech_id in analysis_output.technique_details:
                    tactic = analysis_output.technique_details[tech_id].get('tactic', "Unknown")
                else:
                    tactic = "Unknown"
                
            report.append(f"Tactic: {tactic}")
            
            # Format: Technique: T1071
            technique_id = analysis_output.attack_techniques[0].split(' ')[0] if ' ' in analysis_output.attack_techniques[0] else "Unknown"
            report.append(f"Technique: {technique_id}")
    
    # Add owner if available
    owner = analysis_output.metrics_panel.get('owner', 'Unassigned')
    # Try to extract email from owner JSON if it's a JSON string
    if isinstance(owner, str) and owner.startswith('{"'):
        try:
            owner_data = json.loads(owner)
            if 'assignedTo' in owner_data:
                owner = owner_data['assignedTo']
            elif 'email' in owner_data:
                owner = owner_data['email']
        except:
            pass
    report.append(f"Owner: {owner}")
    
    # Add domain info if available
    if hasattr(analysis_output, 'threat_intel_context') and analysis_output.threat_intel_context != "Not provided":
        if isinstance(analysis_output.threat_intel_context, dict):
            if 'domain' in analysis_output.threat_intel_context:
                report.append(f"Domain: {analysis_output.threat_intel_context['domain']}")
                
                # Add VirusTotal reputation if available
                vt_rep = analysis_output.threat_intel_context.get('virustotal_reputation', 'Unknown')
                vt_mal = analysis_output.threat_intel_context.get('malicious_votes', '?')
                vt_eng = analysis_output.threat_intel_context.get('total_engines', '?')
                report.append(f"VirusTotal Reputation: {vt_rep} ({vt_mal}/{vt_eng} malicious)")
    
    # Add status
    report.append(f"Status: {analysis_output.metrics_panel.get('status', 'Unknown')}")
    
    # Add affected device and most active user if available
    if hasattr(analysis_output, 'asset_impact_analysis') and analysis_output.asset_impact_analysis != "Not provided":
        if isinstance(analysis_output.asset_impact_analysis, dict):
            if 'affected_device' in analysis_output.asset_impact_analysis:
                report.append(f"Affected Device: {analysis_output.asset_impact_analysis['affected_device']}")
            if 'most_active_user' in analysis_output.asset_impact_analysis:
                report.append(f"Most Active User: {analysis_output.asset_impact_analysis['most_active_user']}")
    
    # Add a blank line
    report.append("")
    
    # Add immediate actions section without status column
    report.append("A. Immediate Actions (First 1–2 hours)")
    report.append("")
    
    if analysis_output.immediate_actions:
        for action in analysis_output.immediate_actions:
            if isinstance(action, dict):
                action_desc = action.get('description', '')
                report.append(f"{action_desc}")
    
    # Add future steps section without emoji
    report.append("B. Future Steps (Next 24 hours)")
    report.append("Investigation Steps")
    
    if analysis_output.future_steps:
        for step in analysis_output.future_steps:
            if isinstance(step, dict):
                step_desc = step.get('description', '')
                data_points = step.get('data_points', [])
                
                report.append(f"{step_desc}")
                
                if data_points:
                    for point in data_points:
                        if point:
                            report.append(f"")
                            report.append(f"{point}")
                
                report.append("")
    
    # Join all parts with newlines and return
    return "\n".join(report)

def generate_soc_analyst_prompt(incident_data: Dict[str, Any], logs: List[Dict[str, Any]], 
                               indicators: SecurityIndicators, alerts: List[Dict[str, Any]],
                               example_actions: List[Dict[str, Any]] = None,
                               example_future_steps: List[Dict[str, Any]] = None) -> str:
    """
    Generate a prompt for the LLM to create an enhanced SOC analyst report with immediate actions and future steps.
    
    Args:
        incident_data: Dictionary containing incident information
        logs: List of related logs
        indicators: SecurityIndicators object with extracted indicators
        alerts: List of related alerts
        example_actions: Example immediate actions to guide the LLM's formatting
        example_future_steps: Example future steps to guide the LLM's formatting
        
    Returns:
        Prompt string for the LLM
    """
    # Start building the prompt
    prompt = [
        "You are a senior SOC analyst creating an actionable security incident response report.",
        "Based on the incident data, logs, and indicators provided, generate a comprehensive analysis."
    ]
    
    # Add incident details
    prompt.append("\n## INCIDENT DETAILS:")
    prompt.append(f"Title: {incident_data.get('title', 'Unknown')}")
    prompt.append(f"Severity: {incident_data.get('severity', 'Unknown')}")
    prompt.append(f"Status: {incident_data.get('status', 'Unknown')}")
    prompt.append(f"Incident Number: {incident_data.get('incident_number', 'Unknown')}")
    
    if incident_data.get('description'):
        prompt.append(f"Description: {incident_data.get('description')}")
    
    # Add security indicators
    prompt.append("\n## SECURITY INDICATORS:")
    prompt.append(f"Domains: {', '.join(indicators.domains) if indicators.domains else 'None'}")
    prompt.append(f"IPs: {', '.join(indicators.ips) if indicators.ips else 'None'}")
    prompt.append(f"Users: {', '.join(indicators.users) if indicators.users else 'None'}")
    prompt.append(f"Processes: {', '.join(indicators.processes) if indicators.processes else 'None'}")
    
    # Add alert summary if available
    if alerts:
        prompt.append("\n## RELATED ALERTS:")
        for i, alert in enumerate(alerts[:5], 1):  # Show top 5 alerts
            prompt.append(f"Alert {i}: {alert.get('AlertName', 'Unknown')} (Severity: {alert.get('AlertSeverity', 'Unknown')})")
            if alert.get('Description'):
                desc = alert.get('Description')
                prompt.append(f"  Description: {desc[:150]}..." if len(desc) > 150 else f"  Description: {desc}")
    
    # Add log summary if available
    if logs:
        prompt.append("\n## LOG SUMMARY:")
        log_types = {}
        for log in logs[:50]:  # Sample of logs
            log_type = log.get('Type', 'Unknown')
            if log_type in log_types:
                log_types[log_type] += 1
            else:
                log_types[log_type] = 1
        
        for log_type, count in log_types.items():
            prompt.append(f"- {log_type}: {count} entries")
        
        # Add a few sample logs
        prompt.append("\nSample Logs:")
        for i, log in enumerate(logs[:3]):
            prompt.append(f"Log {i+1}: {str(log)[:200]}...")
    
    # Add output format instructions
    prompt.append("\n## OUTPUT FORMAT:")
    prompt.append("Generate an analysis with the following sections in this exact format:")
    
    prompt.append("\n1. EXECUTIVE SUMMARY")
    prompt.append("A 2-3 sentence summary of incident criticality, impact, and required actions.")
    
    prompt.append("\n2. SEVERITY INDICATOR")
    prompt.append("Provide a single severity level: Critical, High, Medium, or Low.")
    
    prompt.append("\n3. IMMEDIATE ACTIONS (FIRST 1-2 HOURS)")
    prompt.append("Use exactly this section header: 'A. Immediate Actions (First 1-2 hours)'")
    prompt.append("Use exactly this subheader: 'Recommended Action'")
    prompt.append("List 3-5 specific, actionable steps that should be taken immediately (in the first 1-2 hours).")
    prompt.append("Format each action as a JSON object with 'description' and 'status' fields.")
    prompt.append("Example: { \"description\": \"Block malicious IP 1.2.3.4 at the firewall\", \"status\": \"Critical\" }")
    prompt.append("Possible status values: Critical, Recommended, Optional")
    
    # Add specific instructions for firewall information
    prompt.append("\nFor any malicious IPs found, provide detailed blocking recommendations including:")
    prompt.append("- Specify the exact firewall types where blocking should be implemented (e.g., perimeter firewall, internal firewalls, host-based firewalls)")
    prompt.append("- Indicate if blocking should be bidirectional or only for specific traffic directions")
    prompt.append("- Include the specific firewall rules that should be created (ports, protocols, zones)")
    prompt.append("- Mention any potential impact of implementing the blocks")
    prompt.append("- For high-severity incidents, suggest if emergency block protocols should be activated")
    prompt.append("Example: { \"description\": \"Block malicious IP 1.2.3.4 at both perimeter and internal firewalls. Create bidirectional deny rules for all protocols. Prioritize perimeter firewall implementation first due to active exfiltration attempts. Enable logging for all blocked traffic.\", \"status\": \"Critical\" }")
    
    # Add specific instructions for user account actions
    prompt.append("\nFor compromised user accounts, provide detailed recommendations including:")
    prompt.append("- Whether to disable or reset the account (and reasoning)")
    prompt.append("- Specific systems where access should be revoked immediately")
    prompt.append("- Any additional authentication actions needed (e.g., invalidate tokens, revoke certificates)")
    prompt.append("- Notification requirements for account owners and managers")
    prompt.append("- Temporary access provisions if needed for business continuity")
    prompt.append("Example: { \"description\": \"Disable user account jsmith@example.com across all identity providers (Azure AD, O365, VPN). Revoke all active sessions and OAuth tokens. Notify IT manager and department head. Create temporary emergency access for critical system management through breakglass account.\", \"status\": \"Critical\" }")
    
    # Add specific instructions for system isolation
    prompt.append("\nFor system isolation recommendations, provide detailed instructions including:")
    prompt.append("- Specific isolation method (network quarantine, physical disconnection, etc.)")
    prompt.append("- Which systems should be isolated and in what priority order")
    prompt.append("- Potential business impact of isolation and mitigation strategies")
    prompt.append("- Monitoring requirements during isolation")
    prompt.append("- Communication plan for affected stakeholders")
    prompt.append("Example: { \"description\": \"Isolate affected systems (srv-db-01, srv-app-03) via network quarantine at the switch level. Maintain monitoring access via out-of-band management interface. Notify application owners about 4-hour service disruption. Implement database fallback to secondary instance to maintain critical business processes.\", \"status\": \"Critical\" }")
    
    # Add instructions for evidence collection
    prompt.append("\nFor evidence collection actions, include detailed guidance on:")
    prompt.append("- Specific types of evidence to collect (memory dumps, log files, disk images)")
    prompt.append("- Tools and methods to use for collection")
    prompt.append("- Chain of custody requirements")
    prompt.append("- Preservation methods and storage locations")
    prompt.append("Example: { \"description\": \"Collect full memory dumps from affected server srv-web-01 using forensic tools before any system changes. Preserve network traffic captures from the security monitoring system for the past 24 hours. Create forensic disk image of the compromised workstation wks-fin-12. Establish chain of custody documentation and store all evidence in secure storage with access logging enabled.\", \"status\": \"Recommended\" }")
    
    prompt.append("\n4. FUTURE STEPS (NEXT 24 HOURS)")
    prompt.append("Use exactly this section header: 'B. Future Steps (Next 24 hours)'")
    prompt.append("Use exactly this subheader: 'Investigation Steps'")
    prompt.append("List 3-5 investigation steps to take in the next 24 hours.")
    prompt.append("Format each step as a JSON object with 'description' and 'data_points' fields.")
    prompt.append("The 'data_points' field should be an array of strings containing specific data points from logs or alerts that support this step.")
    prompt.append("Example: { \"description\": \"Review DNS logs for similar queries\", \"data_points\": [\"Found 5 DNS queries to malicious domain\", \"User john.doe initiated queries\"] }")
    
    # Enhanced instructions for investigation steps
    prompt.append("\nFor each investigation step, provide highly detailed, technical, and data-driven recommendations:")
    
    # DNS log analysis
    prompt.append("\nFor DNS log analysis recommendations, include:")
    prompt.append("- Specific time ranges to review based on incident timeline")
    prompt.append("- Particular DNS query types or patterns to search for")
    prompt.append("- Correlation with specific user accounts or systems")
    prompt.append("- Similar domains to look for (typosquatting, DGA patterns)")
    prompt.append("- Specific query analysis tools to use and search syntax")
    prompt.append("Example: { \"description\": \"Conduct advanced DNS log analysis for domain pattern variations of 'malicious-domain.com' using regex queries\", \"data_points\": [\"Observed 3 domain variations with similar pattern: mal1cious-domain.com, malicious-d0main.com\", \"All queries originated from subnet 10.15.x.x within finance department\", \"Unusual TXT record queries detected at 2:15 AM from host fin-ws-042\"] }")
    
    # Lateral movement analysis
    prompt.append("\nFor lateral movement detection recommendations, include:")
    prompt.append("- Specific systems to monitor for signs of lateral movement")
    prompt.append("- Authentication logs and access patterns to review")
    prompt.append("- Network traffic flow directions and protocols to analyze")
    prompt.append("- Unusual administrative tool usage to look for")
    prompt.append("- Specific detection methods for the observed attack techniques")
    prompt.append("Example: { \"description\": \"Analyze network flows between compromised workstation wks-eng-15 and high-value servers for signs of lateral movement\", \"data_points\": [\"Detected SMB traffic from wks-eng-15 to 5 servers it normally doesn't communicate with\", \"PowerShell remoting attempts observed from this host to srv-ad-02 at 14:23 UTC\", \"Credential access attempts against multiple systems following temporal pattern\"] }")
    
    # User activity analysis
    prompt.append("\nFor user activity analysis recommendations, include:")
    prompt.append("- Specific user accounts to investigate in depth")
    prompt.append("- Unusual access times, locations, or resource requests")
    prompt.append("- Authentication patterns across different systems")
    prompt.append("- Authorized vs. unauthorized actions")
    prompt.append("- Baseline deviations in behavior")
    prompt.append("Example: { \"description\": \"Perform user behavior analysis on account jsmith focusing on access pattern changes over the past 72 hours\", \"data_points\": [\"User logged in from 3 new geographies not previously observed in 12-month history\", \"Account accessed 27 documents in finance share in 30 minutes - 500% above normal rate\", \"Failed authentication attempts to restricted systems occurring 15 minutes after successful logins\"] }")
    
    # Malware analysis
    prompt.append("\nFor malware analysis recommendations, include:")
    prompt.append("- Specific file hashes or suspicious binaries to analyze")
    prompt.append("- Indicators of compromise to search for across the environment")
    prompt.append("- Memory or disk artifacts to extract and analyze")
    prompt.append("- Persistence mechanisms to investigate")
    prompt.append("- Communication patterns or C2 channels")
    prompt.append("Example: { \"description\": \"Conduct in-depth analysis of suspicious executable 'svchost_update.exe' found on affected system\", \"data_points\": [\"File hash 2a7b4d834ef...\", \"Binary contains embedded PowerShell with obfuscated commands\", \"Attempts to contact 3 IPs (192.168.x.x, 45.33.x.x) over encrypted channel\", \"Creates persistence via scheduled task and registry key\"] }")
    
    prompt.append("\n5. ATTACK TECHNIQUES")
    prompt.append("List of MITRE ATT&CK techniques identified in the format T1234 (Technique Name).")
    
    prompt.append("\nEnsure all output follows the structure of IncidentAnalysisOutput.")
    prompt.append("Return your response as a valid JSON object that matches the IncidentAnalysisOutput model schema.")
    
    # Return the combined prompt
    return "\n".join(prompt)

def generate_soc_analyst_report(incident_data: Dict[str, Any], logs: List[Dict[str, Any]], 
                              indicators: SecurityIndicators, alerts: List[Dict[str, Any]],
                              example_actions: List[Dict[str, Any]] = None,
                              example_future_steps: List[Dict[str, Any]] = None,
                              threat_intel_context: Optional[Union[str, Dict[str, Any]]] = None) -> IncidentAnalysisOutput: # Added parameters
    """
    Generates a SOC analyst report structure using an LLM based on incident data.

    Args:
        incident_data: Dictionary containing incident information.
        logs: List of related logs.
        indicators: SecurityIndicators object with extracted indicators.
        alerts: List of related alerts.
        example_actions: Example immediate actions to guide the LLM's formatting (DEPRECATED - Use prompt instructions)
        example_future_steps: Example future steps to guide the LLM's formatting (DEPRECATED - Use prompt instructions)
        threat_intel_context: Optional VirusTotal or other threat intel data.

    Returns:
        IncidentAnalysisOutput: A Pydantic object containing the structured analysis.
                                Returns a default error object if generation fails.
    """
    # 1. Construct the Prompt using user's template + JSON instructions
    prompt_lines = [
        "You are an expert SOC Analyst providing a detailed, actionable incident response report for a Windows/Azure environment.",
        "Generate a structured SOC report in JSON format based ONLY on the provided Incident Details, Indicators, Alert Summary, and Log Summary.",
        "Your response MUST include 'executive_summary', 'severity_indicator', 'immediate_actions', and 'future_steps' fields.",
        
        "## Guidelines for Recommendations:",
        "1.  **Specificity:** Recommendations MUST reference specific entities (IPs, domains, users, hostnames) identified in the provided data.",
        "2.  **Action Verbs:** Use clear action verbs (e.g., Block, Isolate, Monitor, Investigate, Review, Analyze, Escalate, Capture).",
        "3.  **Tools/Logs:** Suggest relevant Windows/Azure tools (PowerShell, Event Logs, Defender, Sentinel KQL) or technologies (Firewall, Proxy, EDR) where appropriate for the action.",
        "4.  **Context:** Actions should directly relate to the incident type and indicators observed.",
        "5.  **No Hardcoding:** DO NOT use the exact examples from user prompts; adapt the *style* and *specificity*.",
        "6.  **Immediate Actions (1-2 hours):** Focus on containment and immediate evidence preservation. Include 3-5 actions. Each action is a JSON object: `{\"description\": \"Specific action using entity X with tool Y...\"}`.",
        "7.  **Future Steps (Next 24 hours):** Focus on deeper investigation, scope analysis, and enrichment. Include 3-5 steps. Each step is a JSON object: `{\"description\": \"Investigate entity X using log source Y...\", \"data_points\": [\"Evidence point A from logs\", \"Indicator B correlated...\"]`. Data points MUST be derived from the provided summaries, not raw file paths.",
        "8.  **Output:** Ensure the final output is a single, valid JSON object matching the IncidentAnalysisOutput structure.",
        
        "\n---", # Removed extra newline character
        "### INCIDENT DETAILS",
        f"Incident Number: {incident_data.get('incident_number', 'N/A')}",
        f"Title: {incident_data.get('title', 'N/A')}",
        f"Severity: {incident_data.get('severity', 'N/A')}",
        f"Status: {incident_data.get('status', 'N/A')}",
        f"Owner: {incident_data.get('owner', 'N/A')}",
        f"Classification: {incident_data.get('classification', 'N/A')}",
        "\n---", # Removed extra newline character
        "### THREAT INTEL & INDICATORS"
    ]
    
    # Add Domains
    if indicators.domains:
        prompt_lines.append(f"Domains: {', '.join(indicators.domains)}")
    
    # Add Threat Intel Context (like VirusTotal) if available and passed to the function
    if threat_intel_context and threat_intel_context != "Not provided":
        if isinstance(threat_intel_context, dict):
            vt_rep = threat_intel_context.get('virustotal_reputation', 'N/A')
            if vt_rep != 'N/A':
                vt_mal = threat_intel_context.get('malicious_votes', '?')
                vt_eng = threat_intel_context.get('total_engines', '?')
                prompt_lines.append(f"VirusTotal ({threat_intel_context.get('domain', 'related domain')}): {vt_rep} ({vt_mal}/{vt_eng} malicious)")
        elif isinstance(threat_intel_context, str):
             prompt_lines.append(f"Threat Intel Context: {threat_intel_context}")

    # Add other indicators
    if indicators.ips: prompt_lines.append(f"IPs: {', '.join(indicators.ips)}")
    if indicators.users: prompt_lines.append(f"Users: {', '.join(indicators.users)}")
    if indicators.processes: prompt_lines.append(f"Processes: {', '.join(indicators.processes)}")
    if indicators.urls: prompt_lines.append(f"URLs: {', '.join(indicators.urls)}")
    if indicators.file_hashes: prompt_lines.append(f"File Hashes: {', '.join(indicators.file_hashes)}")

    prompt_lines.append("\n---")
    
    # Add Alerts Summary with more detailed information when available
    if alerts:
        alert_names = [alert.get('AlertName', alert.get('DisplayName', 'Unknown Alert')) for alert in alerts[:5]] # Max 5 alerts
        prompt_lines.append("### RELATED ALERTS (Sample)")
        for i, alert in enumerate(alerts[:5]):
            name = alert.get('AlertName', alert.get('DisplayName', 'Unknown Alert'))
            severity = alert.get('AlertSeverity', 'Unknown')
            desc = alert.get('Description', '')[:200]
            if desc:
                desc = f" - {desc}"
            prompt_lines.append(f"- Alert {i+1}: {name} (Severity: {severity}){desc}")
        if len(alerts) > 5: prompt_lines.append("- ... and more")
        prompt_lines.append("\n---")

    # Add Log Summary with more detailed information
    if logs:
        prompt_lines.append("### LOG SUMMARY (Sample Patterns)")
        
        # Extract top IPs with more context
        ip_counts = {}
        ip_context = {}
        for log in logs:
            src_ip = log.get('SourceIP')
            dst_ip = log.get('DestinationIP')
            action = log.get('DeviceAction', log.get('SimplifiedDeviceAction', 'Unknown'))
            hostname = log.get('Computer', log.get('DeviceName', log.get('HostName')))
            
            if src_ip:
                ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
                if src_ip not in ip_context:
                    ip_context[src_ip] = {'actions': set(), 'destinations': set(), 'hostnames': set()}
                ip_context[src_ip]['actions'].add(action)
                if dst_ip:
                    ip_context[src_ip]['destinations'].add(dst_ip)
                if hostname:
                    ip_context[src_ip]['hostnames'].add(hostname)
                    
            if dst_ip:
                ip_counts[dst_ip] = ip_counts.get(dst_ip, 0) + 1
                if dst_ip not in ip_context:
                    ip_context[dst_ip] = {'actions': set(), 'sources': set(), 'hostnames': set()}
                if src_ip:
                    ip_context[dst_ip]['sources'].add(src_ip)
                if hostname:
                    ip_context[dst_ip]['hostnames'].add(hostname)
                
        top_ips = sorted(ip_counts.items(), key=lambda item: item[1], reverse=True)[:3]
        if top_ips:
            prompt_lines.append("Top IPs Mentioned:")
            for ip, count in top_ips:
                context_str = ""
                if ip in ip_context:
                    hosts = list(ip_context[ip]['hostnames'])[:2]
                    if hosts:
                        context_str += f" associated with hosts: {', '.join(hosts)}"
                    actions = list(ip_context[ip].get('actions', set()))[:2]
                    if actions and actions != ['Unknown']:
                         context_str += f" involved in actions: {', '.join(actions)}"
                prompt_lines.append(f"- {ip} ({count}x occurrences){context_str}")

        # Extract most active users with more context
        user_counts = {}
        user_context = {}
        for log in logs:
            user = log.get('SourceUserName', log.get('UserName'))
            if user and user != 'N/A': # Filter out N/A users
                user_counts[user] = user_counts.get(user, 0) + 1
                if user not in user_context:
                    user_context[user] = {'ips': set(), 'actions': set(), 'hosts': set()}
                if log.get('SourceIP'):
                    user_context[user]['ips'].add(log.get('SourceIP'))
                action = log.get('DeviceAction', log.get('SimplifiedDeviceAction', log.get('Activity', 'Unknown')))
                if action != 'Unknown': user_context[user]['actions'].add(action)
                hostname = log.get('Computer', log.get('DeviceName', log.get('HostName')))
                if hostname: user_context[user]['hosts'].add(hostname)
                
        top_users = sorted(user_counts.items(), key=lambda item: item[1], reverse=True)[:3]
        if top_users:
            prompt_lines.append("\nMost Active Users Mentioned:")
            for user, count in top_users:
                context_str = ""
                if user in user_context:
                    hosts = list(user_context[user]['hosts'])[:2]
                    actions = list(user_context[user]['actions'])[:2]
                    if hosts:
                        context_str += f" on hosts: {', '.join(hosts)}"
                    if actions:
                        context_str += f" performing actions: {', '.join(actions)}"
                prompt_lines.append(f"- {user} ({count}x activities){context_str}")
        
        # Extract devices with more context
        device_counts = {}
        device_context = {}
        for log in logs:
            device = log.get('Computer', log.get('DeviceName', log.get('HostName')))
            if device:
                device_counts[device] = device_counts.get(device, 0) + 1
                if device not in device_context:
                    device_context[device] = {'ips': set(), 'actions': set()}
                ip = log.get('SourceIP', log.get('DestinationIP'))
                if ip: device_context[device]['ips'].add(ip)
                action = log.get('DeviceAction', log.get('SimplifiedDeviceAction', log.get('Activity', 'Unknown')))
                if action != 'Unknown': device_context[device]['actions'].add(action)

        top_devices = sorted(device_counts.items(), key=lambda item: item[1], reverse=True)[:3]
        if top_devices:
            prompt_lines.append("\nMost Mentioned Devices:")
            for dev, count in top_devices:
                context_str = ""
                if dev in device_context:
                    actions = list(device_context[dev]['actions'])[:2]
                    ips = list(device_context[dev]['ips'])[:2]
                    if actions:
                        context_str += f" involved in actions: {', '.join(actions)}"
                    if ips:
                         context_str += f" communicating with IPs: {', '.join(ips)}"
                prompt_lines.append(f"- {dev} ({count}x occurrences){context_str}")

        # Extract destination ports, urls or other relevant patterns
        ports = {}
        for log in logs:
            port = log.get('DestinationPort')
            if port:
                ports[port] = ports.get(port, 0) + 1
        top_ports = sorted(ports.items(), key=lambda item: item[1], reverse=True)[:3]
        if top_ports:
            prompt_lines.append("\nTop Destination Ports Mentioned:")
            for port, count in top_ports:
                prompt_lines.append(f"- Port {port} ({count}x occurrences)")

        prompt_lines.append("\n---")

    # Final instruction
    prompt_lines.append("\nGenerate the final JSON output based on the analysis of the provided data and following all instructions.")
    prompt = "\n".join(prompt_lines)

    # Prepare context for fallbacks
    primary_domain = indicators.domains[0] if indicators.domains else None
    primary_ip = indicators.ips[0] if indicators.ips else None
    primary_user = indicators.users[0] if indicators.users else (top_users[0][0] if top_users else None)
    primary_device = top_devices[0][0] if top_devices else None

    # 2. Call Ollama LLM
    try:
        print("Generating SOC analyst report structure with Ollama...")
        client = ollama.Client(host=OLLAMA_API_BASE)
        response = client.chat(
            model=OLLAMA_MODEL,
            messages=[{"role": "user", "content": prompt}],
            stream=False,
            format="json"  # Request JSON output
        )
        response_content = response['message']['content']
        print("Ollama response received.")

        # 3. Parse and Validate with Pydantic
        try:
            analysis_data = json.loads(response_content)
            
            # Create fallback actions and steps based on available data (Windows focused, matching user examples style)
            fallback_actions = []
            if primary_domain:
                fallback_actions.append({
                    "description": f"Block domain {primary_domain} at Firewall/Proxy/DNS Filter levels."
                })
                fallback_actions.append({
                    "description": f"Check reputation of domain {primary_domain} using VirusTotal or other TI source."
                })
            if primary_ip:
                fallback_actions.append({
                    "description": f"Block IP address {primary_ip} using Windows Firewall: `netsh advfirewall firewall add rule name=\"Block Incident IP {primary_ip}\" dir=in action=block remoteip={primary_ip}` (run for dir=out too)."
                })
            if primary_device:
                 fallback_actions.append({
                    "description": f"Isolate system {primary_device} from the network (via EDR, VLAN change, or port disable) to contain potential threat."
                })
            if primary_user:
                fallback_actions.append({
                    "description": f"Monitor account {primary_user} closely for suspicious activity. Consider temporary disablement if high risk is confirmed."
                })
            fallback_actions.append({
                "description": "Capture volatile memory and disk image from key involved system(s) for forensic analysis."
            })
            fallback_actions.append({
                "description": "Escalate to Level 2 SOC or Incident Response team for deeper investigation."
            })
            
            fallback_steps = []
            if primary_domain:
                fallback_steps.append({
                    "description": f"Review DNS logs (Windows Event Log or Sysmon ID 22) across endpoints for queries related to {primary_domain} or similar variations.",
                    "data_points": [f"Domain {primary_domain} identified as key indicator"]
                })
            if primary_ip:
                ip_count = ip_counts.get(primary_ip, 0) if 'ip_counts' in locals() else 0
                fallback_steps.append({
                    "description": f"Analyze firewall/network logs (e.g., using Sentinel KQL) for all traffic to/from IP {primary_ip} to identify communication patterns and scope.",
                    "data_points": [f"IP {primary_ip} observed {ip_count} times in log summary"]
                })
            if primary_user:
                user_count = user_counts.get(primary_user, 0) if 'user_counts' in locals() else 0
                fallback_steps.append({
                    "description": f"Audit Azure AD sign-in and UAL logs for user {primary_user}, focusing on unusual times, locations, or application access.",
                    "data_points": [f"User {primary_user} involved in {user_count} logged activities"]
                })
            if primary_device:
                dev_count = device_counts.get(primary_device, 0) if 'device_counts' in locals() else 0
                fallback_steps.append({
                    "description": f"Investigate process execution logs (Security Event ID 4688 or Sysmon ID 1) on host {primary_device} around the time of the incident.",
                    "data_points": [f"Device {primary_device} mentioned {dev_count} times in logs"]
                })
            fallback_steps.append({
                "description": "Search EDR/Antivirus logs across the environment for alerts related to the identified indicators (domains, IPs, hashes).",
                "data_points": ["Multiple indicators identified requiring environment-wide check"]
            })
            fallback_steps.append({
                "description": "Analyze proxy logs for connections to identified malicious domains/URLs to understand user interaction.",
                 "data_points": [f"Indicators include domains/URLs: {str(indicators.domains)}, {str(indicators.urls)}"]
            })
            
            # Merge analysis_data with required fields potentially missing from LLM response
            merged_data = {
                "executive_summary": analysis_data.get("executive_summary", "Security incident involving potentially suspicious network activity detected. Immediate actions required to contain potential threat by blocking indicators and isolating systems. Further investigation needed to determine full scope and impact."),
                "severity_indicator": analysis_data.get("severity_indicator", incident_data.get("severity", "Medium")),
                "immediate_actions": analysis_data.get("immediate_actions", []) or fallback_actions[:5],  # Use fallbacks if empty, limit length
                "future_steps": analysis_data.get("future_steps", []) or fallback_steps[:5],  # Use fallbacks if empty, limit length
                "metrics_panel": indicators.metrics_panel if hasattr(indicators, 'metrics_panel') else {
                     "incident_number": incident_data.get('incident_number', 'N/A'),
                     "status": incident_data.get('status', 'N/A'),
                     "owner": incident_data.get('owner', 'N/A'),
                     "detection_source": "ASI Scheduled Alerts" # Default or derive
                },
                 "attack_techniques": indicators.attack_techniques if hasattr(indicators, 'attack_techniques') else [],
                 "technique_details": indicators.technique_details if hasattr(indicators, 'technique_details') else {},
                 "threat_intel_context": threat_intel_context if threat_intel_context else "Not provided", # Use passed context
                 "asset_impact_analysis": indicators.asset_impact_analysis if hasattr(indicators, 'asset_impact_analysis') else "Not provided",
                 "significance": incident_data.get("classification", "Not provided"), # Map classification
                 # Add other necessary fields with defaults if needed for format_soc_analyst_report
                 "summary": incident_data.get('title', 'N/A'), # Add summary field if needed by formatter
                 "recommended_actions": [], # Ensure these exist if format_soc_analyst_report expects them
                 "next_steps_for_l1": [],
            }

            # Ensure actions/steps are lists of dicts, even if LLM failed partially
            if not isinstance(merged_data["immediate_actions"], list) or not all(isinstance(i, dict) for i in merged_data["immediate_actions"]):
                 merged_data["immediate_actions"] = fallback_actions[:5]
            if not isinstance(merged_data["future_steps"], list) or not all(isinstance(i, dict) for i in merged_data["future_steps"]):
                 merged_data["future_steps"] = fallback_steps[:5]

            analysis_output = IncidentAnalysisOutput(**merged_data)
            print("Pydantic validation successful.")
            return analysis_output

        except json.JSONDecodeError:
            print(f"LLM Error: Invalid JSON received:\n{response_content}")
            # Create a fallback analysis with generic but useful recommendations
            fallback_analysis = IncidentAnalysisOutput(
                executive_summary="Security incident requiring investigation. Generated fallback recommendations due to LLM response error.",
                severity_indicator="Medium",
                immediate_actions=fallback_actions[:5],
                future_steps=fallback_steps[:5]
            )
            return fallback_analysis
        except pydantic.ValidationError as e:
            print(f"LLM Error: JSON does not match Pydantic model:\n{e}\nReceived JSON:\n{response_content}")
            # Create a fallback analysis with generic but useful recommendations
            fallback_analysis = IncidentAnalysisOutput(
                executive_summary="Security incident requiring investigation. Generated fallback recommendations due to LLM response error.",
                severity_indicator="Medium", 
                immediate_actions=fallback_actions[:5],
                future_steps=fallback_steps[:5]
            )
            return fallback_analysis

    except Exception as e:
        print(f"Error during Ollama call or processing: {str(e)}")
        traceback.print_exc()
        # Create fallback recommendations
        fallback_analysis = IncidentAnalysisOutput(
            executive_summary=f"Error in report generation. Using fallback recommendations.",
            severity_indicator="Medium",
            immediate_actions=fallback_actions[:5],
            future_steps=fallback_steps[:5]
        )
        return fallback_analysis


def format_soc_analyst_report(analysis_output: IncidentAnalysisOutput) -> str:
    """
    Format the incident analysis output into a SOC analyst report with immediate actions and future steps.
    
    Args:
        analysis_output: The IncidentAnalysisOutput object containing analysis results
        
    Returns:
        Formatted report string for display
    """
    # Start building the report string
    report = []
    
    # Add report header without emoji
    report.append(f"Security Incident Report: #{analysis_output.metrics_panel.get('incident_number', 'N/A')}")
    
    # Add incident classification details
    if analysis_output.summary:
        # Extract the title if it's in the summary
        if isinstance(analysis_output.summary, dict) and analysis_output.summary.get('title'):
            report.append(f"{analysis_output.summary.get('title')}")
        elif isinstance(analysis_output.summary, str):
            # Try to get the first line as the title
            first_line = analysis_output.summary.split('\n')[0] if '\n' in analysis_output.summary else analysis_output.summary
            report.append(f"{first_line}")
    
    # Add classification, detection source, etc.
    report.append(f"Classification: {analysis_output.significance if analysis_output.significance != 'Not provided' else 'True Positive'}")
    report.append(f"Severity: {analysis_output.severity_indicator}")
    report.append(f"Detection Source: {analysis_output.metrics_panel.get('detection_source', 'ASI Scheduled Alerts')}")
    
    # Add MITRE ATT&CK details if available
    if analysis_output.attack_techniques:
        if len(analysis_output.attack_techniques) > 0:
            # Format: Tactic: CommandAndControl
            tactic = None
            if '(' in analysis_output.attack_techniques[0]:
                tactic_part = analysis_output.attack_techniques[0].split('(')[1]
                if ')' in tactic_part:
                    tactic = tactic_part.split(')')[0]
            
            if not tactic:
                # Check technique_details for tactic
                tech_id = analysis_output.attack_techniques[0].split(' ')[0] if ' ' in analysis_output.attack_techniques[0] else analysis_output.attack_techniques[0]
                if tech_id in analysis_output.technique_details:
                    tactic = analysis_output.technique_details[tech_id].get('tactic', "Unknown")
                else:
                    tactic = "Unknown"
                
            report.append(f"Tactic: {tactic}")
            
            # Format: Technique: T1071
            technique_id = analysis_output.attack_techniques[0].split(' ')[0] if ' ' in analysis_output.attack_techniques[0] else "Unknown"
            report.append(f"Technique: {technique_id}")
    
    # Add owner if available
    owner = analysis_output.metrics_panel.get('owner', 'Unassigned')
    # Try to extract email from owner JSON if it's a JSON string
    if isinstance(owner, str) and owner.startswith('{"'):
        try:
            owner_data = json.loads(owner)
            if 'assignedTo' in owner_data:
                owner = owner_data['assignedTo']
            elif 'email' in owner_data:
                owner = owner_data['email']
        except:
            pass
    report.append(f"Owner: {owner}")
    
    # Add domain info if available
    if hasattr(analysis_output, 'threat_intel_context') and analysis_output.threat_intel_context != "Not provided":
        if isinstance(analysis_output.threat_intel_context, dict):
            if 'domain' in analysis_output.threat_intel_context:
                report.append(f"Domain: {analysis_output.threat_intel_context['domain']}")
                
                # Add VirusTotal reputation if available
                vt_rep = analysis_output.threat_intel_context.get('virustotal_reputation', 'Unknown')
                vt_mal = analysis_output.threat_intel_context.get('malicious_votes', '?')
                vt_eng = analysis_output.threat_intel_context.get('total_engines', '?')
                report.append(f"VirusTotal Reputation: {vt_rep} ({vt_mal}/{vt_eng} malicious)")
    
    # Add status
    report.append(f"Status: {analysis_output.metrics_panel.get('status', 'Unknown')}")
    
    # Add affected device and most active user if available
    if hasattr(analysis_output, 'asset_impact_analysis') and analysis_output.asset_impact_analysis != "Not provided":
        if isinstance(analysis_output.asset_impact_analysis, dict):
            if 'affected_device' in analysis_output.asset_impact_analysis:
                report.append(f"Affected Device: {analysis_output.asset_impact_analysis['affected_device']}")
            if 'most_active_user' in analysis_output.asset_impact_analysis:
                report.append(f"Most Active User: {analysis_output.asset_impact_analysis['most_active_user']}")
    
    # Add executive summary if available
    if analysis_output.executive_summary:
        report.append(f"\nExecutive Summary: {analysis_output.executive_summary}")
    
    # Add a blank line
    report.append("")
    
    # Add immediate actions section without status column
    report.append("A. Immediate Actions (First 1–2 hours)")
    report.append("")
    
    # Ensure we always have immediate actions
    if analysis_output.immediate_actions:
        for action in analysis_output.immediate_actions:
            if isinstance(action, dict):
                action_desc = action.get('description', '')
                if action_desc:
                    # Remove any stray data_points that might leak into action description
                    if "data_points": # Basic check
                        action_desc = action_desc.split("data_points")[0].strip()
                    report.append(f"{action_desc}")
            elif isinstance(action, str): # Handle case where LLM might return strings
                report.append(f"{action}")
    else:
        # Fallback actions if none are provided
        report.append("Verify incident using security monitoring dashboards")
        report.append("Isolate affected systems from the network")
        report.append("Collect and preserve evidence (memory dumps, logs, network captures)")
    
    # Add future steps section without emoji
    report.append("")
    report.append("B. Future Steps (Next 24 hours)")
    report.append("Investigation Steps")
    report.append("")
    
    # Ensure we always have future steps
    if analysis_output.future_steps:
        for step in analysis_output.future_steps:
            if isinstance(step, dict):
                step_desc = step.get('description', '')
                data_points = step.get('data_points', [])
                
                if step_desc:
                    report.append(f"{step_desc}")
                
                if data_points:
                    # Indent data points for clarity, filter out empty strings
                    valid_points = [p for p in data_points if isinstance(p, str) and p.strip()] 
                    if valid_points:
                        report.append("") # Add space before data points
                        for point in valid_points:
                             # Basic cleaning: avoid printing if it looks like a path
                            if not (point.startswith("/") or point.startswith("C:\\")):
                                report.append(f"  - {point}") 
                
                report.append("") # Add space after each step
            elif isinstance(step, str): # Handle if LLM returns strings
                 report.append(f"{step}")
                 report.append("")
    else:
        # Fallback steps if none are provided
        report.append("Perform timeline analysis of all affected systems")
        report.append("")
        report.append("Run full antivirus/EDR scan on all potentially impacted endpoints")
        report.append("")
        report.append("Conduct forensic analysis of suspicious network traffic")
        report.append("")
    
    # Join all parts with newlines and return
    return "\n".join(report)

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
    parser.add_argument('--mapping', dest='show_mapping', action='store_true',
                        help='Display the mapping between SecurityIncident and SecurityAlert tables')
    parser.add_argument('--investigate', dest='investigate', action='store_true',
                        help='Enable incident investigation mode to map incidents to their alerts')
    
    args = parser.parse_args()
    
    if args.show_mapping:
        display_security_table_mapping()
        sys.exit(0)
        
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
            
        # If investigation mode is enabled, we'll fetch incidents and let user select one
        if args.investigate:
            print("Investigation mode enabled - you will be able to select an incident to investigate")
            incidents = get_security_incidents_from_api(
                days_back=args.api_days,
                include_title_filter=include_title_filter,
                tenant_id=args.tenant_id,
                verbose=True
            )
            
            if not incidents:
                print("No incidents found. Exiting.")
                sys.exit(1)
                
            # Let user select an incident
            selected_incident = display_and_select_incident(incidents)
            
            if selected_incident is not None:
                # Investigate the selected incident
                investigate_incident_alerts(selected_incident, tenant_id=args.tenant_id)
            else:
                print("No incident selected. Exiting.")
        else:
            # Regular analysis mode
            analyze_security_incidents(tenant_id=args.tenant_id, log_window_days=args.log_window, 
                                      use_api=True, api_days=args.api_days,
                                      include_title_filter=include_title_filter)
    else:
        print("Reading incidents from Excel file")
        if args.investigate:
            # Load incidents from Excel file
            try:
                incidents_df = pd.read_excel(args.excel_path)
                
                if incidents_df.empty:
                    print("No incidents found in Excel file. Exiting.")
                    sys.exit(1)
                
                # Group incidents by IncidentNumber
                incident_groups = {}
                for _, row in incidents_df.iterrows():
                    incident_number = row.get('IncidentNumber')
                    if incident_number not in incident_groups:
                        incident_groups[incident_number] = pd.DataFrame([row])
                    else:
                        incident_groups[incident_number] = pd.concat([incident_groups[incident_number], pd.DataFrame([row])])
                
                # Convert to list of DataFrames
                incidents = [group for _, group in incident_groups.items()]
                
                # Let user select an incident
                selected_incident = display_and_select_incident(incidents)
                
                if selected_incident is not None:
                    # Investigate the selected incident
                    investigate_incident_alerts(selected_incident, tenant_id=args.tenant_id)
                else:
                    print("No incident selected. Exiting.")
            except Exception as e:
                print(f"Error loading Excel file: {str(e)}")
                traceback.print_exc()
                sys.exit(1)
        else:
            # Regular analysis mode
            analyze_security_incidents(args.excel_path, args.tenant_id, log_window_days=args.log_window)
    
    print("\nAnalysis complete. Check the generated text files for detailed SOC reports.")