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
import numpy as np
import asyncio
from local_llm_integration import get_local_llm_client  # Import the missing function

# Import necessary libraries for enhanced RAG
from uuid import uuid4
from collections import defaultdict

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
    incident_id: str = Field(default="", description="The incident ID or number")
    incident_title: str = Field(default="", description="The incident title")
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
            async def get_technique_info():
                # Use local_llm_integration instead of direct Ollama call
                llm_client = await get_local_llm_client(model=OLLAMA_MODEL)
                
                # Create a prompt asking for MITRE ATT&CK information
                prompt = (
                    f"Provide information about the following MITRE ATT&CK techniques: {', '.join(techniques_needing_info)}.\n\n"
                    f"For each technique, provide the following in JSON format:\n"
                    f"- name: The name of the technique\n"
                    f"- tactic: The tactic(s) this technique belongs to\n"
                    f"- description: A brief description of the technique\n"
                    f"- mitigation: One or two sentences on how to mitigate this technique\n\n"
                    f"Return a valid JSON object with technique IDs as keys"
                )
                
                # Get the response
                result = await llm_client.generate_json(prompt=prompt)
                return result
                
            # Run the async function
            loop = asyncio.get_event_loop()
            technique_info = loop.run_until_complete(get_technique_info())
            
            if isinstance(technique_info, dict) and not technique_info.get("error"):
                # Format the information for display
                info_text = "\nMITRE ATT&CK Techniques Identified:\n\n"
                for tech_id, tech_data in technique_info.items():
                    if isinstance(tech_data, dict):
                        name = tech_data.get("name", "Unknown Technique")
                        tactic = tech_data.get("tactic", "Unknown Tactic")
                        description = tech_data.get("description", "No description available")
                        mitigation = tech_data.get("mitigation", "No mitigation information available")
                        
                        info_text += f"• {tech_id}: {name}\n"
                        info_text += f"  Tactic: {tactic}\n"
                        info_text += f"  Description: {description}\n"
                        info_text += f"  Mitigation: {mitigation}\n\n"
                    else:
                        info_text += f"• {tech_id}: Information unavailable\n\n"
                
                return info_text
            else:
                error_msg = technique_info.get("error", "Unknown error") if isinstance(technique_info, dict) else str(technique_info)
                return f"\nError retrieving MITRE ATT&CK information: {error_msg}\n"
                
        except Exception as e:
            return f"\nError processing MITRE ATT&CK information: {str(e)}\n"
    
    return "\nNo new MITRE ATT&CK techniques to retrieve information for.\n"


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

def analyze_log_patterns(logs: List[Dict[str, Any]], domain: str = None) -> Dict[str, Any]:
    """
    Analyze security logs for common patterns and statistics.
    Focuses on destination IPs, ports, usernames, device names, etc.
    
    Args:
        logs: List of log dictionaries
        domain: Optional domain name to focus analysis on
    """
    if not logs:
        return {
            "destination_ip": {"description": "Most common destination IPs", "data": {}, "summary": "No data available"},
            "destination_port": {"description": "Most common destination ports", "data": {}, "summary": "No data available"},
            "source_username": {"description": "Most common usernames", "data": {}, "summary": "No data available"},
            "device_name": {"description": "Most common device names", "data": {}, "summary": "No data available"},
            "process_name": {"description": "Most common process names", "data": {}, "summary": "No data available"},
            "alert_type": {"description": "Most common alert types", "data": {}, "summary": "No data available"},
            "action": {"description": "Most common actions", "data": {}, "summary": "No data available"},
        }
    
    try:
        # Ensure logs is a list
        if not isinstance(logs, list):
            print(f"Warning: logs is not a list but {type(logs)}")
            if isinstance(logs, dict):
                # Try to convert if it's a dictionary
                logs = [logs]
            else:
                # Return empty structured dict on invalid input
                return {
                    "destination_ip": {"description": "Most common destination IPs", "data": {}, "summary": "Invalid input format"},
                    "destination_port": {"description": "Most common destination ports", "data": {}, "summary": "Invalid input format"},
                    "source_username": {"description": "Most common usernames", "data": {}, "summary": "Invalid input format"},
                    "device_name": {"description": "Most common device names", "data": {}, "summary": "Invalid input format"},
                    "process_name": {"description": "Most common process names", "data": {}, "summary": "Invalid input format"},
                    "alert_type": {"description": "Most common alert types", "data": {}, "summary": "Invalid input format"},
                    "action": {"description": "Most common actions", "data": {}, "summary": "Invalid input format"},
                }
        
        # Initialize pattern categories
        patterns = {
            "destination_ip": {"description": "Most common destination IPs", "data": {}},
            "destination_port": {"description": "Most common destination ports", "data": {}},
            "source_username": {"description": "Most common usernames", "data": {}},
            "device_name": {"description": "Most common device names", "data": {}},
            "process_name": {"description": "Most common process names", "data": {}},
            "alert_type": {"description": "Most common alert types", "data": {}},
            "action": {"description": "Most common actions", "data": {}},
        }
        
        # Filter logs by domain if a domain is provided
        if domain:
            filtered_logs = []
            for log in logs:
                if not isinstance(log, dict):
                    continue
                    
                # Check if the log contains the specified domain
                log_domain = log.get('domain') or log.get('destination_domain') or log.get('domain_name')
                if log_domain and domain.lower() in log_domain.lower():
                    filtered_logs.append(log)
                    
                # Also check in URI or URL fields
                uri = log.get('uri') or log.get('url') or log.get('resource')
                if uri and domain.lower() in uri.lower():
                    filtered_logs.append(log)
            
            # Use filtered logs if any were found, otherwise use all logs
            if filtered_logs:
                print(f"Filtered logs by domain {domain}: found {len(filtered_logs)} of {len(logs)} logs")
                logs = filtered_logs
            else:
                print(f"No logs found for domain {domain}, using all {len(logs)} logs")
        
        # Process each log entry
        for log in logs:
            if not isinstance(log, dict):
                print(f"Warning: log entry is not a dictionary but {type(log)}")
                continue
                
            # Extract and count destination IPs
            dest_ip = log.get('destination_ip') or log.get('dest_ip') or log.get('dstip') or log.get('dst_ip')
            if dest_ip and isinstance(dest_ip, str) and dest_ip.strip():
                patterns["destination_ip"]["data"][dest_ip] = patterns["destination_ip"]["data"].get(dest_ip, 0) + 1
            
            # Extract and count destination ports
            dest_port = log.get('destination_port') or log.get('dest_port') or log.get('dstport') or log.get('dst_port')
            # Convert port to string if it's a number
            if dest_port is not None:
                if isinstance(dest_port, (int, float)):
                    dest_port = str(int(dest_port))
                if isinstance(dest_port, str) and dest_port.strip():
                    patterns["destination_port"]["data"][dest_port] = patterns["destination_port"]["data"].get(dest_port, 0) + 1
            
            # Extract and count usernames
            username = log.get('username') or log.get('user') or log.get('source_user') or log.get('src_user')
            if username and isinstance(username, str) and username.strip():
                patterns["source_username"]["data"][username] = patterns["source_username"]["data"].get(username, 0) + 1
            
            # Extract and count device names
            device = log.get('device_name') or log.get('host') or log.get('hostname') or log.get('source_host')
            if device and isinstance(device, str) and device.strip():
                patterns["device_name"]["data"][device] = patterns["device_name"]["data"].get(device, 0) + 1
            
            # Extract and count process names
            process = log.get('process_name') or log.get('process') or log.get('image') or log.get('executable')
            if process and isinstance(process, str) and process.strip():
                patterns["process_name"]["data"][process] = patterns["process_name"]["data"].get(process, 0) + 1
            
            # Extract and count alert types
            alert_type = log.get('alert_type') or log.get('alert') or log.get('detection_type') or log.get('event_type')
            if alert_type and isinstance(alert_type, str) and alert_type.strip():
                patterns["alert_type"]["data"][alert_type] = patterns["alert_type"]["data"].get(alert_type, 0) + 1
            
            # Extract and count actions
            action = log.get('action') or log.get('status') or log.get('result')
            if action and isinstance(action, str) and action.strip():
                patterns["action"]["data"][action] = patterns["action"]["data"].get(action, 0) + 1
        
        # Sort each category by frequency and ensure proper format
        for category in patterns:
            # Ensure data is a dictionary and not empty
            if not patterns[category]["data"] or not isinstance(patterns[category]["data"], dict):
                patterns[category]["data"] = {}
                patterns[category]["summary"] = "No data available for this category."
                continue
                
            # Get the top occurrences    
            try:
                sorted_items = sorted(patterns[category]["data"].items(), key=lambda x: -1 * x[1])
                top_items = sorted_items[:5]  # Top 5 items
                
                # Generate a summary
                summary_parts = []
                for item, count in top_items:
                    summary_parts.append(f"{item} ({count})")
                
                patterns[category]["summary"] = f"Top items: {', '.join(summary_parts)}"
            except Exception as e:
                print(f"Error processing {category} data: {str(e)}")
                patterns[category]["summary"] = "Error processing data."
                # Ensure data is a dictionary even if sorting failed
                if not isinstance(patterns[category]["data"], dict):
                    patterns[category]["data"] = {}
        
        return patterns
        
    except Exception as e:
        print(f"Error in analyze_log_patterns: {str(e)}")
        # Return structured empty dict on error
        return {
            "destination_ip": {"description": "Most common destination IPs", "data": {}, "summary": f"Error: {str(e)}"},
            "destination_port": {"description": "Most common destination ports", "data": {}, "summary": f"Error: {str(e)}"},
            "source_username": {"description": "Most common usernames", "data": {}, "summary": f"Error: {str(e)}"},
            "device_name": {"description": "Most common device names", "data": {}, "summary": f"Error: {str(e)}"},
            "process_name": {"description": "Most common process names", "data": {}, "summary": f"Error: {str(e)}"},
            "alert_type": {"description": "Most common alert types", "data": {}, "summary": f"Error: {str(e)}"},
            "action": {"description": "Most common actions", "data": {}, "summary": f"Error: {str(e)}"},
        }

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
    
    try:
        # Add each pattern category
        for category, info in patterns.items():
            if not isinstance(info, dict):
                continue
                
            # Use description field if available, or category name if label is missing
            label = info.get('description', info.get('label', category.replace('_', ' ').title()))
            result.append(f"\n{label}:")
            
            # Safely extract and process data
            data = info.get('data', {})
            if not isinstance(data, dict) or not data:
                result.append("- No data available")
                continue
                
            try:
                # Sort data by count (descending)
                sorted_items = sorted(data.items(), key=lambda x: -1 * x[1] if isinstance(x[1], (int, float)) else 0)
                
                # Add top 10 items
                for item, count in sorted_items[:10]:
                    result.append(f"- {item}: {count} occurrences")
                    
                # Add a note if there are more items
                if len(sorted_items) > 10:
                    result.append(f"- ... and {len(sorted_items) - 10} more items")
            except Exception as e:
                print(f"Error formatting items for {category}: {str(e)}")
                result.append("- Error processing items")
    except Exception as e:
        print(f"Error in format_log_patterns: {str(e)}")
        return "Error formatting log patterns."
    
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
                    related_incidents_data = None
                    related_incidents_text = "No related incidents found."
                    if 'related_incidents_data' in locals() and related_incidents_data:
                        f.write("5. RELATED INCIDENTS\n")
                        f.write("-------------------\n")
                        f.write(related_incidents_text + "\n\n")
                    
                    # Add comment analysis and progression section
                    f.write("6. INVESTIGATION CONTEXT (Based on Comments):\n")
                    f.write("-----------------------------------------\n")
                    f.write(f"Total Comments: {comment_analysis.get('total_comments', 0)}\n")
                    llm_comment_summary = "No LLM summary of comments available."
                    f.write(f"Summary: {comment_analysis.get('summary', llm_comment_summary)}\n\n")
                    
                    # Add MITRE ATT&CK section if techniques found
                    mitre_techniques = []
                    technique_details = {}
                    if 'mitre_techniques' in locals() and mitre_techniques:
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
                    related_incidents_data = None
                    related_incidents_text = "No related incidents found."
                    if 'related_incidents_data' in locals() and related_incidents_data:
                        f.write("5. RELATED INCIDENTS\n")
                        f.write("-------------------\n")
                        f.write(related_incidents_text + "\n\n")
                    
                    # Add comment analysis and progression section
                    f.write("6. INVESTIGATION CONTEXT (Based on Comments):\n")
                    f.write("-----------------------------------------\n")
                    f.write(f"Total Comments: {comment_analysis.get('total_comments', 0)}\n")
                    llm_comment_summary = "No LLM summary of comments available."
                    f.write(f"Summary: {comment_analysis.get('summary', llm_comment_summary)}\n\n")
                    
                    # Add MITRE ATT&CK section if techniques found
                    mitre_techniques = []
                    technique_details = {}
                    if 'mitre_techniques' in locals() and mitre_techniques:
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
    """Format the SOC analyst report into a readable text format with enhanced evidence display"""
    sections = []
    
    # Create header with incident information
    header = f"""
===============================================
        SOC ANALYST REPORT: INCIDENT #{analysis_output.incident_id}
        {analysis_output.incident_title}
===============================================

SEVERITY: {analysis_output.severity_indicator}

EXECUTIVE SUMMARY:
{analysis_output.executive_summary}

"""
    sections.append(header)
    
    # Create immediate actions section with narrative format
    if analysis_output.immediate_actions:
        actions_section = "A. Immediate Actions (First 1-2 hours)\n"
        
        for action in analysis_output.immediate_actions:
            if isinstance(action, dict):
                # Handle legacy format with description/evidence
                desc = action.get('description', 'No description')
                actions_section += f"\n{desc}\n"
                
                # Add evidence if available
                evidence = action.get('evidence', [])
                if evidence:
                    actions_section += "EVIDENCE:\n"
                    for ev in evidence:
                        actions_section += f"• {ev}\n"
            else:
                # Handle new narrative string format
                actions_section += f"\n{action}\n"
        
        sections.append(actions_section)
    
    # Create future steps section with narrative format
    if analysis_output.future_steps:
        steps_section = "B. Future Steps (Next 24 hours)\n"
        
        for step in analysis_output.future_steps:
            if isinstance(step, dict):
                # Handle legacy format with description/data_points
                desc = step.get('description', 'No description')
                steps_section += f"\n{desc}\n"
                
                # Add data points if available
                data_points = step.get('data_points', [])
                if data_points:
                    steps_section += "EVIDENCE:\n"
                    for dp in data_points:
                        steps_section += f"• {dp}\n"
            else:
                # Handle new narrative string format
                steps_section += f"\n{step}\n"
        
        sections.append(steps_section)
    
    # Include MITRE ATT&CK techniques if available
    if hasattr(analysis_output, 'attack_techniques') and analysis_output.attack_techniques:
        tech_section = "C. MITRE ATT&CK Techniques\n"
        technique_details = analysis_output.technique_details if hasattr(analysis_output, 'technique_details') else {}
        
        for technique in analysis_output.attack_techniques:
            tech_section += f"\n• {technique}"
            if technique in technique_details:
                tech_section += f"\n  {technique_details[technique].get('description', '')}"
        
        sections.append(tech_section)
    
    # Add threat intelligence context if available
    if hasattr(analysis_output, 'threat_intel_context') and analysis_output.threat_intel_context and analysis_output.threat_intel_context != "Not provided":
        if isinstance(analysis_output.threat_intel_context, dict):
            ti_section = "D. Threat Intelligence Context\n"
            for k, v in analysis_output.threat_intel_context.items():
                if k != "raw_data":  # Skip raw data
                    ti_section += f"\n{k}: {v}"
            sections.append(ti_section)
        else:
            sections.append(f"D. Threat Intelligence Context\n\n{analysis_output.threat_intel_context}")
    
    # Add other sections if they exist and have content
    if hasattr(analysis_output, 'business_impact') and analysis_output.business_impact != {}:
        if isinstance(analysis_output.business_impact, dict):
            impact_section = "E. Business Impact Assessment\n"
            for k, v in analysis_output.business_impact.items():
                impact_section += f"\n{k}: {v}"
            sections.append(impact_section)
        else:
            sections.append(f"E. Business Impact Assessment\n\n{analysis_output.business_impact}")
    
    # Add metrics panel if available
    if hasattr(analysis_output, 'metrics_panel') and analysis_output.metrics_panel != {}:
        metrics_section = "F. Key Metrics\n"
        if isinstance(analysis_output.metrics_panel, dict):
            for k, v in analysis_output.metrics_panel.items():
                metrics_section += f"\n{k}: {v}"
        else:
            metrics_section += f"\n{analysis_output.metrics_panel}"
        sections.append(metrics_section)
    
    # Combine all sections
    return "\n\n".join(sections)

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

def build_rag_context(incident_data: Dict[str, Any], logs: List[Dict[str, Any]], 
                      indicators: SecurityIndicators, alerts: List[Dict[str, Any]],
                      vt_results: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """
    Build a structured RAG context from all available incident data sources.
    Returns a dictionary of context sections that can be used for retrieval.
    """
    rag_context = {}
    
    # 1. Incident details
    incident_context = []
    for k, v in incident_data.items():
        if v and str(v).lower() not in ["nan", "none", "unknown"]:
            incident_context.append(f"{k}: {v}")
    rag_context["INCIDENT_DETAILS"] = "\n".join(incident_context)
    
    # 2. Associated alerts
    if alerts:
        alert_context = []
        for alert in alerts:
            alert_info = [
                f"Alert: {alert.get('alertDisplayName', 'Unknown')}",
                f"Severity: {alert.get('severity', 'Unknown')}",
                f"Description: {alert.get('description', 'No description')}",
                f"Entities: {', '.join([e.get('displayName', 'Unknown') for e in alert.get('entities', [])])}"
            ]
            alert_context.append("\n".join(alert_info))
        rag_context["ASSOCIATED_ALERTS"] = "\n\n".join(alert_context)
    
    # 3. VirusTotal domain reputation
    if vt_results:
        vt_context = []
        for domain, results in vt_results.items():
            vt_context.append(f"Domain: {domain}")
            vt_context.append(f"Malicious Score: {results.get('malicious_score', 'Unknown')}")
            vt_context.append(f"Categories: {', '.join(results.get('categories', ['None']))}")
            vt_context.append(f"Detection Names: {', '.join(results.get('detection_names', ['None']))}")
        rag_context["VIRUSTOTAL_DOMAIN_REPUTATION"] = "\n".join(vt_context)
    
    # 4. Log patterns
    if logs:
        # Get summary patterns
        log_patterns = analyze_log_patterns(logs)
        pattern_text = format_log_patterns(log_patterns)
        rag_context["LOG_PATTERNS"] = pattern_text
        
        # Add user-domain activity summary if available
        if indicators.domains:
            user_domain_summary, user_domain_details = summarize_user_domain_activity(logs, indicators.domains)
            rag_context["USER_DOMAIN_ACTIVITY"] = user_domain_summary
    
    # 5. Indicators summary
    indicator_context = []
    for field_name in ["domains", "ips", "external_ips", "internal_ips", "users", "file_hashes", "cves", "urls"]:
        field_value = getattr(indicators, field_name, [])
        if field_value:
            indicator_context.append(f"{field_name.upper()}: {', '.join(field_value)}")
    rag_context["INDICATORS"] = "\n".join(indicator_context)
    
    return rag_context

def generate_triage_summary(enhanced_context: Dict[str, Dict[str, Any]], 
                           logs: List[Dict[str, Any]],
                           vt_results: Optional[Dict[str, Any]] = None,
                           indicators: SecurityIndicators = None) -> str:
    """
    Generate a concise triage summary highlighting key findings from enhanced context and log patterns.
    This is positioned at the beginning of the LLM context to focus attention on critical information.
    """
    summary_sections = ["=== KEY FINDINGS FOR TRIAGE ==="]
    
    # Extract most active users from logs
    try:
        # Ensure logs is properly formatted before analysis
        if not isinstance(logs, list):
            print(f"Warning: logs is not a list but {type(logs)}")
            if isinstance(logs, dict):
                logs = [logs]
            else:
                logs = []
                
        log_patterns = analyze_log_patterns(logs)
        # Ensure log_patterns is a dictionary with proper structure
        if not isinstance(log_patterns, dict):
            print(f"Warning: analyze_log_patterns returned non-dictionary type: {type(log_patterns)}")
            log_patterns = {
                "destination_ip": {"description": "Most common destination IPs", "data": {}, "summary": "No data available"},
                "destination_port": {"description": "Most common destination ports", "data": {}, "summary": "No data available"},
                "source_username": {"description": "Most common usernames", "data": {}, "summary": "No data available"},
                "device_name": {"description": "Most common device names", "data": {}, "summary": "No data available"},
                "process_name": {"description": "Most common process names", "data": {}, "summary": "No data available"},
                "alert_type": {"description": "Most common alert types", "data": {}, "summary": "No data available"},
                "action": {"description": "Most common actions", "data": {}, "summary": "No data available"},
            }
    except Exception as e:
        print(f"Error fetching or processing logs: {str(e)}")
        log_patterns = {
            "destination_ip": {"description": "Most common destination IPs", "data": {}, "summary": "Error occurred"},
            "destination_port": {"description": "Most common destination ports", "data": {}, "summary": "Error occurred"},
            "source_username": {"description": "Most common usernames", "data": {}, "summary": "Error occurred"},
            "device_name": {"description": "Most common device names", "data": {}, "summary": "Error occurred"},
            "process_name": {"description": "Most common process names", "data": {}, "summary": "Error occurred"},
            "alert_type": {"description": "Most common alert types", "data": {}, "summary": "Error occurred"},
            "action": {"description": "Most common actions", "data": {}, "summary": "Error occurred"},
        }
    
    # Use more robust user activity extraction
    user_activity = {}
    if log_patterns and "source_username" in log_patterns:
        try:
            # First verify 'data' field exists and initialize if needed
            if not isinstance(log_patterns["source_username"], dict):
                log_patterns["source_username"] = {"data": {}, "description": "Most common usernames"}
                
            if "data" not in log_patterns["source_username"]:
                log_patterns["source_username"]["data"] = {}
                
            pattern_data = log_patterns["source_username"]["data"]
            
            if isinstance(pattern_data, dict):
                # If it's already a dictionary, use it directly
                user_activity = pattern_data
            elif isinstance(pattern_data, list):
                # If it's a list, convert it to a dict by counting occurrences
                for user in pattern_data:
                    if isinstance(user, str):
                        user_activity[user] = user_activity.get(user, 0) + 1
                print(f"Converted list of users to dictionary with {len(user_activity)} entries")
            else:
                print(f"Warning: source_username data has unexpected type: {type(pattern_data)}")
                # Create empty dictionary to avoid errors
                user_activity = {}
        except Exception as e:
            print(f"Error processing user activity data: {str(e)}")
            user_activity = {}
    
    # Process primary threat domains with defensive checks
    threat_domains = []
    if enhanced_context and isinstance(enhanced_context, dict) and "domains" in enhanced_context:
        try:
            for domain, data in enhanced_context["domains"].items():
                if not isinstance(data, dict):
                    print(f"Warning: domain data for {domain} is not a dictionary")
                    continue
                    
                vt_score = "N/A"
                vt_category = ""
                
                # Check if vt_results exists and has valid domain data
                if vt_results and isinstance(vt_results, dict) and domain in vt_results:
                    domain_result = vt_results[domain]
                    if isinstance(domain_result, dict):
                        vt_score = domain_result.get("malicious_score", "N/A")
                        categories = domain_result.get("categories", [])
                        if isinstance(categories, list) and categories:
                            vt_category = f", Category: {', '.join(categories[:2])}" 
                
                mentions = data.get("mentions", 0)
                connected_hosts = []
                if "connected_hosts" in data and isinstance(data["connected_hosts"], list):
                    connected_hosts = data["connected_hosts"]
                
                threat_domains.append((domain, vt_score, vt_category, mentions, len(connected_hosts)))
        except Exception as e:
            print(f"Error processing threat domains: {str(e)}")
    
    # Sort domains by VT score (if available) and mentions - with error handling
    try:
        if threat_domains:
            def safe_sort_key(x):
                try:
                    vt_score = 0
                    if x[1] != "N/A":
                        try:
                            vt_score = float(x[1])
                        except:
                            vt_score = 0
                    mentions = x[3] if isinstance(x[3], (int, float)) else 0
                    return (-1 * vt_score, -1 * mentions)
                except:
                    return (0, 0)
                    
            threat_domains.sort(key=safe_sort_key)
    except Exception as e:
        print(f"Error sorting threat domains: {str(e)}")
    
    # Add primary threat information
    if threat_domains:
        try:
            domain, vt_score, vt_category, mentions, connected_hosts = threat_domains[0]
            host_info = f" (contacted by {connected_hosts} hosts)" if connected_hosts > 0 else ""
            summary_sections.append(f"* Primary Threat: Domain {domain} (VT Score: {vt_score}{vt_category}){host_info}")
        except Exception as e:
            print(f"Error adding primary threat information: {str(e)}")
            summary_sections.append("* Primary Threat: Could not determine due to data error")
    
    # Find key affected hosts with defensive programming
    affected_hosts = []
    if enhanced_context and isinstance(enhanced_context, dict) and "hosts" in enhanced_context:
        try:
            for host, data in enhanced_context["hosts"].items():
                if not isinstance(data, dict):
                    continue
                    
                mentions = data.get("mentions", 0)
                
                domains = []
                if "domains" in data and isinstance(data["domains"], list):
                    domains = data["domains"]
                    
                alerts = []
                if "alerts" in data and isinstance(data["alerts"], list):
                    alerts = data["alerts"]
                    
                affected_hosts.append((host, mentions, len(domains), len(alerts)))
        except Exception as e:
            print(f"Error processing affected hosts: {str(e)}")
    
    # Sort hosts by mentions and number of suspicious domains contacted - with error handling
    try:
        if affected_hosts:
            def safe_host_sort_key(x):
                try:
                    mentions = x[1] if isinstance(x[1], (int, float)) else 0
                    domains = x[2] if isinstance(x[2], (int, float)) else 0
                    alerts = x[3] if isinstance(x[3], (int, float)) else 0
                    return (-1 * mentions, -1 * domains, -1 * alerts)
                except:
                    return (0, 0, 0)
            
            affected_hosts.sort(key=safe_host_sort_key)
    except Exception as e:
        print(f"Error sorting affected hosts: {str(e)}")
    
    # Add key affected host information
    if affected_hosts:
        try:
            host, mentions, domains, alerts = affected_hosts[0]
            domain_info = f", contacted {domains} suspicious domains" if domains > 0 else ""
            alert_info = f", {alerts} associated alerts" if alerts > 0 else ""
            summary_sections.append(f"* Key Affected Host: {host} ({mentions} log mentions{domain_info}{alert_info})")
        except Exception as e:
            print(f"Error adding affected host information: {str(e)}")
            summary_sections.append("* Key Affected Host: Could not determine due to data error")
    
    # Find high severity alerts with defensive programming
    high_severity_alerts = []
    if enhanced_context and isinstance(enhanced_context, dict) and "alerts" in enhanced_context:
        try:
            for alert_id, data in enhanced_context.get("alerts", {}).items():
                if not isinstance(data, dict):
                    continue
                    
                severity = str(data.get("severity", "")).lower()
                if severity in ["high", "critical"]:
                    title = data.get("title", "Unknown Alert")
                    
                    entities = []
                    if "entities" in data and isinstance(data["entities"], list):
                        entities = data["entities"]
                        
                    high_severity_alerts.append((title, severity, entities))
        except Exception as e:
            print(f"Error processing high severity alerts: {str(e)}")
    
    # Add high severity alert information
    if high_severity_alerts:
        try:
            title, severity, entities = high_severity_alerts[0]
            entity_info = ""
            if entities and len(entities) > 0:
                entity_info = f" on {', '.join(entities[:2])}"
            summary_sections.append(f"* Associated High-Severity Alert: \"{title}\" ({severity.capitalize()}){entity_info}")
        except Exception as e:
            print(f"Error adding high severity alert information: {str(e)}")
            summary_sections.append("* Associated High-Severity Alert: Could not determine due to data error")
    
    # Add key activity information from logs
    if log_patterns and isinstance(log_patterns, dict):
        activities = []
        
        try:
            # Check for suspicious ports - with enhanced type checking
            if "destination_port" in log_patterns and isinstance(log_patterns["destination_port"], dict):
                port_data = log_patterns["destination_port"].get("data", {})
                suspicious_ports = ["53", "443", "8080", "4444", "22"]  # Common C2 ports
                
                # Handle dictionary format
                if isinstance(port_data, dict):
                    for port, count in port_data.items():
                        if str(port) in suspicious_ports and count > 5:
                            activities.append(f"Outbound connections on port {port} ({count} occurrences)")
                # Handle list format
                elif isinstance(port_data, list):
                    # Count occurrences of each port
                    port_counts = {}
                    for port in port_data:
                        port_str = str(port)
                        port_counts[port_str] = port_counts.get(port_str, 0) + 1
                    # Check for suspicious ports
                    for port, count in port_counts.items():
                        if port in suspicious_ports and count > 5:
                            activities.append(f"Outbound connections on port {port} ({count} occurrences)")
        except Exception as e:
            print(f"Error processing port data: {str(e)}")
        
        try:
            # Check for process activity - with enhanced type checking
            if "process_name" in log_patterns and isinstance(log_patterns["process_name"], dict):
                process_data = log_patterns["process_name"].get("data", {})
                suspicious_processes = ["powershell.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe"]
                
                # Handle dictionary format
                if isinstance(process_data, dict):
                    for process, count in process_data.items():
                        process_str = str(process).lower()
                        if any(susp in process_str for susp in suspicious_processes) and count > 3:
                            activities.append(f"Suspicious process {process} ({count} executions)")
                # Handle list format
                elif isinstance(process_data, list):
                    # Count occurrences of each process
                    process_counts = {}
                    for process in process_data:
                        if process:
                            process_str = str(process).lower()
                            process_counts[process_str] = process_counts.get(process_str, 0) + 1
                    # Check for suspicious processes
                    for process, count in process_counts.items():
                        if any(susp in process for susp in suspicious_processes) and count > 3:
                            activities.append(f"Suspicious process {process} ({count} executions)")
        except Exception as e:
            print(f"Error processing process data: {str(e)}")
        
        if activities:
            summary_sections.append(f"* Key Activity: {activities[0]}")
    
    # Add activity window if we have timestamps
    earliest_time = None
    latest_time = None
    
    try:
        if enhanced_context and isinstance(enhanced_context, dict):
            for entity_type in ["domains", "hosts", "ips", "users"]:
                if entity_type in enhanced_context:
                    for entity, data in enhanced_context.get(entity_type, {}).items():
                        if not isinstance(data, dict):
                            continue
                            
                        timestamps = data.get("seen_at", [])
                        if not isinstance(timestamps, list):
                            continue
                            
                        for timestamp in timestamps:
                            try:
                                # Try various date parsing strategies
                                if isinstance(timestamp, datetime):
                                    dt = timestamp
                                elif isinstance(timestamp, str):
                                    try:
                                        # First try standard ISO format
                                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                                    except ValueError:
                                        try:
                                            # Then try pandas parsing
                                            dt = pd.to_datetime(timestamp)
                                        except:
                                            # Lastly try dateutil parser which is more flexible
                                            try:
                                                from dateutil.parser import parse
                                                dt = parse(timestamp)
                                            except:
                                                print(f"Could not parse timestamp: {timestamp}")
                                                continue
                                else:
                                    # Skip non-string, non-datetime objects
                                    continue
                                    
                                if earliest_time is None or dt < earliest_time:
                                    earliest_time = dt
                                if latest_time is None or dt > latest_time:
                                    latest_time = dt
                            except Exception as e:
                                # Just continue on error parsing a specific timestamp
                                continue
    except Exception as e:
        print(f"Error processing timestamps: {str(e)}")
    
    if earliest_time and latest_time:
        try:
            # Format timestamps
            earliest_str = earliest_time.strftime("%Y-%m-%d %H:%M")
            latest_str = latest_time.strftime("%Y-%m-%d %H:%M")
            
            # Calculate duration
            duration = latest_time - earliest_time
            if duration.days > 0:
                duration_str = f"{duration.days} days, {duration.seconds // 3600} hours"
            elif duration.seconds > 3600:
                duration_str = f"{duration.seconds // 3600} hours, {(duration.seconds % 3600) // 60} minutes"
            else:
                duration_str = f"{duration.seconds // 60} minutes"
            
            summary_sections.append(f"* Activity Window: Started {earliest_str}, lasted {duration_str}")
        except Exception as e:
            print(f"Error formatting timestamp information: {str(e)}")
    
    # Add most active users section with robust error handling
    try:
        if user_activity and isinstance(user_activity, dict) and len(user_activity) > 0:
            summary_sections.append("* Most Active Users (from logs):")
            # Safely sort user_activity
            try:
                sorted_users = sorted(user_activity.items(), key=lambda x: -1 * x[1] if isinstance(x[1], (int, float)) else 0)
            except Exception as e:
                print(f"Error sorting user activity: {str(e)}")
                # Just use the items directly if sorting fails
                sorted_users = list(user_activity.items())
                
            # Limit to top 5 users
            user_count = 0
            for user, count in sorted_users:
                if user_count >= 5:  # Only show top 5
                    break
                    
                if user != "Unknown" and user and str(user).strip():
                    user_count += 1
                    connected_domains = []
                    
                    # Safely get connected domains
                    try:
                        if enhanced_context and isinstance(enhanced_context, dict) and "domains" in enhanced_context:
                            for domain, data in enhanced_context.get("domains", {}).items():
                                if isinstance(data, dict) and "connected_users" in data:
                                    connected_user_list = data.get("connected_users", [])
                                    if isinstance(connected_user_list, list) and user in connected_user_list:
                                        connected_domains.append(domain)
                    except Exception as e:
                        print(f"Error getting connected domains for user {user}: {str(e)}")
                    
                    domain_info = ""
                    if connected_domains:
                        domain_info = f", connected to domains: {', '.join(connected_domains[:2])}"
                        
                    summary_sections.append(f"  - {user}: {count} occurrences{domain_info}")
    except Exception as e:
        print(f"Error adding user activity section: {str(e)}")
        summary_sections.append("* Most Active Users: Error processing user data")
    
    return "\n".join(summary_sections)

def generate_soc_analyst_report(incident_data: Dict[str, Any], logs: List[Dict[str, Any]], 
                              indicators: SecurityIndicators, alerts: List[Dict[str, Any]],
                              example_actions: List[Dict[str, Any]] = None,
                              example_future_steps: List[Dict[str, Any]] = None,
                              threat_intel_context: Optional[Union[str, Dict[str, Any]]] = None) -> IncidentAnalysisOutput: # Added parameters
    """Generate a comprehensive SOC analyst report using local LLM with enhanced RAG context"""
    
    # Get the same essential values used in the prompt
    primary_domain = indicators.domains[0] if indicators.domains else None
    primary_ip = indicators.external_ips[0] if indicators.external_ips else (indicators.ips[0] if indicators.ips else None)
    primary_user = indicators.users[0] if indicators.users else None
    
    # Get top 5 entities from logs
    device_counts = {}
    user_counts = {}
    ip_counts = {}
    
    for log in logs:
        device = log.get('device', log.get('Computer', log.get('DeviceName', None)))
        if device:
            device_counts[device] = device_counts.get(device, 0) + 1
            
        user = log.get('user', log.get('User', log.get('UserName', None)))
        if user:
            user_counts[user] = user_counts.get(user, 0) + 1
            
        ip = log.get('ip', log.get('IpAddress', log.get('IPAddress', None)))
        if ip:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
    
    # Sort by count
    top_devices = sorted(device_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    top_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    
    # Get primary device if available
    primary_device = top_devices[0][0] if top_devices else None
    
    # Build enhanced RAG context from all available data sources
    print("Building enhanced entity-centric RAG context from incident data...")
    vt_results = None
    if VIRUSTOTAL_AVAILABLE and indicators.domains:
        try:
            # Get VirusTotal results for domains if available
            vt_results = analyze_domains(indicators.domains)
            print(f"Added VirusTotal data for {len(vt_results)} domains to RAG context")
        except Exception as e:
            print(f"Error fetching VirusTotal data: {str(e)}")
    
    # Build and format the enhanced RAG context
    enhanced_context = build_enhanced_rag_context(incident_data, logs, indicators, alerts, vt_results)
    
    # NEW: Generate the key findings for triage summary
    print("Extracting key findings for triage from enhanced context...")
    triage_summary = generate_triage_summary(enhanced_context, logs, vt_results, indicators)
    print("Key triage findings extracted")
    
    # Format the complete context
    formatted_context = format_enhanced_rag_context(enhanced_context)
    print(f"Created enhanced entity-centric RAG context with {len(enhanced_context['domains'])} domains, {len(enhanced_context['hosts'])} hosts, {len(enhanced_context['users'])} users")
    
    # Generate the SOC analyst prompt
    base_prompt = generate_soc_analyst_prompt(incident_data, logs, indicators, alerts, example_actions, example_future_steps)
    
    # Create enhanced prompt with simplified evidence instructions to improve LLM reliability
    evidence_instructions = """
### Evidence-Based Response Requirements:
1. For EACH immediate action and future step, include specific evidence from the context.
2. Keep your evidence concise and focused on the key facts.
3. Reference specific entities, activities, and relationships from the context.
4. Pay special attention to the KEY FINDINGS FOR TRIAGE section which highlights critical information.
"""
    
    # Combine the base prompt with enhanced evidence instructions and prepend the triage summary
    enhanced_prompt = f"{base_prompt}\n\n{evidence_instructions}\n\n{triage_summary}\n\n=== ENHANCED CONTEXT FOR EVIDENCE-BASED RECOMMENDATIONS ===\n\n{formatted_context}"
    print(f"Created enhanced prompt with evidence requirements and triage summary ({len(enhanced_prompt)} chars)")

    # Call LocalLLM using the integration module
    try:
        print("Generating evidence-based SOC analyst report with local LLM...")
        
        async def generate_with_local_llm():
            # Get LocalLLM client
            llm_client = await get_local_llm_client(model=OLLAMA_MODEL)
            
            # Generate JSON response with simplified schema to improve reliability
            system_prompt = """You are an expert SOC analyst providing detailed, actionable security incident analysis.
            
Your response must be valid JSON with the following essential fields:
- executive_summary: A brief summary of the incident, its impact, and required actions
- severity_indicator: One of "Critical", "High", "Medium", or "Low"
- immediate_actions: An array of strings, each describing a specific action with embedded evidence
- future_steps: An array of strings, each describing an investigation step with embedded evidence

Format each immediate action and future step as a complete sentence that:
1. Clearly states the specific action to take
2. Incorporates key entities (domains, IPs, users, systems) directly in the text
3. References specific evidence without requiring separate fields

For example:
- "Block domain ecomicrolab.com across firewall, proxy, and endpoint systems to prevent further malicious communication."
- "Isolate systems that have interacted with the domain, such as the device with IP 10.248.28.157, to contain any potential threat."
- "Review DNS logs (Event ID 22) across endpoints for queries related to ecomicrolab.com or similar variations."

Focus on the entities and relationships highlighted in the KEY FINDINGS FOR TRIAGE section.
Create detailed, specific actions that reference actual entities from the data.
"""
            
            # Create a simplified schema with only essential fields to improve reliability
            simplified_schema = {
                "type": "object",
                "properties": {
                    "executive_summary": {"type": "string", "description": "2-3 sentence summary of the incident"},
                    "severity_indicator": {"type": "string", "enum": ["Critical", "High", "Medium", "Low"]},
                    "immediate_actions": {
                        "type": "array",
                        "items": {"type": "string", "description": "Narrative action with embedded evidence"}
                    },
                    "future_steps": {
                        "type": "array",
                        "items": {"type": "string", "description": "Narrative investigation step with embedded evidence"}
                    }
                },
                "required": ["executive_summary", "severity_indicator", "immediate_actions", "future_steps"]
            }
            
            try:
                response_data = await llm_client.generate_json(
                    prompt=enhanced_prompt,
                    system_prompt=system_prompt,
                    schema=simplified_schema
                )
                return response_data
            except Exception as e:
                print(f"Error generating JSON with LLM: {str(e)}")
                # Return a basic structure that will trigger fallbacks
                return {"error": f"Failed to generate valid JSON: {str(e)}"}
                
        # Run the async function
        loop = asyncio.get_event_loop()
        analysis_data = loop.run_until_complete(generate_with_local_llm())
        print("Evidence-enhanced LLM response received.")

        # Create fallback actions and steps based on available data (Windows focused, matching user examples style)
        fallback_actions = []
        if primary_domain:
            vt_evidence = ""
            if vt_results and primary_domain in vt_results:
                vt_score = vt_results[primary_domain].get("malicious_score", "Unknown")
                vt_evidence = f" [VT Score: {vt_score}]"
                
            domain_hosts = []
            domain_users = []
            if primary_domain in enhanced_context["domains"]:
                domain_hosts = enhanced_context["domains"][primary_domain].get("connected_hosts", [])
                domain_users = enhanced_context["domains"][primary_domain].get("connected_users", [])
            
            host_evidence = f", accessed by {len(domain_hosts)} systems" if domain_hosts else ""
            user_evidence = f", accessed by users: {', '.join(domain_users[:3])}" if domain_users else ""
            
            fallback_actions.append({
                "description": f"Block domain {primary_domain} at Firewall/Proxy/DNS Filter levels{vt_evidence}{host_evidence}.",
                "evidence": [
                    f"Domain found in incident indicators",
                    f"VT Reputation: {vt_results[primary_domain].get('malicious_score', 'Unknown')}" if vt_results and primary_domain in vt_results else "No VT data available",
                    f"Connected systems: {', '.join(domain_hosts[:3])}" if domain_hosts else "No systems found in logs"
                ]
            })
        
        if primary_device:
            device_data = enhanced_context["hosts"].get(primary_device, {})
            domains = device_data.get("domains", [])
            users = device_data.get("users", [])
            activities = device_data.get("activities", [])
            
            domain_evidence = f", contacted suspicious domains: {', '.join(domains[:2])}" if domains else ""
            activity_evidence = f", performed actions: {', '.join(activities[:2])}" if activities else ""
            
            fallback_actions.append({
                "description": f"Isolate system {primary_device} from the network{domain_evidence}{activity_evidence}.",
                "evidence": [
                    f"System appeared {device_data.get('mentions', 0)} times in logs",
                    f"Connected to domains: {', '.join(domains[:3])}" if domains else "No domain connections found",
                    f"Users on system: {', '.join(users[:3])}" if users else "No users found in logs"
                ]
            })
        
        if primary_user:
            user_data = enhanced_context["users"].get(primary_user, {})
            hosts = user_data.get("hosts", [])
            domains = user_data.get("domains", [])
            activities = user_data.get("activities", [])
            
            host_evidence = f", accessed systems: {', '.join(hosts[:2])}" if hosts else ""
            domain_evidence = f", accessed suspicious domains: {', '.join(domains[:2])}" if domains else ""
            
            fallback_actions.append({
                "description": f"Monitor account {primary_user} closely for suspicious activity{host_evidence}{domain_evidence}.",
                "evidence": [
                    f"User appeared {user_data.get('mentions', 0)} times in logs",
                    f"Accessed systems: {', '.join(hosts[:3])}" if hosts else "No system access found",
                    f"Accessed domains: {', '.join(domains[:3])}" if domains else "No domain access found"
                ]
            })
        
        # More evidence-based fallback actions
        fallback_actions.append({
            "description": "Capture volatile memory and disk image from involved systems for forensic analysis.",
            "evidence": [
                f"Multiple systems involved: {', '.join([h for h, _ in top_devices[:3]])}",
                f"Suspicious activities observed across {len(enhanced_context['hosts'])} systems",
                "Memory forensics needed to identify potential malware/persistence"
            ]
        })
        
        # Create evidence-based fallback future steps
        fallback_steps = []
        if primary_domain:
            domain_data = enhanced_context["domains"].get(primary_domain, {})
            hosts = domain_data.get("connected_hosts", [])
            users = domain_data.get("connected_users", [])
            
            host_evidence = f"Domain connected to {len(hosts)} systems" if hosts else "No systems found connecting to domain"
            user_evidence = f"Domain accessed by {len(users)} users" if users else "No users found accessing domain"
            
            fallback_steps.append({
                "description": f"Review DNS logs (Event ID 22) across endpoints for queries related to {primary_domain} or similar variations.",
                "data_points": [
                    f"Domain {primary_domain} identified as key indicator",
                    host_evidence,
                    user_evidence
                ]
            })
        
        if primary_device:
            device_data = enhanced_context["hosts"].get(primary_device, {})
            domains = device_data.get("domains", [])
            ips = device_data.get("ips", [])
            
            domain_evidence = f"System contacted {len(domains)} domains" if domains else "No domains found"
            ip_evidence = f"System connected to {len(ips)} IPs" if ips else "No IP connections found"
            
            fallback_steps.append({
                "description": f"Investigate process execution logs (Security ID 4688) on host {primary_device} around the time of the incident.",
                "data_points": [
                    f"System {primary_device} mentioned {device_data.get('mentions', 0)} times in logs",
                    domain_evidence,
                    ip_evidence
                ]
            })
        
        # Add the rest of the fallback steps...
        fallback_steps.append({
            "description": "Search EDR/Antivirus logs across the environment for alerts related to the identified indicators.",
            "data_points": [
                f"Multiple indicators identified: {len(indicators.domains)} domains, {len(indicators.ips)} IPs",
                f"Alert correlation needed across {len(enhanced_context['hosts'])} systems",
                f"{len(enhanced_context['alerts'])} alerts already associated with this incident"
            ]
        })
        
        if indicators.domains:
            fallback_steps.append({
                "description": "Analyze proxy logs for connections to identified malicious domains to understand user interaction patterns.",
                "data_points": [
                    f"Domains identified: {', '.join(indicators.domains[:3])}" + (f" and {len(indicators.domains)-3} more" if len(indicators.domains) > 3 else ""),
                    f"Domains accessed by {sum(len(d.get('connected_users', [])) for d in enhanced_context['domains'].values())} users",
                    f"Timeline analysis needed to establish access sequence"
                ]
            })
        
        # 3. Parse and Validate with Pydantic
        try:
            # Check if we got an error from the LLM client
            if isinstance(analysis_data, dict) and "error" in analysis_data:
                print(f"Error from LLM client: {analysis_data['error']}")
                analysis_data = {}  # Use empty dict to trigger fallbacks
            
            # Prepare actions and steps, ensuring they are in the right format
            immediate_actions = analysis_data.get("immediate_actions", [])
            if not immediate_actions:
                # Create narrative string fallbacks if none from LLM
                immediate_actions = [
                    f"Block domain {primary_domain} across firewall, proxy, and endpoint systems to prevent further malicious communication.",
                    f"Isolate system {primary_device} from the network to contain any potential threat.",
                    f"Monitor account {primary_user} closely for suspicious activity."
                ] if primary_domain and primary_device and primary_user else fallback_actions[:5]
            elif not isinstance(immediate_actions[0], str):
                # Convert dictionary actions to narrative strings if needed
                immediate_actions = convert_fallbacks_to_narrative_format(immediate_actions)
            
            future_steps = analysis_data.get("future_steps", [])
            if not future_steps:
                # Create narrative string fallbacks if none from LLM
                future_steps = [
                    f"Review DNS logs (Event ID 22) across endpoints for queries related to {primary_domain} or similar variations.",
                    f"Investigate process execution logs (Security ID 4688) on host {primary_device} around the time of the incident.",
                    f"Search EDR/Antivirus logs across the environment for alerts related to the identified indicators."
                ] if primary_domain and primary_device else fallback_steps[:5]
            elif not isinstance(future_steps[0], str):
                # Convert dictionary steps to narrative strings if needed
                future_steps = convert_fallbacks_to_narrative_format(future_steps)
            
            # Merge analysis_data with required fields potentially missing from LLM response
            merged_data = {
                "incident_id": str(incident_data.get('incident_number', 'N/A')),
                "executive_summary": analysis_data.get("executive_summary", "Security incident involving potentially suspicious network activity detected. Immediate actions required to contain potential threat by blocking indicators and isolating systems. Further investigation needed to determine full scope and impact."),
                "severity": analysis_data.get("severity", incident_data.get("severity", "Medium")),
                "incident_title": incident_data.get('title', 'N/A'),
                "severity_indicator": analysis_data.get("severity_indicator", incident_data.get("severity", "Medium")),
                "immediate_actions": immediate_actions,
                "future_steps": future_steps,
                "identified_techniques": analysis_data.get("identified_techniques", []),
                "metrics_panel": indicators.metrics_panel if hasattr(indicators, 'metrics_panel') else {
                     "incident_number": str(incident_data.get('incident_number', 'N/A')), # Also convert here
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

        except pydantic.ValidationError as e:
            print(f"LLM Error: JSON does not match Pydantic model:\n{e}")
            # Create a fallback analysis with generic but useful recommendations
            
            # Create string-style fallbacks
            string_fallback_actions = [
                f"Block domain {primary_domain} across firewall, proxy, and endpoint systems to prevent further malicious communication.",
                f"Isolate system {primary_device} from the network to contain any potential threat.",
                f"Monitor account {primary_user} closely for suspicious activity.",
                f"Capture volatile memory and disk image from involved systems for forensic analysis.",
                f"Escalate the incident to Level 2 SOC analysts for deeper investigation."
            ] if primary_domain and primary_device and primary_user else convert_fallbacks_to_narrative_format(fallback_actions[:5])
            
            string_fallback_steps = [
                f"Review DNS logs across endpoints for queries related to {primary_domain} or similar variations.",
                f"Investigate process execution logs on host {primary_device} around the time of the incident.",
                f"Search EDR/Antivirus logs across the environment for alerts related to the identified indicators.",
                f"Analyze proxy logs for connections to identified malicious domains to understand user interaction patterns.",
                f"Audit user activity logs to assess the behavior of potentially compromised users."
            ] if primary_domain and primary_device else convert_fallbacks_to_narrative_format(fallback_steps[:5])
            
            fallback_analysis = IncidentAnalysisOutput(
                incident_id=str(incident_data.get('incident_number', 'N/A')),
                severity="Medium",
                incident_title=incident_data.get('title', 'N/A'),
                executive_summary="Security incident requiring investigation. Generated fallback recommendations with evidence due to LLM response error.",
                severity_indicator="Medium",
                immediate_actions=string_fallback_actions,
                future_steps=string_fallback_steps,
                identified_techniques=[]
            )
            return fallback_analysis

    except Exception as e:
        print(f"Error during LLM call or processing: {str(e)}")
        traceback.print_exc()
        # Create string-style fallbacks
        string_fallback_actions = [
            f"Block domain {primary_domain} across firewall, proxy, and endpoint systems to prevent further malicious communication.",
            f"Isolate system {primary_device} from the network to contain any potential threat.",
            f"Monitor account {primary_user} closely for suspicious activity.",
            f"Capture volatile memory and disk image from involved systems for forensic analysis.",
            f"Escalate the incident to Level 2 SOC analysts for deeper investigation."
        ] if primary_domain and primary_device and primary_user else convert_fallbacks_to_narrative_format(fallback_actions[:5])
        
        string_fallback_steps = [
            f"Review DNS logs across endpoints for queries related to {primary_domain} or similar variations.",
            f"Investigate process execution logs on host {primary_device} around the time of the incident.",
            f"Search EDR/Antivirus logs across the environment for alerts related to the identified indicators.",
            f"Analyze proxy logs for connections to identified malicious domains to understand user interaction patterns.",
            f"Audit user activity logs to assess the behavior of potentially compromised users."
        ] if primary_domain and primary_device else convert_fallbacks_to_narrative_format(fallback_steps[:5])
        
        # Create fallback recommendations
        fallback_analysis = IncidentAnalysisOutput(
            incident_id=str(incident_data.get('incident_number', 'N/A')),
            severity="Medium",
            incident_title=incident_data.get('title', 'N/A'),
            executive_summary=f"Error in report generation. Using fallback evidence-based recommendations.",
            severity_indicator="Medium",
            immediate_actions=string_fallback_actions,
            future_steps=string_fallback_steps,
            identified_techniques=[]
        )
        return fallback_analysis

def build_enhanced_rag_context(incident_data: Dict[str, Any], logs: List[Dict[str, Any]], 
                      indicators: SecurityIndicators, alerts: List[Dict[str, Any]],
                      vt_results: Optional[Dict[str, Any]] = None) -> Dict[str, Dict[str, Any]]:
    """
    Build an enhanced, entity-centric RAG context from all available incident data sources.
    Returns a dictionary organized by entity type for more targeted retrieval.
    """
    # Initialize entity-centric context structure
    enhanced_context = {
        "domains": defaultdict(dict),
        "ips": defaultdict(dict),
        "hosts": defaultdict(dict),
        "users": defaultdict(dict),
        "incident": {},
        "alerts": [],
        "patterns": {}
    }
    
    # 1. Process incident details
    for k, v in incident_data.items():
        if v and str(v).lower() not in ["nan", "none", "unknown"]:
            enhanced_context["incident"][k] = v
    
    # 2. Process domain information including VirusTotal results
    for domain in indicators.domains:
        enhanced_context["domains"][domain]["mentions"] = 0
        enhanced_context["domains"][domain]["connected_hosts"] = set()
        enhanced_context["domains"][domain]["connected_users"] = set()
        enhanced_context["domains"][domain]["seen_at"] = []
        
        # Add VirusTotal context if available
        if vt_results and domain in vt_results:
            enhanced_context["domains"][domain]["virustotal"] = {
                "malicious_score": vt_results[domain].get("malicious_score", "Unknown"),
                "categories": vt_results[domain].get("categories", []),
                "detection_names": vt_results[domain].get("detection_names", []),
                "first_seen": vt_results[domain].get("first_seen", "Unknown"),
                "last_seen": vt_results[domain].get("last_seen", "Unknown")
            }
    
    # 3. Process IP information
    for ip in indicators.ips + indicators.internal_ips + indicators.external_ips:
        if ip not in enhanced_context["ips"]:
            enhanced_context["ips"][ip]["mentions"] = 0
            enhanced_context["ips"][ip]["connected_hosts"] = set()
            enhanced_context["ips"][ip]["connected_users"] = set()
            enhanced_context["ips"][ip]["connected_domains"] = set()
            enhanced_context["ips"][ip]["seen_at"] = []
            enhanced_context["ips"][ip]["activities"] = set()
    
    # 4. Process log data to enrich entities with relationship information
    for log in logs:
        # Extract entities from log
        timestamp = log.get("TimeGenerated", log.get("timestamp", "Unknown"))
        device = log.get("Computer", log.get("DeviceName", log.get("HostName", "Unknown")))
        user = log.get("User", log.get("UserName", log.get("UserId", "Unknown")))
        source_ip = log.get("SourceIP", log.get("src_ip", log.get("source_ip", None)))
        dest_ip = log.get("DestinationIP", log.get("dst_ip", log.get("destination_ip", None)))
        domain = log.get("Domain", log.get("DomainName", log.get("domain", None)))
        action = log.get("Action", log.get("DeviceAction", "Unknown"))
        
        # Update host information
        if device and device != "Unknown":
            if device not in enhanced_context["hosts"]:
                enhanced_context["hosts"][device] = {
                    "mentions": 0,
                    "users": set(),
                    "ips": set(),
                    "domains": set(),
                    "activities": set(),
                    "timestamps": []
                }
            enhanced_context["hosts"][device]["mentions"] += 1
            if timestamp and timestamp != "Unknown":
                enhanced_context["hosts"][device]["timestamps"].append(timestamp)
            if user and user != "Unknown":
                enhanced_context["hosts"][device]["users"].add(user)
            if source_ip:
                enhanced_context["hosts"][device]["ips"].add(source_ip)
            if dest_ip:
                enhanced_context["hosts"][device]["ips"].add(dest_ip)
            if domain:
                enhanced_context["hosts"][device]["domains"].add(domain)
            if action and action != "Unknown":
                enhanced_context["hosts"][device]["activities"].add(action)
        
        # Update user information
        if user and user != "Unknown":
            if user not in enhanced_context["users"]:
                enhanced_context["users"][user] = {
                    "mentions": 0,
                    "hosts": set(),
                    "ips": set(),
                    "domains": set(),
                    "activities": set(),
                    "timestamps": []
                }
            enhanced_context["users"][user]["mentions"] += 1
            if timestamp and timestamp != "Unknown":
                enhanced_context["users"][user]["timestamps"].append(timestamp)
            if device and device != "Unknown":
                enhanced_context["users"][user]["hosts"].add(device)
            if source_ip:
                enhanced_context["users"][user]["ips"].add(source_ip)
            if dest_ip:
                enhanced_context["users"][user]["ips"].add(dest_ip)
            if domain:
                enhanced_context["users"][user]["domains"].add(domain)
            if action and action != "Unknown":
                enhanced_context["users"][user]["activities"].add(action)
        
        # Update domain information
        if domain and domain in enhanced_context["domains"]:
            enhanced_context["domains"][domain]["mentions"] += 1
            if device and device != "Unknown":
                enhanced_context["domains"][domain]["connected_hosts"].add(device)
            if user and user != "Unknown":
                enhanced_context["domains"][domain]["connected_users"].add(user)
            if timestamp and timestamp != "Unknown":
                enhanced_context["domains"][domain]["seen_at"].append(timestamp)
        
        # --- START ENHANCED DOMAIN-USER LINKING ---
        # Check other relevant fields for domain presence and link user if found in the same log
        potential_domain_fields = [
            log.get("DestinationHostName"),
            log.get("RequestURL")
            # Add other fields if necessary, e.g., fields containing URLs
        ]

        # Normalize target domains for comparison
        target_domains_lower = {d.lower() for d in indicators.domains}

        for field_value in potential_domain_fields:
            if field_value and isinstance(field_value, str):
                # Basic normalization: lower case, handle potential URLs
                normalized_field_value = field_value.lower()
                # Attempt to extract domain from URL if it looks like one
                if "://" in normalized_field_value:
                    try:
                        from urllib.parse import urlparse
                        parsed_url = urlparse(field_value) # Use original case for parsing potentially
                        normalized_domain_from_url = parsed_url.netloc.lower()
                        if normalized_domain_from_url in target_domains_lower:
                             # Found a target domain in URL, check for user in this log
                             if user and user != "Unknown":
                                 # Add user to the set for the matched target domain
                                 target_domain_original_case = next((d for d in indicators.domains if d.lower() == normalized_domain_from_url), normalized_domain_from_url)
                                 enhanced_context["domains"][target_domain_original_case]["connected_users"].add(user)
                                 # print(f"DEBUG: Linked user '{user}' to domain '{target_domain_original_case}' via URL field") # Optional debug
                    except Exception:
                         pass # Ignore parsing errors
                else:
                     # Treat as hostname/domain
                     normalized_domain = normalized_field_value.strip().rstrip('.')
                     if normalized_domain in target_domains_lower:
                          # Found a target domain in hostname field, check for user in this log
                          if user and user != "Unknown":
                              # Add user to the set for the matched target domain
                              target_domain_original_case = next((d for d in indicators.domains if d.lower() == normalized_domain), normalized_domain)
                              enhanced_context["domains"][target_domain_original_case]["connected_users"].add(user)
                              # print(f"DEBUG: Linked user '{user}' to domain '{target_domain_original_case}' via HostName/Domain field") # Optional debug
        # --- END ENHANCED DOMAIN-USER LINKING ---

        # Update IP information
        for ip in [source_ip, dest_ip]:
            if ip and ip in enhanced_context["ips"]:
                enhanced_context["ips"][ip]["mentions"] += 1
                if device and device != "Unknown":
                    enhanced_context["ips"][ip]["connected_hosts"].add(device)
                if user and user != "Unknown":
                    enhanced_context["ips"][ip]["connected_users"].add(user)
                if domain:
                    enhanced_context["ips"][ip]["connected_domains"].add(domain)
                if timestamp and timestamp != "Unknown":
                    enhanced_context["ips"][ip]["seen_at"].append(timestamp)
                if action and action != "Unknown":
                    enhanced_context["ips"][ip]["activities"].add(action)
    
    # 5. Process alert information
    if alerts:
        for alert in alerts:
            alert_summary = {
                "title": alert.get("alertDisplayName", "Unknown Alert"),
                "severity": alert.get("severity", "Unknown"),
                "description": alert.get("description", "No description"),
                "entities": [],
                "timestamp": alert.get("timeGenerated", "Unknown")
            }
            
            # Extract entities from alert
            for entity in alert.get("entities", []):
                entity_type = entity.get("type", "unknown")
                entity_name = entity.get("displayName", "Unknown")
                
                # Add to alert summary
                alert_summary["entities"].append({
                    "type": entity_type,
                    "name": entity_name
                })
                
                # Update entity information based on alert
                if entity_type == "host" and entity_name in enhanced_context["hosts"]:
                    if "alerts" not in enhanced_context["hosts"][entity_name]:
                        enhanced_context["hosts"][entity_name]["alerts"] = []
                    enhanced_context["hosts"][entity_name]["alerts"].append(alert_summary["title"])
                
                elif entity_type == "account" and entity_name in enhanced_context["users"]:
                    if "alerts" not in enhanced_context["users"][entity_name]:
                        enhanced_context["users"][entity_name]["alerts"] = []
                    enhanced_context["users"][entity_name]["alerts"].append(alert_summary["title"])
                
                elif entity_type == "ip" and entity_name in enhanced_context["ips"]:
                    if "alerts" not in enhanced_context["ips"][entity_name]:
                        enhanced_context["ips"][entity_name]["alerts"] = []
                    enhanced_context["ips"][entity_name]["alerts"].append(alert_summary["title"])
                
                elif entity_type == "dns" and entity_name in enhanced_context["domains"]:
                    if "alerts" not in enhanced_context["domains"][entity_name]:
                        enhanced_context["domains"][entity_name]["alerts"] = []
                    enhanced_context["domains"][entity_name]["alerts"].append(alert_summary["title"])
            
            enhanced_context["alerts"].append(alert_summary)
    
    # 6. Add log patterns
    if logs:
        log_patterns = analyze_log_patterns(logs)
        enhanced_context["patterns"] = log_patterns
    
    # 7. Convert sets to lists for JSON serialization
    for domain, data in enhanced_context["domains"].items():
        if "connected_hosts" in data:
            data["connected_hosts"] = list(data["connected_hosts"])
        if "connected_users" in data:
            data["connected_users"] = list(data["connected_users"])
    
    for ip, data in enhanced_context["ips"].items():
        if "connected_hosts" in data:
            data["connected_hosts"] = list(data["connected_hosts"])
        if "connected_users" in data:
            data["connected_users"] = list(data["connected_users"])
        if "connected_domains" in data:
            data["connected_domains"] = list(data["connected_domains"])
        if "activities" in data:
            data["activities"] = list(data["activities"])
    
    for host, data in enhanced_context["hosts"].items():
        if "users" in data:
            data["users"] = list(data["users"])
        if "ips" in data:
            data["ips"] = list(data["ips"])
        if "domains" in data:
            data["domains"] = list(data["domains"])
        if "activities" in data:
            data["activities"] = list(data["activities"])
    
    for user, data in enhanced_context["users"].items():
        if "hosts" in data:
            data["hosts"] = list(data["hosts"])
        if "ips" in data:
            data["ips"] = list(data["ips"])
        if "domains" in data:
            data["domains"] = list(data["domains"])
        if "activities" in data:
            data["activities"] = list(data["activities"])
    
    return enhanced_context

def format_enhanced_rag_context(enhanced_context: Dict[str, Dict[str, Any]]) -> str:
    """
    Format the enhanced RAG context into a structured text format for LLM consumption.
    Organizes information by entity with rich relationship context.
    """
    formatted_sections = []
    
    # 1. Incident Overview
    if enhanced_context.get("incident"):
        incident_section = ["=== INCIDENT OVERVIEW ==="]
        for k, v in enhanced_context["incident"].items():
            incident_section.append(f"{k}: {v}")
        formatted_sections.append("\n".join(incident_section))
    
    # 2. Domain Context with Evidence
    if enhanced_context.get("domains"):
        domains_section = ["=== DOMAIN CONTEXT ==="]
        for domain, data in enhanced_context["domains"].items():
            domain_info = [f"Domain: {domain}"]
            
            # Add VirusTotal information if available
            if "virustotal" in data:
                vt = data["virustotal"]
                domain_info.append(f"Malicious Score: {vt.get('malicious_score', 'Unknown')}")
                if vt.get("categories"):
                    domain_info.append(f"Categories: {', '.join(vt.get('categories', []))}")
                if vt.get("detection_names"):
                    domain_info.append(f"Detection Names: {', '.join(vt.get('detection_names', []))}")
                if vt.get("first_seen") != "Unknown":
                    domain_info.append(f"First Seen: {vt.get('first_seen', 'Unknown')}")
            
            # Add relationship information
            if data.get("mentions", 0) > 0:
                domain_info.append(f"Mentions in Logs: {data.get('mentions', 0)}")
            if data.get("connected_hosts"):
                domain_info.append(f"Connected Systems: {', '.join(data.get('connected_hosts', []))}")
            if data.get("connected_users"):
                domain_info.append(f"Users Who Accessed: {', '.join(data.get('connected_users', []))}")
            if data.get("alerts"):
                domain_info.append(f"Associated Alerts: {', '.join(data.get('alerts', []))}")
            
            domains_section.append("\n".join(domain_info) + "\n")
        
        formatted_sections.append("\n".join(domains_section))
    
    # 3. Host/System Context
    if enhanced_context.get("hosts"):
        hosts_section = ["=== SYSTEM CONTEXT ==="]
        for host, data in enhanced_context["hosts"].items():
            if data.get("mentions", 0) > 0:  # Only include hosts with relevant data
                host_info = [f"System: {host}"]
                host_info.append(f"Mentions in Logs: {data.get('mentions', 0)}")
                
                if data.get("users"):
                    host_info.append(f"Associated Users: {', '.join(data.get('users', []))}")
                if data.get("domains"):
                    host_info.append(f"Contacted Domains: {', '.join(data.get('domains', []))}")
                if data.get("ips"):
                    host_info.append(f"Connected IPs: {', '.join(data.get('ips', []))}")
                if data.get("activities"):
                    host_info.append(f"Observed Activities: {', '.join(data.get('activities', []))}")
                if data.get("alerts"):
                    host_info.append(f"Associated Alerts: {', '.join(data.get('alerts', []))}")
                
                # Add timeline info if available
                if data.get("timestamps") and len(data["timestamps"]) >= 2:
                    earliest = min(data["timestamps"])
                    latest = max(data["timestamps"])
                    host_info.append(f"Activity Timeframe: {earliest} to {latest}")
                
                hosts_section.append("\n".join(host_info) + "\n")
        
        formatted_sections.append("\n".join(hosts_section))
    
    # 4. User Context
    if enhanced_context.get("users"):
        users_section = ["=== USER CONTEXT ==="]
        for user, data in enhanced_context["users"].items():
            if data.get("mentions", 0) > 0:  # Only include users with relevant data
                user_info = [f"User: {user}"]
                user_info.append(f"Mentions in Logs: {data.get('mentions', 0)}")
                
                if data.get("hosts"):
                    user_info.append(f"Systems Accessed: {', '.join(data.get('hosts', []))}")
                if data.get("domains"):
                    user_info.append(f"Domains Accessed: {', '.join(data.get('domains', []))}")
                if data.get("ips"):
                    user_info.append(f"Connected IPs: {', '.join(data.get('ips', []))}")
                if data.get("activities"):
                    user_info.append(f"Observed Activities: {', '.join(data.get('activities', []))}")
                if data.get("alerts"):
                    user_info.append(f"Associated Alerts: {', '.join(data.get('alerts', []))}")
                
                # Add timeline info if available
                if data.get("timestamps") and len(data["timestamps"]) >= 2:
                    earliest = min(data["timestamps"])
                    latest = max(data["timestamps"])
                    user_info.append(f"Activity Timeframe: {earliest} to {latest}")
                
                users_section.append("\n".join(user_info) + "\n")
        
        formatted_sections.append("\n".join(users_section))
    
    # 5. IP Address Context
    if enhanced_context.get("ips"):
        ips_section = ["=== IP ADDRESS CONTEXT ==="]
        for ip, data in enhanced_context["ips"].items():
            if data.get("mentions", 0) > 0:  # Only include IPs with relevant data
                ip_info = [f"IP Address: {ip}"]
                ip_info.append(f"Mentions in Logs: {data.get('mentions', 0)}")
                
                if data.get("connected_hosts"):
                    ip_info.append(f"Connected Systems: {', '.join(data.get('connected_hosts', []))}")
                if data.get("connected_users"):
                    ip_info.append(f"Associated Users: {', '.join(data.get('connected_users', []))}")
                if data.get("connected_domains"):
                    ip_info.append(f"Related Domains: {', '.join(data.get('connected_domains', []))}")
                if data.get("activities"):
                    ip_info.append(f"Observed Activities: {', '.join(data.get('activities', []))}")
                if data.get("alerts"):
                    ip_info.append(f"Associated Alerts: {', '.join(data.get('alerts', []))}")
                
                # Add timeline info if available
                if data.get("seen_at") and len(data["seen_at"]) >= 2:
                    earliest = min(data["seen_at"])
                    latest = max(data["seen_at"])
                    ip_info.append(f"Activity Timeframe: {earliest} to {latest}")
                
                ips_section.append("\n".join(ip_info) + "\n")
        
        formatted_sections.append("\n".join(ips_section))
    
    # 6. Alert Summary
    if enhanced_context.get("alerts"):
        alerts_section = ["=== ALERT SUMMARY ==="]
        for alert in enhanced_context["alerts"]:
            alert_info = [
                f"Alert: {alert.get('title', 'Unknown')}",
                f"Severity: {alert.get('severity', 'Unknown')}",
                f"Time: {alert.get('timestamp', 'Unknown')}",
                f"Description: {alert.get('description', 'No description')}"
            ]
            
            if alert.get("entities"):
                entities = [f"{e.get('type', 'unknown')}: {e.get('name', 'Unknown')}" for e in alert.get("entities", [])]
                alert_info.append(f"Entities: {', '.join(entities)}")
            
            alerts_section.append("\n".join(alert_info) + "\n")
        
        formatted_sections.append("\n".join(alerts_section))
    
    # 7. Log Patterns
    if enhanced_context.get("patterns"):
        patterns_section = ["=== LOG PATTERNS ==="]
        for pattern_type, pattern_data in enhanced_context["patterns"].items():
            patterns_section.append(f"Pattern Type: {pattern_type}")
            for entity, stats in pattern_data.items():
                if isinstance(stats, dict):
                    patterns_section.append(f"  {entity}: {stats.get('count', 0)} occurrences")
                    if stats.get("details"):
                        for detail in stats.get("details", [])[:3]:  # Limit to top 3 details
                            patterns_section.append(f"    - {detail}")
        
        formatted_sections.append("\n".join(patterns_section))
    
    return "\n\n".join(formatted_sections)

def convert_fallbacks_to_narrative_format(actions):
    """Convert dictionary-style fallbacks to narrative string format"""
    if not actions:
        return []
        
    # If already string format, return as is
    if isinstance(actions[0], str):
        return actions
        
    # Convert from dict format to string format
    result = []
    for action in actions:
        if isinstance(action, dict):
            # Get description
            description = action.get('description', '')
            if not description:
                continue
                
            # Add to result
            result.append(description)
    
    return result

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