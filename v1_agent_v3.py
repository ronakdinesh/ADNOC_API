# Standard library imports
from typing import Union, List, Optional, Dict
from datetime import datetime
import traceback
import logging
import re
import os
import json

# Add debug code at the start
import os
print("Current working directory:", os.getcwd())

# Constants - Define base directory to make paths more manageable
BASE_DIR = r'C:\Users\kpmgpov\Desktop\ADNOC LLM AI POV CODE\ADNOC_LLM11FEB\ADNOC_LLM11FEB'
TRANSFORMED_DATA_FILE = os.path.join(BASE_DIR, r'final_data_v3\transformed_joint_data.xlsx')
SECURITY_LOGS_FILE = os.path.join(BASE_DIR, r'new_data\03 CommonSecurityLog.xlsx')
OUTPUT_DIR = os.path.join(BASE_DIR, 'processedoutput')

# Debug print statements
print(f"Checking if files exist:")
print(f"TRANSFORMED_DATA_FILE exists: {os.path.exists(TRANSFORMED_DATA_FILE)}")
print(f"SECURITY_LOGS_FILE exists: {os.path.exists(SECURITY_LOGS_FILE)}")
print(f"Full path to TRANSFORMED_DATA_FILE: {os.path.abspath(TRANSFORMED_DATA_FILE)}")
print(f"Full path to SECURITY_LOGS_FILE: {os.path.abspath(SECURITY_LOGS_FILE)}")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Third party imports
import pandas as pd
from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIModel
import sys
sys.path.append(os.path.join(BASE_DIR, 'Code'))
from virustotal import check_domain_reputation

# Set empty API key since Ollama doesn't require one
os.environ["OPENAI_API_KEY"] = "dummy_key"

# Initialize Ollama model
ollama_model = OpenAIModel(
    model_name='llama3.2:latest',
    base_url='http://localhost:11434/v1'
)
agent = Agent(ollama_model)

def load_transformed_data() -> pd.DataFrame:
    """Load and return the transformed joint data from Excel file"""
    try:
        # Add debug logging
        logger.info(f"Attempting to load data from: {TRANSFORMED_DATA_FILE}")
        if not os.path.exists(TRANSFORMED_DATA_FILE):
            logger.error(f"File not found at path: {TRANSFORMED_DATA_FILE}")
            raise FileNotFoundError(f"File not found: {TRANSFORMED_DATA_FILE}")
            
        transformed_data = pd.read_excel(TRANSFORMED_DATA_FILE)
        logger.info(f"Successfully loaded data with {len(transformed_data)} rows")
        return transformed_data
    except Exception as e:
        logger.error(f"Error loading transformed data: {str(e)}")
        raise

def get_brief_mitre_description(tactic: str, techniques: list) -> str:
    """Get a brief MITRE ATT&CK description for the incident data section."""
    try:
        # Get MITRE info from AI agent
        mitre_info = get_mitre_description(tactic, techniques)
        
        tactic_desc = mitre_info['tactic']['description']
        tech_desc = [f"{t}: {mitre_info['techniques'][t]['description']}" for t in techniques]
        
        return f"MITRE Info:\n- Tactic ({tactic}): {tactic_desc}\n- Techniques: {', '.join(tech_desc)}"
    except Exception as e:
        logger.error(f"Error getting brief MITRE description: {str(e)}")
        # Make one final attempt with a very simple prompt
        try:
            simple_prompt = f"Explain the MITRE ATT&CK tactic {tactic} and techniques {techniques} in 2-3 sentences."
            simple_result = agent.run_sync(simple_prompt)
            return f"MITRE Info:\n{simple_result.data}"
        except:
            return f"MITRE Info:\n- Tactic: {tactic}\n- Techniques: {', '.join(techniques)}"

def get_incident_info(incident_number: str) -> str:
    """Get and display all information for a specific incident number."""
    try:
        data = load_transformed_data()
        data['IncidentNumber'] = data['IncidentNumber'].astype(str)
        incident_number = str(incident_number)
        
        incident_row = data[data['IncidentNumber'] == incident_number]
        
        if incident_row.empty:
            return f"Incident number {incident_number} not found. Please check the number and try again."
            
        # Convert to dict and remove verbose fields
        result_dict = incident_row.iloc[0].to_dict()
        fields_to_remove = ['Description', 'ExtendedProperties']
        for field in fields_to_remove:
            if field in result_dict:
                del result_dict[field]
        
        # Add brief MITRE description
        tactics = result_dict.get('Tactics')
        techniques = eval(result_dict.get('Techniques', '[]')) if isinstance(result_dict.get('Techniques'), str) else result_dict.get('Techniques', [])
        result_dict['MITRE_Description'] = get_brief_mitre_description(tactics, techniques)
            
        # Save the incident data to CSV
        save_incident_to_csv(result_dict)
        
        return result_dict

    except Exception as e:
        logger.error(f"Error getting incident info: {str(e)}")
        raise

def get_security_logs_by_domain(domain: str) -> pd.DataFrame:
    """Return security logs that match the given domain in RequestURL."""
    try:
        security_logs = pd.read_excel(SECURITY_LOGS_FILE)
        # Filter columns as per agent_v2
        columns = [
            'DeviceVendor', 'DeviceEventClassID', 'Activity', 'DeviceAction',
            'ApplicationProtocol', 'DestinationPort', 'DestinationIP', 'DeviceName',
            'Protocol', 'RequestURL', 'SourceIP', 'SourceUserName', 'DeviceEventCategory',
            'FlexString2', 'OpCo'
        ]
        filtered_logs = security_logs[columns].drop_duplicates()
        
        # Filter rows where domain appears in RequestURL
        if domain:
            domain_logs = filtered_logs[filtered_logs['RequestURL'].str.contains(str(domain), na=False)]
            return domain_logs
        return pd.DataFrame()
        
    except Exception as e:
        logger.error(f"Error getting security logs for domain: {str(e)}")
        raise

def get_mitre_description(tactic: str, techniques: list) -> dict:
    """Get MITRE ATT&CK descriptions using AI agent."""
    try:
        # Create techniques JSON structure first
        technique_json = ',\n'.join([
            f'        "{t}": {{\n'
            f'            "name": "{t}",\n'
            f'            "description": "detailed description here"\n'
            f'        }}'
            for t in techniques
        ])
        
        mitre_prompt = (
            f"You are a MITRE ATT&CK expert. Provide descriptions in valid JSON format for:\n\n"
            f"Tactic: {tactic}\n"
            f"Techniques: {techniques}\n\n"
            "Return ONLY a valid JSON object with this exact structure:\n"
            "{\n"
            '    "tactic": {\n'
            f'        "name": "{tactic}",\n'
            '        "description": "detailed description here"\n'
            "    },\n"
            '    "techniques": {\n'
            f"{technique_json}\n"
            "    }\n"
            "}"
        )
        
        result = agent.run_sync(mitre_prompt)
        
        try:
            # Clean the response to ensure valid JSON
            json_str = result.data.strip()
            # Remove any markdown code block markers
            if '```' in json_str:
                json_str = json_str.split('```')[1] if 'json' in json_str else json_str.split('```')[1]
                json_str = json_str.strip('`')
            json_str = json_str.strip()
            
            mitre_info = json.loads(json_str)
            
            # Validate the response has required fields
            if not isinstance(mitre_info, dict):
                raise ValueError("Response is not a dictionary")
            if 'tactic' not in mitre_info or 'techniques' not in mitre_info:
                raise ValueError("Missing required fields")
                
            return mitre_info
            
        except Exception as e:
            logger.error(f"Failed to parse MITRE information: {str(e)}")
            # Create a basic but valid response
            return {
                "tactic": {
                    "name": tactic,
                    "description": f"The {tactic} tactic represents methods used by attackers to achieve their objectives."
                },
                "techniques": {
                    t: {
                        "name": t,
                        "description": f"Technique {t} is commonly used in {tactic} operations."
                    } for t in techniques
                }
            }
            
    except Exception as e:
        logger.error(f"Error getting MITRE descriptions: {str(e)}")
        # Return basic structure instead of raising
        return {
            "tactic": {
                "name": tactic,
                "description": f"The {tactic} tactic represents methods used by attackers to achieve their objectives."
            },
            "techniques": {
                t: {
                    "name": t,
                    "description": f"Technique {t} is commonly used in {tactic} operations."
                } for t in techniques
            }
        }

def analyze_security_data(incident_info: dict, security_logs: pd.DataFrame) -> str:
    """Generate AI recommendations based on incident info, security logs, and VT data."""
    try:
        # Create a summary of security log patterns
        blocked_count = len(security_logs[security_logs['DeviceAction'] == 'Blocked'])
        allowed_count = len(security_logs[security_logs['DeviceAction'] == 'Allowed'])
        unique_sources = security_logs['SourceIP'].nunique()
        unique_users = security_logs['SourceUserName'].dropna().nunique()
        
        # Get affected systems and users
        affected_systems = security_logs['DeviceName'].dropna().unique().tolist()
        affected_users = security_logs['SourceUserName'].dropna().unique().tolist()
        
        # Get VirusTotal reputation data
        domain = incident_info.get('domain')
        vt_data = check_domain_reputation(domain) if domain else None
        
        # Create VT analysis section with clearer risk indicators
        if vt_data:
            risk_level = "high risk" if vt_data.get('malicious_votes', 0) > 5 else \
                        "medium risk" if vt_data.get('suspicious_votes', 0) > 0 else \
                        "low risk"
            vt_analysis = (
                f"Domain Risk Level: {risk_level}\n"
                f"- Reputation Score: {vt_data.get('reputation')}\n"
                f"- Malicious Votes: {vt_data.get('malicious_votes')}\n"
                f"- Suspicious Votes: {vt_data.get('suspicious_votes')}\n"
                f"- Clean Votes: {vt_data.get('clean_votes')}\n"
                f"- Detection Engines: {vt_data.get('detection_engines')}"
            )
        else:
            vt_analysis = "- No VirusTotal data available - treat as unknown risk"

        # Get tactics and techniques
        tactics = incident_info.get('Tactics')
        techniques = incident_info.get('Techniques')
        if isinstance(techniques, str):
            techniques = eval(techniques)
        
        # Get specific device and user details
        device_patterns = analyze_log_patterns(security_logs)
        top_devices = device_patterns['device_name']['data']
        top_users = device_patterns['source_username']['data']
        
        # Format the specific details
        affected_devices = [f"{device} ({count} events)" 
                          for device, count in top_devices.items()]
        affected_accounts = [f"{user} ({count} events)" 
                           for user, count in top_users.items()]
        
        # Get log patterns
        patterns = analyze_log_patterns(security_logs)
        patterns_text = "\n\nSecurity Log Patterns:\n\n"
        for category, info in patterns.items():
            patterns_text += f"{info['label']}:\n"
            for item, count in info['data'].items():
                patterns_text += f"- {item}: {count} occurrences\n"
            patterns_text += "\n"
        
        analysis_prompt = (
            f"Analyze this security incident and provide detailed recommendations:\n\n"
            f"Incident Information:\n"
            f"- Alert Name: {incident_info.get('AlertName')}\n"
            f"- Severity: {incident_info.get('AlertSeverity')}\n"
            f"- Status: {incident_info.get('Status')}\n"
            f"- Domain: {domain}\n"
            f"{incident_info.get('MITRE_Description')}\n\n"
            f"Security Log Summary:\n"
            f"- Total Events: {len(security_logs)}\n"
            f"- Blocked Actions: {blocked_count}\n"
            f"- Allowed Actions: {allowed_count}\n"
            f"- Unique Source IPs: {unique_sources}\n"
            f"- Unique Users Affected: {unique_users}\n"
            f"- Affected Systems: {', '.join(affected_systems)}\n"
            f"- Affected Users: {', '.join(affected_users)}\n"
            f"- Device Vendors: {', '.join(security_logs['DeviceVendor'].unique())}\n"
            f"- Event Categories: {', '.join(security_logs['DeviceEventCategory'].dropna().unique())}\n\n"
            f"VirusTotal Domain Analysis:\n"
            f"{vt_analysis}\n\n"
            "Based on the VirusTotal analysis and security logs, provide appropriate recommendations.\n"
            "If the domain has low malicious/suspicious votes, consider monitoring instead of blocking.\n"
            "If the domain has high malicious votes, recommend immediate blocking.\n\n"
            "Format your response exactly as follows:\n\n"
            "**Security Incident Analysis and Recommendations**\n\n"
            "**Risk Assessment:**\n"
            "Provide a detailed risk assessment including severity and potential impact.\n\n"
            "**Key Observations:**\n"
            "• List key statistics and patterns from security logs\n"
            "• Include number of events, affected users, and systems\n"
            "• Note any suspicious patterns or anomalies\n\n"
            "**Domain Analysis:**\n"
            "• Include detailed VirusTotal reputation analysis\n"
            "• Explain why the domain is considered malicious or benign\n"
            "• Note any discrepancies between VirusTotal data and observed behavior\n\n"
            "**MITRE ATT&CK Analysis:**\n"
            "Explain the tactics and techniques observed.\n\n"
            "**AI Recommendations & Actions**\n\n"
            "A. Immediate Actions (First 1-2 hours):\n\n"
            "RECOMMENDED ACTION                                                                                                          ACTION\n\n"
            f"Block outgoing traffic to {domain}                                                                                        Apply\n\n"
            f"Isolate affected systems ({', '.join(affected_devices[:2])})                                                             Apply\n\n"
            f"Disable user accounts ({', '.join(affected_accounts[:2])})                                                               Apply\n\n"
            f"Collect system memory for analysis                                                                                        Apply\n\n"
            
            "B. Future Steps (Next 24 hours):\n\n"
            "Investigation Steps\n\n"
            "• Review DNS logs for similar queries\n"
            "• Analyze system memory for malware\n"
            "• Check for lateral movement attempts\n"
            "• Review user activity logs\n\n"
            
            f"{patterns_text}"  # Add patterns at the end
        )
        
        result = agent.run_sync(analysis_prompt)
        
        # Ensure patterns are always included in output
        if "Security Log Patterns:" not in result.data:
            result.data += patterns_text
            
        # Save recommendations to CSV
        save_recommendations_to_csv(incident_info.get('SystemAlertId', ''), result.data)
        
        return result.data
        
    except Exception as e:
        logger.error(f"Error analyzing security data: {str(e)}")
        raise

def analyze_log_patterns(security_logs: pd.DataFrame) -> dict:
    """Analyze security logs for common patterns and statistics."""
    try:
        patterns = {}
        
        # DestinationIP analysis
        dest_ips = security_logs['DestinationIP'].dropna()
        if not dest_ips.empty:
            patterns['destination_ip'] = {
                'data': dest_ips.value_counts().head(3).to_dict(),
                'label': 'Most Common Destination IPs'
            }
        
        # DestinationPort analysis
        dest_ports = security_logs['DestinationPort'].dropna()
        if not dest_ports.empty:
            port_counts = dest_ports.value_counts().head(3)
            if not port_counts.empty:
                patterns['destination_port'] = {
                    'data': port_counts.to_dict(),
                    'label': 'Most Common Destination Ports'
                }
        
        # SourceUserName analysis
        usernames = security_logs['SourceUserName'].dropna()
        if not usernames.empty:
            patterns['source_username'] = {
                'data': usernames.value_counts().head(3).to_dict(),
                'label': 'Most Active Users'
            }
        
        # DeviceName analysis
        devices = security_logs['DeviceName'].dropna()
        if not devices.empty:
            device_counts = devices.value_counts().head(3)
            if not device_counts.empty:
                patterns['device_name'] = {
                    'data': device_counts.to_dict(),
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
        
    except Exception as e:
        logger.error(f"Error analyzing log patterns: {str(e)}")
        raise

def save_incident_to_csv(incident_data: dict) -> None:
    """Save incident data to CSV with the specified schema."""
    try:
        # Extract entities from the JSON string if present
        entities = []
        if isinstance(incident_data.get('Entities'), str):
            try:
                entities = json.loads(incident_data['Entities'])
            except:
                entities = eval(incident_data['Entities'])
        
        # Get MITRE info
        mitre_desc = incident_data.get('MITRE_Description', '')
        techniques = incident_data.get('Techniques', '[]')
        if isinstance(techniques, str):
            techniques = eval(techniques)
            
        # Get source IP first
        source_ip = next((entity['Address'] for entity in entities if entity['Type'] == 'ip'), '')
        
        # Create a dictionary with the exact schema mapping
        mapped_data = {
            'incident_id': incident_data.get('SystemAlertId', ''),  # 71a8f1bd-e65f-43d5-ac4a-7af4b4ba852b
            'alert_name': incident_data.get('AlertName', ''),  # [Custom]-[TI]-DNS with TI Domain Correlation
            'alert_severity': incident_data.get('AlertSeverity', ''),  # High
            'source_ip': source_ip,
            'source_username': '',  # Will be populated from security logs
            'source_hostname': '',  # Will be populated from security logs
            'destination_ip': next((entity['Address'] for entity in entities 
                                  if entity['Type'] == 'ip' and entity['Address'] != source_ip), ''),
            'destination_port': '',  # Will be populated from security logs
            'destination_domain': next((entity['DomainName'] for entity in entities if entity['Type'] == 'dns'), ''),  # ecomicrolab.com
            'destination_reputation': '',  # Will be populated from VT data
            'mitre_tactic_name': incident_data.get('Tactics', ''),  # CommandAndControl
            'mitre_tactic_description': mitre_desc if isinstance(mitre_desc, str) else '',
            'mitre_technique_id': techniques[0] if techniques else '',  # T1071
            'mitre_technique_name': '',  # Will be populated from MITRE data
            'mitre_technique_description': ''  # Will be populated from MITRE data
        }
        
        # Create DataFrame and save to CSV
        df = pd.DataFrame([mapped_data])
        output_path = os.path.join(OUTPUT_DIR, 'incident_sample_1.csv')
        
        # Create directory if it doesn't exist
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        
        # Save to CSV
        df.to_csv(output_path, index=False)
        logger.info(f"Incident data saved to {output_path}")
        
    except Exception as e:
        logger.error(f"Error saving incident data to CSV: {str(e)}")
        raise

def save_recommendations_to_csv(incident_id: str, analysis_text: str) -> None:
    """Save AI recommendations to CSV following the recommendations schema."""
    try:
        immediate_actions = []
        investigation_steps = []
        
        # Parse the analysis text to extract actions
        sections = analysis_text.split('\n')
        current_section = None
        
        for line in sections:
            line = line.strip()
            if "A. Immediate Actions" in line:
                current_section = "immediate"
            elif "B. Future Steps" in line:
                current_section = "future"
            elif line.startswith('- ') or line.startswith('• '):
                if current_section == "immediate" and "RECOMMENDED ACTION" in sections[sections.index(line)-1]:
                    immediate_actions.append(line.lstrip('- ').lstrip('• '))
                elif current_section == "future" and "Investigation Steps" in sections[sections.index(line)-1]:
                    investigation_steps.append(line.lstrip('- ').lstrip('• '))
        
        # Create recommendation data
        recommendation_data = {
            'incident_id': incident_id,
            'action_timeframe': 'First 1-2 hours',
            'action_title': 'Initial Response',
            'action_details': '|'.join(immediate_actions) if immediate_actions else 'Block outgoing traffic|Isolate affected system|Disable user account|Collect system memory for analysis',
            'action_status': '|'.join(['pending'] * (len(immediate_actions) or 4)),
            'investigation_timeframe': 'Next 24 hours',
            'investigation_title': 'Investigation Steps',
            'investigation_details': '|'.join(investigation_steps) if investigation_steps else 'Review DNS logs for similar queries|Analyze system memory for malware|Check for lateral movement attempts|Review user activity logs',
            'Action': 'Action Required',
            'recom': 'Remediate Alert'
        }
        
        # Create DataFrame and save to CSV
        df = pd.DataFrame([recommendation_data])
        output_path = os.path.join(OUTPUT_DIR, 'recommendation_sample_1.csv')
        
        # Create directory if it doesn't exist
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        
        # Save to CSV
        df.to_csv(output_path, index=False)
        logger.info(f"Recommendations saved to {output_path}")
        
    except Exception as e:
        logger.error(f"Error saving recommendations to CSV: {str(e)}")
        raise

if __name__ == "__main__":
    print("Security Incident Data Viewer")
    print("Enter an incident number or type 'quit' to exit")
    
    while True:
        try:
            user_input = input("\nEnter incident number: ")
            if user_input.lower() == 'quit':
                break
                
            # Get incident info
            result = get_incident_info(user_input)
            print("\nIncident Data:")
            for key, value in result.items():
                print(f"{key}: {value}")
            
            # Get and analyze security logs if domain exists
            if 'domain' in result:
                domain = result['domain']
                print(f"\nRelated Security Logs for domain: {domain}")
                security_logs = get_security_logs_by_domain(domain)
                
                # Add pattern analysis
                print("\nSecurity Log Patterns:")
                patterns = analyze_log_patterns(security_logs)
                for category, info in patterns.items():
                    print(f"\n{info['label']}:")
                    for item, count in info['data'].items():
                        print(f"- {item}: {count} occurrences")
                
                if not security_logs.empty:
                    print("\nMatching Security Log Entries:")
                    print(security_logs.to_string())
                    
                    print("\nAI Analysis and Recommendations:")
                    analysis = analyze_security_data(result, security_logs)
                    print(analysis)
                else:
                    print("No matching security logs found")
            
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error: {str(e)}")