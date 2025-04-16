import pandas as pd
import os
import json
from datetime import datetime
from typing import List, Dict, Any, Optional, Union
import re
import traceback
import ollama  # Using ollama client directly
from pydantic import BaseModel, Field

# Ollama configuration
OLLAMA_API_BASE = "http://localhost:11434"
OLLAMA_MODEL = "llama3.2:latest"


class IncidentAnalysisOutput(BaseModel):
    # Allow threat_details to be a dictionary or fallback to string
    threat_details: Union[str, Dict[str, Any]] = Field(description="Detailed description of the identified threat, including type and vector, or a structured dictionary.")
    significance: str = Field(description="Assessment of the incident's importance and potential impact.")
    recommended_actions: List[str] = Field(description="List of concrete steps to take for remediation and prevention.")
    summary: str = Field(description="A brief overall summary of the incident analysis.")


def extract_ips_and_domains(text: str) -> tuple:
    """Extract IPs and domains from text"""
    # Pattern for IPv4 addresses
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    
    # Simple pattern for domains
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    
    # Find all matches
    ips = re.findall(ip_pattern, str(text))
    domains = re.findall(domain_pattern, str(text))
    
    # Filter out IPs that might be timestamps or not valid
    valid_ips = [ip for ip in ips if all(0 <= int(octet) <= 255 for octet in ip.split('.'))]
    
    return valid_ips, domains

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
    
    # Create a summary of the timeline
    summary = f"Incident #{incident_number} was first detected on {first_detected} with {first_severity} severity and {first_status} status."
    
    # Check if incident was assigned
    assignment_milestone = None
    for milestone in key_milestones:
        for change in milestone['changes']:
            if change.get('field') == 'Owner' and change.get('from') == 'Unassigned':
                assignment_milestone = milestone
                summary += f" Assigned to {change.get('to')} at {milestone['timestamp']}."
                break
        if assignment_milestone:
            break
    
    # Check if incident was resolved
    if current_status in ['Closed', 'Resolved']:
        summary += f" Resolved on {last_row['LastModifiedTime']}."
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
        'summary': summary
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
    
    return formatted

def analyze_incident_context(incident_data: pd.DataFrame) -> str:
    """Analyze incident data and provide context using an LLM"""

    # Sort data by timestamp to ensure chronological order
    incident_data = incident_data.sort_values('LastModifiedTime')

    # Get first and last rows
    first_row = incident_data.iloc[0]
    last_row = incident_data.iloc[-1]

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

    # Extract entities from comments
    all_ips = []
    all_domains = []
    comments_text = "\n".join(comments)
    if comments_text:
        ips, domains = extract_ips_and_domains(comments_text)
        all_ips.extend(ips)
        all_domains.extend(domains)

    # Remove duplicates
    all_ips = list(set(all_ips))
    all_domains = list(set(all_domains))

    # Prepare information for the LLM
    incident_info = (
        f"Incident Number: {incident_number}\n"
        f"Tenant ID: {tenant_id}\n"
        f"Current Status: {last_row['Status']} (Initial: {first_row['Status']})\n"
        f"Current Severity: {last_row['Severity']} (Initial: {first_row['Severity']})\n"
        f"First Detected: {first_row['LastModifiedTime']}\n"
        f"Last Updated: {last_row['LastModifiedTime']}\n"
        f"Total Updates: {len(incident_data)}\n"
        f"Detected IPs: {', '.join(all_ips) if all_ips else 'None'}\n"
        f"Detected Domains: {', '.join(all_domains) if all_domains else 'None'}\n"
        f"Comments:\n{comments_text if comments_text else 'No comments available.'}"
    )

    # Construct the prompt for the LLM
    prompt = (
        f"You are a cybersecurity analyst reviewing security incidents. Provide detailed analysis of the incident data.\n\n"
        f"Analyze the following security incident data and provide a structured analysis. "
        f"Focus on the threat details, significance, and recommended actions based ONLY on the provided information.\n\n"
        f"Incident Data:\n"
        f"--------------\n"
        f"{incident_info}\n"
        f"--------------\n\n"
        f"Provide the analysis as a JSON object with keys: 'threat_details', 'significance', 'recommended_actions' (as a list of strings), and 'summary'."
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
        except json.JSONDecodeError as e:
            print(f"Failed to decode JSON response even with format='json': {e}")
            print(f"Raw response content:\n{json_str}")
            raise ValueError("Ollama response was not valid JSON despite format='json' instruction")

        # Validate against our Pydantic model
        validated_result = IncidentAnalysisOutput(**analysis_result)
        print(f"Analysis generated successfully for Incident #{incident_number}.")

        # Format threat_details based on its type (string or dict)
        threat_details_formatted = ""
        if isinstance(validated_result.threat_details, dict):
            # Simple formatting for a dict - convert key-value pairs to string
            threat_details_formatted = "\n".join([f"  - {k}: {v}" for k, v in validated_result.threat_details.items()])
        else:
            # Assume it's a string if not a dict
            threat_details_formatted = validated_result.threat_details

        analysis_content = (
            f"THREAT DETAILS:\n* {threat_details_formatted}\n\n"
            f"SIGNIFICANCE:\n* {validated_result.significance}\n\n"
            f"RECOMMENDED ACTIONS:\n" +
            "\n".join([f"* {action}" for action in validated_result.recommended_actions]) + "\n\n"
            f"SUMMARY:\n{validated_result.summary}"
        )

    except Exception as e:
        print(f"\nError generating analysis with LLM for incident {incident_number}: {e}")
        traceback.print_exc() # Print full traceback for debugging LLM errors
        analysis_content = f"Error during AI analysis generation: {e}\nUsing generic analysis based on available data.\n\n"
        # Fallback to a simpler analysis if LLM fails
        analysis_content += (
             f"Based on the available data, this security incident is currently {last_row['Status']} with "
             f"{last_row['Severity']} severity. It was first detected on {first_row['LastModifiedTime']} "
             f"and last updated on {last_row['LastModifiedTime']}.\n\n"
             f"Detected IPs: {', '.join(all_ips) if all_ips else 'None'}\n"
             f"Detected Domains: {', '.join(all_domains) if all_domains else 'None'}\n\n"
             f"Further investigation is needed."
        )

    # Generate the final analysis string including the base summary and the AI part
    analysis = (
        f"INCIDENT SUMMARY:\n"
        f"----------------\n"
        f"Incident #{incident_number} detected from TenantID {tenant_id}\n"
        f"Current Status: {last_row['Status']} (initially {first_row['Status']})\n"
        f"Current Severity: {last_row['Severity']} (initially {first_row['Severity']})\n"
        f"First Detected: {first_row['LastModifiedTime']}\n"
        f"Last Updated: {last_row['LastModifiedTime']}\n"
        f"Number of Updates: {len(incident_data)}\n\n"
        f"DETECTED ENTITIES:\n"
        f"-----------------\n"
        f"IPs: {', '.join(all_ips) if all_ips else 'None identified'}\n"
        f"Domains: {', '.join(all_domains) if all_domains else 'None identified'}\n\n"
        f"INCIDENT ANALYSIS (Generated by AI):\n"
        f"----------------------------------\n"
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
                
                # Get contextual analysis
                context_analysis = analyze_incident_context(group)
                print("\nSOC ANALYST INSIGHTS (Generated by AI):") # Updated title
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
                        f.write("SOC ANALYST INSIGHTS (Generated by AI):\n") # Updated title in file
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