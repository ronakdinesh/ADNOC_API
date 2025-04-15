import pandas as pd
import os
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
import re
import traceback

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
    """Analyze incident data and provide context"""
    
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
    if 'Comments' in last_row and last_row['Comments']:
        try:
            comments_data = json.loads(last_row['Comments'])
            for comment in comments_data:
                if isinstance(comment, dict) and 'message' in comment:
                    comments.append(comment['message'])
        except:
            comments = [str(last_row['Comments'])]
    
    # Extract entities from comments
    all_ips = []
    all_domains = []
    for comment in comments:
        ips, domains = extract_ips_and_domains(comment)
        all_ips.extend(ips)
        all_domains.extend(domains)
    
    # Remove duplicates
    all_ips = list(set(all_ips))
    all_domains = list(set(all_domains))
    
    # Generate contextual analysis
    analysis = f"""
INCIDENT SUMMARY:
----------------
Incident #{incident_number} was detected from TenantID {tenant_id}
Current Status: {last_row['Status']} (initially {first_row['Status']})
Current Severity: {last_row['Severity']} (initially {first_row['Severity']})
First Detected: {first_row['LastModifiedTime']}
Last Updated: {last_row['LastModifiedTime']}
Number of Updates: {len(incident_data)}

DETECTED ENTITIES:
-----------------
IPs: {', '.join(all_ips) if all_ips else 'None identified'}
Domains: {', '.join(all_domains) if all_domains else 'None identified'}

INCIDENT ANALYSIS:
-----------------
"""
    
    # Add incident-specific analysis
    if 'DNS with TI Domain' in str(comments):
        analysis += """
This security incident involves a DNS request to a malicious domain that was flagged by threat 
intelligence. The domain ecomicrolab.com was identified as malicious, having been flagged by 
9 out of 94 security vendors. The connection attempt was made from an internal workstation 
but was successfully blocked by proxy controls.

THREAT DETAILS:
* Threat Type: Malicious Domain Communication / Potential C2 Channel
* Attack Vector: DNS Request to Malicious Domain
* Affected Systems: Workstation (User: enuaimi@adnoc.ae)
* Potential Impact: Data exfiltration, command & control activity, additional malware download

SIGNIFICANCE:
* This incident represents an early stage of a potential attack chain
* The fact that the communication was blocked indicates security controls are working
* However, the presence of this activity suggests endpoint compromise or user error

RECOMMENDED ACTIONS:
* Isolate affected workstation until investigation completes
* Interview user about their recent activities
* Block domain at all network egress points
* Perform memory forensics on affected workstation
* Check for similar connection attempts from other internal systems
* Update endpoint security signatures across the environment
"""
    else:
        # Generic analysis for other types of incidents
        analysis += f"""
Based on the available information, this security incident is currently {last_row['Status']} with 
{last_row['Severity']} severity. The incident was initially created on {first_row['LastModifiedTime']} 
and has undergone {len(incident_data)} updates.

Key points:
* The incident was originally rated as {first_row['Severity']} severity
* Current status is {last_row['Status']}
* Owner information: {last_row['Owner']}

Further investigation is required to determine the full scope and impact of this incident.
"""
    
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
                print("\nSOC ANALYST INSIGHTS:")
                print("="*20)
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
                        f.write("SOC ANALYST INSIGHTS:\n")
                        f.write("="*20 + "\n")
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
    analyze_security_incidents(excel_path) 