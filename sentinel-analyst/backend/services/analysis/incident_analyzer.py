import pandas as pd
import os
import json
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
import re
import traceback

class IncidentAnalyzer:
    """
    Class for analyzing security incidents based on the provided script logic.
    """
    
    def __init__(self):
        """Initialize the incident analyzer"""
        pass
    
    def extract_ips_and_domains(self, text: str) -> Tuple[List[str], List[str]]:
        """Extract IPs and domains from text (from script)"""
        # Pattern for IPv4 addresses
        ip_pattern = r'\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b'
        
        # Simple pattern for domains
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}\\b'
        
        # Find all matches
        ips = re.findall(ip_pattern, str(text))
        domains = re.findall(domain_pattern, str(text))
        
        # Filter out IPs that might be timestamps or not valid
        valid_ips = [ip for ip in ips if all(0 <= int(octet) <= 255 for octet in ip.split('.'))]
        
        return valid_ips, domains

    def create_incident_timeline(self, incident_data: pd.DataFrame) -> Dict[str, Any]:
        """Create a comprehensive timeline of incident changes (from script)"""
        
        # Sort data by timestamp to ensure chronological order
        incident_data = incident_data.sort_values('LastModifiedTime')
        
        # Get first and last rows
        first_row = incident_data.iloc[0]
        last_row = incident_data.iloc[-1]
        
        # Extract initial and current states
        incident_number = str(first_row['IncidentNumber'])
        first_detected = str(first_row['LastModifiedTime']) # Ensure string conversion if needed
        first_status = first_row['Status']
        first_severity = first_row['Severity']
        current_status = last_row['Status']
        current_severity = last_row['Severity']
        
        # Create a detailed timeline of key changes
        key_milestones = []
        previous_row = None
        
        for idx, row in incident_data.iterrows():
            milestone = {
                'timestamp': str(row['LastModifiedTime']), # Ensure string conversion
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
                        # Attempt to parse owner if it looks like JSON, otherwise use as string
                        new_owner_name = 'Unknown'
                        previous_owner_name = 'Unassigned'
                        
                        if isinstance(row['Owner'], str) and row['Owner'].startswith('{'):
                            new_owner = json.loads(row['Owner'])
                            new_owner_name = new_owner.get('assignedTo', 'Unknown')
                        elif isinstance(row['Owner'], dict): # Handle if already dict
                            new_owner_name = row['Owner'].get('assignedTo', 'Unknown')
                        else:
                            new_owner_name = str(row['Owner']) if pd.notna(row['Owner']) else 'Unknown'

                        if isinstance(previous_row['Owner'], str) and previous_row['Owner'].startswith('{'):
                            previous_owner = json.loads(previous_row['Owner'])
                            previous_owner_name = previous_owner.get('assignedTo', 'Unassigned')
                        elif isinstance(previous_row['Owner'], dict):
                            previous_owner_name = previous_row['Owner'].get('assignedTo', 'Unassigned')
                        else:
                           previous_owner_name = str(previous_row['Owner']) if pd.notna(previous_row['Owner']) else 'Unassigned'

                        # Only add change if owner actually changed
                        if new_owner_name != previous_owner_name:
                            milestone['changes'].append({
                                'field': 'Owner',
                                'from': previous_owner_name,
                                'to': new_owner_name
                            })
                    except Exception: # Fallback to string representation on error
                         if str(row['Owner']) != str(previous_row['Owner']):
                             milestone['changes'].append({
                                'field': 'Owner',
                                'from': str(previous_row['Owner']) if pd.notna(previous_row['Owner']) else 'Unassigned',
                                'to': str(row['Owner']) if pd.notna(row['Owner']) else 'Unknown'
                             })
                
                # Check for new comments
                # Comparing raw comment fields might be more robust than checking lengths
                if 'Comments' in row and 'Comments' in previous_row and str(row['Comments']) != str(previous_row['Comments']):
                     try:
                         current_comments_data = json.loads(row['Comments']) if isinstance(row['Comments'], str) and row['Comments'].startswith('[') else []
                         previous_comments_data = json.loads(previous_row['Comments']) if isinstance(previous_row['Comments'], str) and previous_row['Comments'].startswith('[') else []

                         if len(current_comments_data) > len(previous_comments_data):
                             new_comment_count = len(current_comments_data) - len(previous_comments_data)
                             last_new_comment = current_comments_data[-1].get('message', '') if current_comments_data else ''
                             summary_text = (last_new_comment[:100] + '...') if len(last_new_comment) > 100 else last_new_comment
                             milestone['changes'].append({
                                 'field': 'Comments',
                                 'action': f'Added {new_comment_count} new comment(s)',
                                 'summary': summary_text
                             })
                         elif str(row['Comments']) != str(previous_row['Comments']): # Handle cases where comments change but length doesn't (e.g., edited)
                              milestone['changes'].append({
                                 'field': 'Comments',
                                 'action': 'Comments field updated',
                                 'summary': str(row['Comments'])[:100] + ('...' if len(str(row['Comments'])) > 100 else '')
                             })
                     except Exception: # Fallback if JSON parsing fails or structure is unexpected
                         if str(row['Comments']) != str(previous_row['Comments']):
                            milestone['changes'].append({
                                'field': 'Comments',
                                'action': 'Comments field updated',
                                'summary': str(row['Comments'])[:100] + ('...' if len(str(row['Comments'])) > 100 else '')
                            })

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
                 # Check if the field is Owner and it changed *from* Unassigned
                if change.get('field') == 'Owner' and change.get('from', '').lower() == 'unassigned' and change.get('to', '').lower() != 'unassigned':
                    assignment_milestone = milestone
                    summary += f" Assigned to {change.get('to')} at {milestone['timestamp']}."
                    break
            if assignment_milestone:
                break
        
        # Check if incident was resolved
        if current_status in ['Closed', 'Resolved']:
            summary += f" Resolved on {str(last_row['LastModifiedTime'])}."
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

    def format_incident_timeline(self, timeline: Dict[str, Any]) -> str:
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

    def analyze_incident_context(self, incident_data: pd.DataFrame) -> Dict[str, Any]:
        """Analyze incident data and provide context (adapted from script)"""
        
        # Sort data by timestamp to ensure chronological order
        incident_data = incident_data.sort_values('LastModifiedTime')
        
        # Get first and last rows
        first_row = incident_data.iloc[0]
        last_row = incident_data.iloc[-1]
        
        # Extract key information for analysis
        incident_number = str(first_row['IncidentNumber'])
        tenant_id = first_row['TenantId']
        
        # Extract comments
        comments_text = []
        raw_comments_field = last_row.get('Comments', None)
        if pd.notna(raw_comments_field):
            try:
                # Attempt to parse as JSON list of comment objects
                comments_data = json.loads(raw_comments_field) if isinstance(raw_comments_field, str) else raw_comments_field
                if isinstance(comments_data, list):
                    for comment in comments_data:
                        if isinstance(comment, dict) and 'message' in comment:
                            comments_text.append(comment['message'])
                elif isinstance(comments_data, str): # Handle case where it's just a string after parsing
                     comments_text.append(comments_data)
            except Exception: # If JSON parsing fails, treat the whole field as a single comment string
                comments_text = [str(raw_comments_field)]
        
        # Extract entities from comments
        all_ips = []
        all_domains = []
        for comment in comments_text:
            ips, domains = self.extract_ips_and_domains(comment)
            all_ips.extend(ips)
            all_domains.extend(domains)
        
        # Remove duplicates
        all_ips = sorted(list(set(all_ips)))
        all_domains = sorted(list(set(all_domains)))
        
        # Determine incident type based on comments (from script logic)
        incident_type = "Unknown"
        comments_lower = ' '.join(comments_text).lower() # Join for easier searching
        if 'dns with ti domain' in comments_lower:
            incident_type = "Malicious Domain Communication"
        elif 'malware' in comments_lower:
             incident_type = "Malware Detection"
        elif 'phishing' in comments_lower:
             incident_type = "Phishing Attempt"
        # Add more rules here if needed

        # Generate analysis dictionary based on type
        analysis_content = {}
        if incident_type == "Malicious Domain Communication":
            # Extract affected user if possible (example placeholder)
            affected_user = "Unknown"
            user_match = re.search(r'User:\s*([\w\.@-]+)', ' '.join(comments_text), re.IGNORECASE)
            if user_match:
                affected_user = user_match.group(1)
            
            # Structure the analysis from the script
            analysis_content = {
                'summary': "This security incident involves a DNS request to a malicious domain flagged by threat intelligence.",
                'description': f"A domain ({all_domains[0] if all_domains else 'unknown'}) was identified as potentially malicious. The connection attempt may have originated from an internal system (User: {affected_user}). Blocking status needs verification.",
                'threat_details': {
                    'type': "Malicious Domain Communication / Potential C2 Channel",
                    'vector': "DNS Request to Malicious Domain",
                    'affected_systems': f"Workstation/User: {affected_user} (IPs: {', '.join(all_ips) if all_ips else 'unknown'})",
                    'potential_impact': "Data exfiltration, command & control activity, additional malware download"
                },
                'significance': [
                    "Represents a potential early stage of an attack.",
                    "Activity suggests possible endpoint compromise or user interaction with malicious content.",
                    "Verification of blocking controls is essential."
                ],
                'recommended_actions': [
                    "Verify the connection attempt was blocked by security controls (proxy, firewall).",
                    "Isolate the affected system if compromise is suspected.",
                    "Interview the user ({affected_user}) if applicable.",
                    "Ensure the domain ({all_domains[0] if all_domains else 'unknown'}) is blocked network-wide.",
                    "Perform endpoint analysis (scan, memory forensics) on the affected system.",
                    "Search logs for similar connection attempts from other systems."
                ]
            }
        else:
             # Generic analysis for other types (adapted from script)
             owner_info = str(last_row['Owner']) # Keep owner info simple for generic case
             try:
                 if isinstance(last_row['Owner'], str) and last_row['Owner'].startswith('{'):
                     owner_data = json.loads(last_row['Owner'])
                     owner_info = owner_data.get('assignedTo', owner_info)
             except:
                 pass # Keep original string if parsing fails

             analysis_content = {
                 'summary': f"Security incident #{incident_number} ({incident_type}) is currently {last_row['Status']} with {last_row['Severity']} severity.",
                 'description': f"The incident was created on {str(first_row['LastModifiedTime'])} and has {len(incident_data)} recorded updates.",
                 'key_points': [
                     f"Originally detected with {first_row['Severity']} severity and {first_row['Status']} status.",
                     f"Current status is {last_row['Status']} / {last_row['Severity']}.",
                     f"Assigned Owner: {owner_info}",
                     f"Entities found: {len(all_ips)} IPs, {len(all_domains)} Domains."
                 ],
                 'recommended_actions': [
                     f"Review incident details and comments for '{incident_type}' indicators.",
                     "Verify affected systems or users based on logs and entities.",
                     "Correlate IP/domain entities with threat intelligence feeds.",
                     "Follow standard operating procedures for '{incident_type}' incidents.",
                     "Update incident with findings and actions taken."
                 ]
             }

        # Assemble the final result dictionary for this incident's context
        result = {
            'incident_number': incident_number,
            'tenant_id': tenant_id,
            'incident_type': incident_type,
            'current_status': last_row['Status'],
            'current_severity': last_row['Severity'],
            'initial_status': first_row['Status'],
            'initial_severity': first_row['Severity'],
            'first_detected': str(first_row['LastModifiedTime']),
            'last_updated': str(last_row['LastModifiedTime']),
            'update_count': len(incident_data),
            'entities': {
                'ips': all_ips,
                'domains': all_domains
            },
            'comments': comments_text, # Include extracted comments
            'analysis': analysis_content # Structured analysis dictionary
        }
        
        return result

    def analyze_incident(self, excel_path: str, incident_id: Optional[str] = None, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Main method to analyze security incidents (core logic from script).
        
        Args:
            excel_path: Path to the Excel file containing incident data.
            incident_id: Optional specific incident number (string) to filter for.
            tenant_id: Optional tenant ID (string) to filter incidents.
            
        Returns:
            Dict containing analysis results or an error structure.
        """
        try:
            # Read the Excel file
            if not os.path.exists(excel_path):
                 return {"error": f"Data file not found at path: {excel_path}", "traceback": ""}
            
            df = pd.read_excel(excel_path)
            
            # Convert IncidentNumber to string to ensure consistent matching
            if 'IncidentNumber' in df.columns:
                 df['IncidentNumber'] = df['IncidentNumber'].astype(str)
            else:
                 return {"error": "Excel file missing required 'IncidentNumber' column.", "traceback": ""}

            # Ensure required columns exist
            required_cols = ['IncidentNumber', 'TenantId', 'Status', 'Severity', 'LastModifiedTime']
            missing_cols = [col for col in required_cols if col not in df.columns]
            if missing_cols:
                 return {"error": f"Excel file missing required columns: {', '.join(missing_cols)}", "traceback": ""}
                 
            # Convert LastModifiedTime to datetime objects, handling potential errors
            try:
                 df['LastModifiedTime'] = pd.to_datetime(df['LastModifiedTime'])
            except Exception as time_e:
                 # Attempt to infer format if direct conversion fails
                 try:
                     df['LastModifiedTime'] = pd.to_datetime(df['LastModifiedTime'], infer_datetime_format=True)
                 except Exception as infer_e:
                      return {"error": f"Could not parse 'LastModifiedTime' column. Ensure it's a valid date/time format. Error: {infer_e}", "traceback": traceback.format_exc()}


            # Filter by tenant_id if provided
            if tenant_id:
                if 'TenantId' not in df.columns:
                     return {"error": "Cannot filter by TenantId: column not found in data.", "traceback": ""}
                # Ensure consistent type for comparison if TenantId might be numeric
                df['TenantId'] = df['TenantId'].astype(str)
                df = df[df['TenantId'] == str(tenant_id)]
            
            # Filter by incident_id if provided
            if incident_id:
                 # Ensure incident_id is treated as string for comparison
                df = df[df['IncidentNumber'] == str(incident_id)]
            
            if df.empty:
                # Provide a more specific message based on filters
                if incident_id and tenant_id:
                    error_msg = f"No incident found matching IncidentNumber '{incident_id}' and TenantId '{tenant_id}'"
                elif incident_id:
                     error_msg = f"No incident found matching IncidentNumber '{incident_id}'"
                elif tenant_id:
                     error_msg = f"No incidents found matching TenantId '{tenant_id}'"
                else:
                     error_msg = "No incidents found in the provided data file"
                return {"error": error_msg, "results": []} # Return empty results list too
            
            # Sort by LastModifiedTime (essential for timeline and context)
            df = df.sort_values('LastModifiedTime')
            
            # Group by IncidentNumber
            incident_groups = df.groupby('IncidentNumber')
            
            results = []
            
            # Analyze each incident group
            for incident_number, group in incident_groups:
                try:
                    # Create timeline analysis
                    timeline = self.create_incident_timeline(group.copy()) # Pass copy to avoid modifying original group
                    
                    # Get contextual analysis
                    context_analysis = self.analyze_incident_context(group.copy()) # Pass copy here too
                    
                    # Create complete result for this incident
                    incident_result = {
                        'incident_id': incident_number, # Use the key from groupby
                        'timeline': timeline,
                        'analysis': context_analysis
                    }
                    results.append(incident_result)
                except Exception as group_e:
                     # Log error for specific incident but continue with others
                     print(f"Error analyzing group for incident {incident_number}: {str(group_e)}") # Log to server console
                     results.append({
                         'incident_id': incident_number,
                         'error': f"Failed to analyze incident {incident_number}: {str(group_e)}",
                         'timeline': None,
                         'analysis': None
                     })

            # Return final structured results
            return {
                "total_incidents_processed": len(incident_groups), # How many unique incidents were processed
                "total_incidents_returned": len([r for r in results if 'error' not in r]), # How many successfully analyzed
                "results": results # List containing analysis or error for each incident group
            }
                
        except FileNotFoundError:
             return {"error": f"Data file not found at path: {excel_path}", "traceback": traceback.format_exc()}
        except pd.errors.EmptyDataError:
             return {"error": "The provided Excel file is empty.", "traceback": traceback.format_exc()}
        except Exception as e:
            # Catch-all for other unexpected errors during loading or initial processing
            return {
                "error": f"An unexpected error occurred during analysis: {str(e)}",
                "traceback": traceback.format_exc() # Include traceback for debugging
            }

# Factory function to get an instance of the analyzer
def get_analyzer():
    return IncidentAnalyzer() 