#!/usr/bin/env python3
"""
SOC AI Agent - Security Incident Analysis and Report Generation
This script uses local LLMs through Context7 to analyze security incidents and generate structured SOC analyst reports.
"""

import os
import sys
import json
import argparse
import re
from typing import Dict, List, Any, Optional

# Check if running in Jupyter notebook
try:
    get_ipython  # type: ignore
    IN_JUPYTER = True
except NameError:
    IN_JUPYTER = False

# Initialize logger
import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("SOC-AI-Agent")

# Load required packages for API calls
try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    logger.error("Required package 'requests' not found. Please install with 'pip install requests'")
    sys.exit(1)

# ---------------------------------------------------
# Config and environment setup
# ---------------------------------------------------

# LLM API settings - modify as needed for your local setup
LLAMA_API_BASE = os.environ.get("LLAMA_API_BASE", "http://localhost:11434/api")
OLLAMA_API_BASE = os.environ.get("OLLAMA_API_BASE", "http://localhost:11434")

# Ollama model to use
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:latest")

# ---------------------------------------------------
# Data parsing functions
# ---------------------------------------------------

def extract_incident_details(text: str) -> Dict[str, Any]:
    """Extract incident details from the incident output text"""
    
    incident = {}
    
    # Extract incident number
    incident_number_match = re.search(r'SECURITY INCIDENT #(\d+)', text)
    if incident_number_match:
        incident["incident_number"] = incident_number_match.group(1)
    
    # Extract incident title
    title_match = re.search(r'Title\s+(.+?)$', text, re.MULTILINE)
    if title_match:
        incident["title"] = title_match.group(1).strip()
    
    # Extract severity
    severity_match = re.search(r'Severity\s+(.+?)$', text, re.MULTILINE)
    if severity_match:
        incident["severity"] = severity_match.group(1).strip()
    
    # Extract status
    status_match = re.search(r'Status\s+(.+?)$', text, re.MULTILINE)
    if status_match:
        incident["status"] = status_match.group(1).strip()
    
    return incident

def extract_domains(text: str) -> List[str]:
    """Extract domain names from the incident text"""
    domains = []
    
    # Look for domains in DomainName fields
    domain_matches = re.findall(r'DomainName":\s*"([^"]+)"', text)
    domains.extend(domain_matches)
    
    # Look for domains in VirusTotal section
    vt_domains = re.findall(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):\s*\w+\s*RISK', text)
    domains.extend(vt_domains)
    
    # Look for domains mentioned in log patterns
    log_domains = re.findall(r'Security Log Patterns for domain: ([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', text)
    domains.extend(log_domains)
    
    return list(set(domains))  # Remove duplicates

def extract_ips(text: str) -> Dict[str, List[str]]:
    """Extract IP addresses categorized as internal and external"""
    ips = {
        "internal": [],
        "external": []
    }
    
    # Extract IPs from Most Common Destination IPs section
    ip_section_match = re.search(r'Most Common Destination IPs:(.*?)Most Common', text, re.DOTALL)
    if ip_section_match:
        ip_lines = ip_section_match.group(1).split('\n')
        for line in ip_lines:
            ip_match = re.search(r'- ((?:\d{1,3}\.){3}\d{1,3}):', line)
            if ip_match:
                ip = ip_match.group(1)
                # Categorize as internal or external based on IP range
                if ip.startswith(('10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '192.168.')):
                    ips["internal"].append(ip)
                else:
                    ips["external"].append(ip)
    
    # Look for IP Address fields in Entities section
    address_matches = re.findall(r'Address":\s*"([^"]+)"', text)
    for ip in address_matches:
        if ip.startswith(('10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '192.168.')):
            ips["internal"].append(ip)
        else:
            ips["external"].append(ip)
    
    # Remove duplicates
    ips["internal"] = list(set(ips["internal"]))
    ips["external"] = list(set(ips["external"]))
    
    return ips

def extract_users(text: str) -> List[str]:
    """Extract user accounts from the incident text"""
    users = []
    
    # Look for user emails in Most Active Users section
    user_section_match = re.search(r'Most Active Users:(.*?)Most Common', text, re.DOTALL)
    if user_section_match:
        user_lines = user_section_match.group(1).split('\n')
        for line in user_lines:
            user_match = re.search(r'- ([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+):', line)
            if user_match:
                users.append(user_match.group(1).strip())
    
    return list(set(users))  # Remove duplicates

def extract_devices(text: str) -> List[str]:
    """Extract device names from the incident text"""
    devices = []
    
    # Look for device names in Most Common Device Names section
    device_section_match = re.search(r'Most Common Device Names:(.*?)(?:$|\n\n)', text, re.DOTALL)
    if device_section_match:
        device_lines = device_section_match.group(1).split('\n')
        for line in device_lines:
            device_match = re.search(r'- ([^:]+):', line)
            if device_match:
                devices.append(device_match.group(1).strip())
    
    return list(set(devices))  # Remove duplicates

def extract_techniques(text: str) -> List[str]:
    """Extract MITRE ATT&CK techniques from the incident text"""
    techniques = []
    
    # Look for techniques in the Techniques section
    techniques_match = re.search(r'Techniques: \["([^"]+)"\]', text)
    if techniques_match:
        techniques = techniques_match.group(1).split('","')
    
    return techniques

def analyze_incident(incident_text: str) -> Dict[str, Any]:
    """Analyze the incident text and extract all relevant information"""
    analysis = {}
    
    # Extract incident details
    analysis["incident"] = extract_incident_details(incident_text)
    
    # Extract domains
    analysis["domains"] = extract_domains(incident_text)
    
    # Extract IPs
    analysis["ips"] = extract_ips(incident_text)
    
    # Extract users
    analysis["users"] = extract_users(incident_text)
    
    # Extract devices
    analysis["devices"] = extract_devices(incident_text)
    
    # Extract techniques
    analysis["techniques"] = extract_techniques(incident_text)
    
    # Extract tactics
    tactics_match = re.search(r'Tactics: ([^\n]+)', incident_text)
    if tactics_match:
        analysis["tactics"] = tactics_match.group(1).strip()
    
    return analysis

# ---------------------------------------------------
# LLM interaction functions
# ---------------------------------------------------

def generate_soc_prompt(analysis: Dict[str, Any]) -> str:
    """Generate a prompt for the LLM to create a SOC analyst report"""
    
    prompt = [
        "You are an expert SOC analyst creating an actionable security incident response report.",
        "Based on the security incident data provided, generate a comprehensive analysis with immediate actions and future steps.",
        "",
        "## INCIDENT DETAILS:",
    ]
    
    # Add incident details
    incident = analysis.get("incident", {})
    prompt.append(f"Incident Number: {incident.get('incident_number', 'Unknown')}")
    prompt.append(f"Title: {incident.get('title', 'Unknown')}")
    prompt.append(f"Severity: {incident.get('severity', 'Unknown')}")
    prompt.append(f"Status: {incident.get('status', 'Unknown')}")
    
    # Add domains
    domains = analysis.get("domains", [])
    if domains:
        prompt.append("\n## DOMAINS:")
        for domain in domains:
            prompt.append(f"- {domain}")
    
    # Add IPs
    ips = analysis.get("ips", {})
    if ips.get("internal") or ips.get("external"):
        prompt.append("\n## IP ADDRESSES:")
        prompt.append("Internal IPs:")
        for ip in ips.get("internal", []):
            prompt.append(f"- {ip}")
        prompt.append("External IPs:")
        for ip in ips.get("external", []):
            prompt.append(f"- {ip}")
    
    # Add users
    users = analysis.get("users", [])
    if users:
        prompt.append("\n## USERS:")
        for user in users:
            prompt.append(f"- {user}")
    
    # Add devices
    devices = analysis.get("devices", [])
    if devices:
        prompt.append("\n## DEVICES:")
        for device in devices:
            prompt.append(f"- {device}")
    
    # Add MITRE ATT&CK details
    techniques = analysis.get("techniques", [])
    tactics = analysis.get("tactics", "Unknown")
    if techniques or tactics != "Unknown":
        prompt.append("\n## MITRE ATT&CK:")
        prompt.append(f"Tactics: {tactics}")
        prompt.append("Techniques:")
        for technique in techniques:
            prompt.append(f"- {technique}")
    
    # Add output requirements
    prompt.append("\n## OUTPUT REQUIREMENTS:")
    prompt.append("Generate a detailed SOC analyst report with the following sections:")
    
    prompt.append("\n1. IMMEDIATE ACTIONS (FIRST 1-2 HOURS):")
    prompt.append("Provide at least 5-7 specific, actionable steps that should be taken immediately")
    prompt.append("Include these types of actions:")
    prompt.append("- Blocking actions for malicious domains and IPs")
    prompt.append("- System isolation procedures for affected systems")
    prompt.append("- User account monitoring or restriction measures")
    prompt.append("- Evidence collection steps")
    prompt.append("- Communication and escalation procedures")
    prompt.append("Format as a bullet list with the exact heading '🛡️ Immediate Actions (First 1–2 hours)'")
    
    prompt.append("\n2. FUTURE STEPS (NEXT 24 HOURS):")
    prompt.append("Provide at least 5-7 detailed investigation steps to take in the next 24 hours")
    prompt.append("Include these types of steps:")
    prompt.append("- Specific log sources to analyze")
    prompt.append("- Correlation activities between different data sources")
    prompt.append("- Systems to investigate for signs of lateral movement")
    prompt.append("- Additional data collection needed")
    prompt.append("- Threat intelligence enrichment activities")
    prompt.append("Format as a bullet list with the exact heading 'Future Steps (Next 24 hours)'")
    
    prompt.append("\nImportant: Your response should contain only the formatted report, nothing else. Do not include introductions, explanations, or any text outside the requested sections. Be specific, practical, and action-oriented.")
    
    return "\n".join(prompt)

def get_report_from_llm(prompt: str) -> str:
    """Get the SOC analyst report from the local LLM"""
    logger.info(f"Making request to Ollama API using model: {OLLAMA_MODEL}")
    
    api_url = f"{OLLAMA_API_BASE}/chat"
    headers = {"Content-Type": "application/json"}
    data = {
        "model": OLLAMA_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False
    }
    
    try:
        response = requests.post(api_url, headers=headers, json=data)
        response.raise_for_status()
        result = response.json()
        return result['message']['content']
    except Exception as e:
        logger.error(f"Error communicating with Ollama API: {str(e)}")
        if 'response' in locals():
            logger.error(f"Response status code: {response.status_code}")
            logger.error(f"Response text: {response.text}")
        raise

# ---------------------------------------------------
# Main function
# ---------------------------------------------------

def main():
    """Main function to process security incident data and generate a SOC analyst report"""
    parser = argparse.ArgumentParser(description="SOC AI Agent - Generate SOC Analyst Reports from Security Incidents")
    parser.add_argument("input_file", help="Path to the security incident text file")
    parser.add_argument("--output", "-o", help="Output file path (default: stdout)")
    parser.add_argument("--model", "-m", default=OLLAMA_MODEL, help=f"Ollama model to use (default: {OLLAMA_MODEL})")
    args = parser.parse_args()
    
    # Set model from args
    global OLLAMA_MODEL
    OLLAMA_MODEL = args.model
    
    try:
        # Read the incident file
        logger.info(f"Reading incident data from: {args.input_file}")
        with open(args.input_file, 'r') as f:
            incident_text = f.read()
        
        # Analyze the incident
        logger.info("Analyzing incident data...")
        analysis = analyze_incident(incident_text)
        
        # Generate the prompt
        logger.info("Generating LLM prompt...")
        prompt = generate_soc_prompt(analysis)
        
        # Get the report from the LLM
        logger.info("Requesting SOC analyst report from LLM...")
        report = get_report_from_llm(prompt)
        
        # Output the report
        if args.output:
            logger.info(f"Writing report to: {args.output}")
            with open(args.output, 'w') as f:
                f.write(report)
        else:
            print("\n" + "=" * 80)
            print("SOC ANALYST REPORT")
            print("=" * 80 + "\n")
            print(report)
        
        logger.info("Report generation complete.")
        
    except FileNotFoundError:
        logger.error(f"Input file not found: {args.input_file}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 