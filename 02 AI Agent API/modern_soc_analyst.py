"""
Modern SOC Analyst System with Tool Calling and Context7 MCP Integration

This module implements a modern SOC analyst system using:
1. Latest Pydantic techniques (v2+)
2. Tool calling pattern for modular capabilities
3. Context7 MCP integration for security framework documentation
4. Local LLM support via Ollama with deepseek-r1:7b model
"""

import os
import json
import asyncio
import requests
from datetime import datetime
from typing import Dict, List, Optional, Any, Union, Literal, Annotated

# Modern Pydantic imports
from pydantic import (
    BaseModel, 
    Field, 
    field_validator, 
    model_validator,
    ConfigDict,
    TypeAdapter
)

# Tool calling framework
from functools import wraps
from inspect import signature, Parameter

# Context7 MCP integration
# In a real implementation, we'd import actual MCP functions
# from mcp_context7_integration import resolve_library_id, get_library_docs

# Ollama integration for local LLM support
class OllamaClient:
    """Client for interacting with Ollama API"""
    
    def __init__(self, model: str = "deepseek-r1:7b", host: str = "localhost", port: int = 11434):
        self.model = model
        self.base_url = f"http://{host}:{port}/api"
    
    async def generate(self, prompt: str, system_prompt: Optional[str] = None, 
                      temperature: float = 0.2, max_tokens: int = 4096) -> str:
        """Generate text using Ollama API"""
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
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: requests.post(url, json=payload)
            )
            response.raise_for_status()
            return response.json().get("response", "")
        except Exception as e:
            print(f"Error calling Ollama API: {e}")
            return f"Error: {e}"


# Modern Pydantic models using the latest techniques
class TechniqueDetails(BaseModel):
    """Details about a specific MITRE ATT&CK technique identified in the incident"""
    model_config = ConfigDict(extra='forbid')
    
    technique_id: str = Field(description="MITRE ATT&CK technique ID (e.g., T1078)")
    technique_name: str = Field(description="MITRE ATT&CK technique name")
    evidence: List[str] = Field(description="Evidence supporting this technique identification")
    confidence: Literal["Low", "Medium", "High"] = Field(description="Confidence level")
    
    @field_validator('technique_id')
    @classmethod
    def validate_technique_id(cls, v: str) -> str:
        """Validate MITRE ATT&CK technique ID format"""
        if not (v.startswith('T') and v[1:].isdigit()):
            raise ValueError(f"Invalid MITRE ATT&CK technique ID format: {v}")
        return v


class ActionRecommendation(BaseModel):
    """Detailed recommendation for immediate action based on incident analysis"""
    model_config = ConfigDict(frozen=False, extra='forbid')
    
    description: str = Field(description="Detailed description of the recommended action")
    evidence: List[str] = Field(description="Evidence supporting this recommendation")
    priority: Literal["Low", "Medium", "High", "Critical"] = Field(
        description="Priority level for this action"
    )
    specific_commands: Optional[List[str]] = Field(
        default=None, 
        description="Specific commands or steps to execute this action"
    )
    expected_outcome: str = Field(description="Expected outcome of performing this action")
    security_framework_alignment: Optional[str] = Field(
        default=None, 
        description="How this aligns with security frameworks (MITRE, NIST, etc.)"
    )


class InvestigationStep(BaseModel):
    """Detailed next step for further investigation of the incident"""
    model_config = ConfigDict(extra='forbid')
    
    description: str = Field(description="Detailed description of the investigation step")
    rationale: str = Field(description="Why this step is important based on current evidence")
    tools: List[str] = Field(description="Specific tools recommended for this investigation step")
    data_sources: List[str] = Field(description="Data sources to examine during this step")
    expected_findings: str = Field(description="What findings might result from this investigation")
    techniques_addressed: Optional[List[str]] = Field(
        default=None, 
        description="MITRE ATT&CK techniques this step helps investigate"
    )


class IncidentAnalysisOutput(BaseModel):
    """Comprehensive incident analysis output with structured recommendations"""
    model_config = ConfigDict(extra='allow')
    
    incident_id: str = Field(description="Incident identifier")
    severity: Literal["Low", "Medium", "High", "Critical"] = Field(
        description="Assessed severity of the incident"
    )
    incident_title: str = Field(description="Short, descriptive title for the incident")
    executive_summary: str = Field(description="Brief summary of the incident and key findings")
    identified_techniques: List[TechniqueDetails] = Field(
        description="MITRE ATT&CK techniques identified in the incident"
    )
    immediate_actions: List[ActionRecommendation] = Field(
        description="Prioritized list of immediate actions to take"
    )
    future_steps: List[InvestigationStep] = Field(
        description="Recommended next steps for investigation"
    )
    related_incidents: Optional[List[str]] = Field(
        default=None, 
        description="Related incident IDs that may be connected"
    )
    timeline: Optional[Dict[str, str]] = Field(
        default=None, 
        description="Timeline of key events in the incident"
    )


class SecurityIndicators(BaseModel):
    """Structured security indicators extracted from incident data"""
    model_config = ConfigDict(extra='forbid')
    
    ip_addresses: List[str] = Field(default_factory=list, description="IP addresses")
    domains: List[str] = Field(default_factory=list, description="Domain names")
    hashes: List[str] = Field(default_factory=list, description="File hashes")
    users: List[str] = Field(default_factory=list, description="User accounts")
    processes: List[str] = Field(default_factory=list, description="Process names")
    urls: List[str] = Field(default_factory=list, description="URLs")
    
    # Additional categorized fields
    internal_ips: List[str] = Field(default_factory=list, description="Internal IP addresses")
    external_ips: List[str] = Field(default_factory=list, description="External IP addresses")
    
    # Computed properties using modern Pydantic techniques
    @property
    def has_indicators(self) -> bool:
        """Check if any indicators exist"""
        return any([
            self.ip_addresses, self.domains, self.hashes, 
            self.users, self.processes, self.urls
        ])
    
    @property 
    def indicator_count(self) -> int:
        """Get total count of indicators"""
        return sum(len(x) for x in [
            self.ip_addresses, self.domains, self.hashes, 
            self.users, self.processes, self.urls
        ])
    
    @model_validator(mode='after')
    def categorize_ips(self) -> 'SecurityIndicators':
        """Categorize IPs into internal and external"""
        for ip in self.ip_addresses:
            if ip.startswith(('10.', '172.16.', '192.168.')):
                if ip not in self.internal_ips:
                    self.internal_ips.append(ip)
            else:
                if ip not in self.external_ips:
                    self.external_ips.append(ip)
        return self


# Tool calling framework
class ToolRegistry:
    """Registry for tool functions"""
    
    def __init__(self):
        self.tools = {}
    
    def register(self, name=None):
        """Decorator to register a tool function"""
        def decorator(func):
            tool_name = name or func.__name__
            
            @wraps(func)
            async def wrapper(*args, **kwargs):
                print(f"Calling tool: {tool_name}")
                result = await func(*args, **kwargs)
                print(f"Tool {tool_name} completed")
                return result
            
            # Store function signature for validation
            sig = signature(func)
            param_info = []
            
            for param_name, param in sig.parameters.items():
                if param.default is Parameter.empty and param.kind is not Parameter.VAR_POSITIONAL and param.kind is not Parameter.VAR_KEYWORD:
                    param_info.append({
                        "name": param_name,
                        "required": True,
                        "type": str(param.annotation).replace("typing.", "")
                    })
                else:
                    param_info.append({
                        "name": param_name,
                        "required": False,
                        "type": str(param.annotation).replace("typing.", ""),
                        "default": "None" if param.default is None else str(param.default)
                    })
            
            self.tools[tool_name] = {
                "function": wrapper,
                "description": func.__doc__ or "",
                "parameters": param_info,
                "return_type": str(sig.return_annotation).replace("typing.", "")
            }
            
            return wrapper
        return decorator


# Create tool registry
tools = ToolRegistry()


# Context7 MCP integration tools
@tools.register(name="get_mitre_technique_info")
async def get_mitre_technique_info(technique_id: str) -> Dict[str, Any]:
    """
    Get detailed information about a MITRE ATT&CK technique from Context7 MCP
    
    Args:
        technique_id: MITRE ATT&CK technique ID (e.g., T1078)
        
    Returns:
        Dictionary with technique details
    """
    # In a real implementation, we would call MCP API
    # library_id = await resolve_library_id("mitre-attack")
    # docs = await get_library_docs(library_id, topic=f"technique {technique_id}")
    
    # Simulated response for demonstration
    technique_info = {
        "T1071": {
            "name": "Application Layer Protocol",
            "tactic": "Command and Control",
            "description": "Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic.",
            "mitigation": "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware or tools can be used to mitigate activity at the network level.",
            "url": "https://attack.mitre.org/techniques/T1071/"
        },
        "T1078": {
            "name": "Valid Accounts",
            "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
            "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
            "mitigation": "Enforce strong password and account management policies and practices, including MFA and account lockout policies.",
            "url": "https://attack.mitre.org/techniques/T1078/"
        }
    }
    
    if technique_id in technique_info:
        return {
            "technique_id": technique_id,
            "technique_info": technique_info[technique_id],
            "source": "Context7 MCP (simulated)"
        }
    else:
        return {
            "technique_id": technique_id,
            "technique_info": {
                "name": "Unknown Technique",
                "tactic": "Unknown",
                "description": "No information available for this technique ID.",
                "mitigation": "No mitigation information available.",
                "url": f"https://attack.mitre.org/techniques/"
            },
            "source": "Fallback information"
        }


@tools.register(name="get_security_framework_guidance")
async def get_security_framework_guidance(
    framework: Literal["mitre", "owasp", "nist"],
    topic: str
) -> Dict[str, Any]:
    """
    Get security framework guidance from Context7 MCP
    
    Args:
        framework: Security framework to query ("mitre", "owasp", or "nist")
        topic: Topic to get guidance for
        
    Returns:
        Dictionary with framework guidance
    """
    # In a real implementation, we would call MCP API
    # library_id = await resolve_library_id(f"{framework}-framework")
    # docs = await get_library_docs(library_id, topic=topic)
    
    # Simulated response for demonstration
    guidance = {
        "mitre": {
            "dns": "MITRE ATT&CK describes DNS tunneling (T1071.004) as a technique used by adversaries to exfiltrate data or for command and control. Monitor for unusual DNS query patterns, high volumes of DNS queries, and DNS requests to newly registered or uncommon TLDs.",
            "phishing": "MITRE ATT&CK describes phishing (T1566) as a common initial access technique. Implement email filtering, user awareness training, browser protections, and disable execution of commonly exploited file types.",
            "default": "MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations."
        },
        "owasp": {
            "injection": "OWASP Top 10 lists Injection (A03:2021) as a major web application security risk. Use parameterized queries, input validation, and proper error handling to prevent injection attacks.",
            "authentication": "OWASP Top 10 includes Broken Authentication (A07:2021) as a major risk. Implement MFA, secure session management, and proper password handling.",
            "default": "OWASP Top 10 is a standard awareness document for developers and web application security, representing the most critical security risks to web applications."
        },
        "nist": {
            "incident response": "NIST SP 800-61 provides guidance on computer security incident handling including preparation, detection and analysis, containment, eradication, recovery, and post-incident activity.",
            "risk management": "NIST Cybersecurity Framework provides guidance for risk management consisting of five core functions: Identify, Protect, Detect, Respond, and Recover.",
            "default": "The NIST Cybersecurity Framework provides a policy framework of computer security guidance for organizations to assess and improve their ability to prevent, detect, and respond to cyber attacks."
        }
    }
    
    framework_data = guidance.get(framework, {"default": "No information available for this framework."})
    return {
        "framework": framework,
        "topic": topic,
        "guidance": framework_data.get(topic.lower(), framework_data.get("default", "No specific guidance available.")),
        "source": "Context7 MCP (simulated)"
    }


# SOC Analyst tools
@tools.register(name="extract_security_indicators")
async def extract_security_indicators(
    incident_data: Dict[str, Any], 
    logs: List[Dict[str, Any]] = None
) -> SecurityIndicators:
    """
    Extract security indicators from incident data and logs
    
    Args:
        incident_data: Dictionary containing incident details
        logs: Optional list of log entries related to the incident
        
    Returns:
        SecurityIndicators object with extracted indicators
    """
    indicators = SecurityIndicators()
    
    # Extract from incident data
    if "entities" in incident_data:
        for entity in incident_data.get("entities", []):
            if "Address" in entity and entity["Address"]:
                indicators.ip_addresses.append(entity["Address"])
            if "Account" in entity and entity["Account"]:
                indicators.users.append(entity["Account"])
            if "DomainName" in entity and entity["DomainName"]:
                indicators.domains.append(entity["DomainName"])
            if "Process" in entity and entity["Process"]:
                indicators.processes.append(entity["Process"])
    
    # Extract from incident properties directly
    title = incident_data.get("Title", "")
    description = incident_data.get("Description", "")
    
    # Look for domain in title (common pattern in DNS alerts)
    if "DNS" in title and "Domain" in incident_data:
        domain = incident_data.get("Domain")
        if domain and domain not in indicators.domains:
            indicators.domains.append(domain)
    
    # Extract from logs if provided
    if logs:
        for log in logs:
            if "src_ip" in log and log["src_ip"]:
                indicators.ip_addresses.append(log["src_ip"])
            if "dest_ip" in log and log["dest_ip"]:
                indicators.ip_addresses.append(log["dest_ip"])
            if "domain" in log and log["domain"]:
                indicators.domains.append(log["domain"])
            if "user" in log and log["user"]:
                indicators.users.append(log["user"])
            if "file_hash" in log and log["file_hash"]:
                indicators.hashes.append(log["file_hash"])
            if "process" in log and log["process"]:
                indicators.processes.append(log["process"])
    
    # Remove duplicates via model validator
    return indicators


@tools.register(name="generate_soc_analyst_report")
async def generate_soc_analyst_report(
    incident_data: Dict[str, Any],
    logs: List[Dict[str, Any]],
    indicators: SecurityIndicators = None,
    ollama_model: str = "deepseek-r1:7b"
) -> IncidentAnalysisOutput:
    """
    Generate a comprehensive SOC analyst report for a security incident
    
    Args:
        incident_data: Dictionary containing incident details
        logs: List of log entries related to the incident
        indicators: Optional SecurityIndicators object (if None, will be extracted)
        ollama_model: Ollama model to use for generation
        
    Returns:
        IncidentAnalysisOutput object with analysis and recommendations
    """
    # Extract indicators if not provided
    if indicators is None:
        indicators = await extract_security_indicators(incident_data, logs)
    
    # Get framework guidance based on incident type
    incident_type = incident_data.get("Title", "")
    framework_guidance = {}
    
    if any(keyword in incident_type.lower() for keyword in ["dns", "domain", "c2", "command"]):
        mitre_guidance = await get_security_framework_guidance("mitre", "dns")
        framework_guidance["mitre"] = mitre_guidance["guidance"]
    elif any(keyword in incident_type.lower() for keyword in ["phish", "email", "spam"]):
        mitre_guidance = await get_security_framework_guidance("mitre", "phishing")
        framework_guidance["mitre"] = mitre_guidance["guidance"]
    else:
        mitre_guidance = await get_security_framework_guidance("mitre", "default")
        framework_guidance["mitre"] = mitre_guidance["guidance"]
    
    # Get MITRE technique info if available in incident data
    technique_info = None
    if "Technique" in incident_data and incident_data["Technique"]:
        technique_id = incident_data["Technique"]
        technique_info = await get_mitre_technique_info(technique_id)
    
    # Format log summary
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
    
    # Create a system prompt for the LLM
    system_prompt = """You are an expert SOC analyst tasked with analyzing a security incident.
Your primary responsibility is to provide a comprehensive, evidence-based analysis with specific,
technically precise recommendations.

Focus on concrete evidence from the logs and incident data. Provide technically accurate, actionable
recommendations that include specific commands and tools. Include specific indicators (IPs, domains,
hashes, users) in your recommendations.

Your analysis should be detailed enough that any SOC analyst could immediately implement your recommendations.
"""

    # Create a detailed prompt with all available information
    prompt = f"""Please analyze this security incident and provide a comprehensive report.

INCIDENT DETAILS:
----------------
Incident ID: {incident_data.get('IncidentNumber', 'Unknown')}
Title: {incident_data.get('Title', 'Unknown')}
Severity: {incident_data.get('Severity', 'Unknown')}
Status: {incident_data.get('Status', 'Unknown')}
Created: {incident_data.get('CreatedTimeUtc', 'Unknown')}
"""

    if "Domain" in incident_data:
        prompt += f"Domain: {incident_data.get('Domain')}\n"
    
    if "Owner" in incident_data:
        prompt += f"Owner: {incident_data.get('Owner')}\n"
    
    if technique_info:
        prompt += f"\nMITRE TECHNIQUE:\n----------------\n"
        prompt += f"Technique: {technique_info['technique_id']} - {technique_info['technique_info']['name']}\n"
        prompt += f"Tactic: {technique_info['technique_info']['tactic']}\n"
        prompt += f"Description: {technique_info['technique_info']['description']}\n"
        prompt += f"Mitigation: {technique_info['technique_info']['mitigation']}\n"
    
    # Add extracted indicators
    prompt += f"\nEXTRACTED INDICATORS:\n---------------------\n"
    
    if indicators.domains:
        prompt += f"Domains: {', '.join(indicators.domains)}\n"
    
    if indicators.ip_addresses:
        prompt += f"IP Addresses: {', '.join(indicators.ip_addresses)}\n"
    
    if indicators.users:
        prompt += f"Users: {', '.join(indicators.users)}\n"
    
    if indicators.processes:
        prompt += f"Processes: {', '.join(indicators.processes)}\n"
    
    if indicators.hashes:
        prompt += f"File Hashes: {', '.join(indicators.hashes)}\n"
    
    # Add logs summary
    prompt += f"\nLOG SUMMARY:\n------------\n{logs_summary}\n"
    
    # Add framework guidance
    if framework_guidance:
        prompt += f"\nSECURITY FRAMEWORK GUIDANCE:\n---------------------------\n"
        for framework, guidance in framework_guidance.items():
            prompt += f"{framework.upper()}: {guidance}\n\n"
    
    # Add output instructions
    prompt += """
Please provide your analysis in the following JSON format:
{
  "incident_id": "The incident ID",
  "severity": "High|Medium|Low|Critical based on your assessment",
  "incident_title": "Brief title describing the incident",
  "executive_summary": "Brief executive summary",
  "identified_techniques": [
    {
      "technique_id": "MITRE ATT&CK technique ID",
      "technique_name": "Name of the technique",
      "evidence": ["Evidence item 1", "Evidence item 2"],
      "confidence": "High|Medium|Low"
    }
  ],
  "immediate_actions": [
    {
      "description": "Detailed action description",
      "evidence": ["Evidence for this action 1", "Evidence for this action 2"],
      "priority": "Critical|High|Medium|Low",
      "specific_commands": ["command 1", "command 2"],
      "expected_outcome": "What will happen after this action",
      "security_framework_alignment": "How this aligns with security frameworks"
    }
  ],
  "future_steps": [
    {
      "description": "Investigation step description",
      "rationale": "Why this step is important",
      "tools": ["Tool 1", "Tool 2"],
      "data_sources": ["Data source 1", "Data source 2"],
      "expected_findings": "What you might find",
      "techniques_addressed": ["T1234", "T5678"]
    }
  ]
}
"""

    # Call Ollama for generation
    ollama_client = OllamaClient(model=ollama_model)
    response_text = await ollama_client.generate(prompt, system_prompt)
    
    # Extract JSON from response
    try:
        # Find JSON in the response
        json_start = response_text.find('{')
        json_end = response_text.rfind('}') + 1
        
        if json_start != -1 and json_end != -1:
            json_text = response_text[json_start:json_end]
            response_data = json.loads(json_text)
            return IncidentAnalysisOutput.model_validate(response_data)
        else:
            # Fallback approach if no JSON found
            print("Warning: Could not find JSON in Ollama response. Using fallback parsing.")
            return _fallback_parser(response_text, incident_data)
    except json.JSONDecodeError as e:
        print(f"JSON decode error: {e}")
        return _fallback_parser(response_text, incident_data)
    except Exception as e:
        print(f"Error parsing Ollama response: {e}")
        # Create minimal valid output
        return _fallback_parser(response_text, incident_data)


def _fallback_parser(text: str, incident_data: Dict[str, Any]) -> IncidentAnalysisOutput:
    """Fallback parser for when JSON parsing fails"""
    # Extract what we can from the text response
    lines = text.split('\n')
    
    # Try to extract key information
    incident_id = incident_data.get("IncidentNumber", "UNKNOWN")
    severity = incident_data.get("Severity", "Medium")
    title = incident_data.get("Title", "Security Incident Analysis")
    summary = ""
    
    for line in lines:
        if "incident id" in line.lower() or "incident number" in line.lower():
            parts = line.split(":")
            if len(parts) > 1:
                incident_id = parts[-1].strip()
        elif "severity" in line.lower():
            if "high" in line.lower():
                severity = "High"
            elif "critical" in line.lower():
                severity = "Critical"
            elif "low" in line.lower():
                severity = "Low"
        elif "title" in line.lower() or "summary" in line.lower():
            parts = line.split(":")
            if len(parts) > 1:
                title = parts[-1].strip()
        
        # Collect lines that might be part of the summary
        if not line.startswith('#') and len(line) > 20 and ":" not in line:
            summary += line + "\n"
            if len(summary) > 200:
                break
    
    # Look for technique information in incident data
    technique_id = incident_data.get("Technique", "T0000")
    technique_name = "Unknown Technique"
    
    # Create a minimal valid response
    return IncidentAnalysisOutput(
        incident_id=incident_id,
        severity=severity,
        incident_title=title,
        executive_summary=summary[:500] if summary else "Analysis of security incident based on available data.",
        identified_techniques=[
            TechniqueDetails(
                technique_id=technique_id,
                technique_name=technique_name,
                evidence=["Evidence derived from incident data"],
                confidence="Medium"
            )
        ],
        immediate_actions=[
            ActionRecommendation(
                description="Investigate the security incident thoroughly",
                evidence=["Incident data indicates potential security concern"],
                priority="Medium",
                expected_outcome="Better understanding of the incident scope and impact"
            )
        ],
        future_steps=[
            InvestigationStep(
                description="Perform comprehensive log analysis",
                rationale="To identify all affected systems and understand the attack path",
                tools=["Log analysis tools", "SIEM"],
                data_sources=["Security logs", "Network traffic logs"],
                expected_findings="Complete understanding of the incident timeline and impact"
            )
        ]
    )


@tools.register(name="format_soc_analyst_report")
async def format_soc_analyst_report(report: IncidentAnalysisOutput) -> str:
    """
    Format the SOC analyst report for display
    
    Args:
        report: IncidentAnalysisOutput object with analysis and recommendations
        
    Returns:
        Formatted string report
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
    """Main function to demonstrate the modern SOC analyst system"""
    print("Modern SOC Analyst System")
    print("========================\n")
    
    # Sample incident data (in a real scenario, this would come from Azure Sentinel)
    sample_incident = {
        "IncidentNumber": "INC-2023-12345",
        "Title": "[Custom]-[TI]-DNS with TI Domain Correlation",
        "Description": "Multiple DNS queries to potentially malicious domain detected",
        "Severity": "Medium",
        "Status": "New",
        "CreatedTimeUtc": "2023-12-15T10:25:13Z",
        "Domain": "suspicious-domain.example.com",
        "Technique": "T1071",
        "Owner": "SOC Team",
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
            "event_type": "dns_query",
            "src_ip": "10.0.0.15",
            "domain": "suspicious-domain.example.com",
            "query_type": "A",
            "message": "DNS query for suspicious domain"
        },
        {
            "timestamp": "2023-12-15T10:16:12Z",
            "event_type": "dns_query",
            "src_ip": "10.0.0.15",
            "domain": "suspicious-domain.example.com",
            "query_type": "A",
            "message": "DNS query for suspicious domain"
        },
        {
            "timestamp": "2023-12-15T10:17:45Z",
            "event_type": "network_connection",
            "src_ip": "10.0.0.15",
            "dest_ip": "203.0.113.100",
            "dest_port": 443,
            "protocol": "TCP",
            "message": "Connection to suspicious IP"
        },
        {
            "timestamp": "2023-12-15T10:18:22Z",
            "event_type": "process_creation",
            "src_ip": "10.0.0.15",
            "user": "jhenderson",
            "process": "powershell.exe",
            "command_line": "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADEALgAxADAANQAiACwANAA0ADMANQAPAA==",
            "message": "PowerShell execution with encoded command"
        }
    ]
    
    # Extract security indicators
    print("Extracting security indicators...")
    indicators = await extract_security_indicators(sample_incident, sample_logs)
    print(f"Extracted {indicators.indicator_count} indicators")
    
    # Generate SOC analyst report
    print("\nGenerating SOC analyst report (this may take a minute)...")
    soc_report = await generate_soc_analyst_report(
        incident_data=sample_incident,
        logs=sample_logs,
        indicators=indicators,
        ollama_model="deepseek-r1:7b"  # Use the deepseek model
    )
    
    # Format and print the report
    formatted_report = await format_soc_analyst_report(soc_report)
    print("\n" + formatted_report)
    
    # Save the report to a file
    try:
        filename = f"incident_{sample_incident['IncidentNumber']}_report.txt"
        with open(filename, "w") as f:
            f.write(formatted_report)
        print(f"\nReport saved to {filename}")
    except Exception as e:
        print(f"Error saving report to file: {e}")


if __name__ == "__main__":
    # Run the main function
    print("Starting Modern SOC Analyst with tool calling and Context7 integration using deepseek-r1:7b...")
    asyncio.run(main()) 