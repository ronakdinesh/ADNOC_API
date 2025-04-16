from pydantic import BaseModel
from typing import List, Optional, Dict, Any, Union
import requests
import json

# Ollama configuration
OLLAMA_API_BASE = "http://localhost:11434/v1"
OLLAMA_MODEL = "llama3.2:latest"

class IncidentAnalysisOutput(BaseModel):
    """Pydantic model for incident analysis output"""
    summary: str
    significance: str
    recommendation: Optional[str] = None
    entities_info: Optional[str] = None

def format_analysis_output(analysis_data: Dict[str, Any]) -> IncidentAnalysisOutput:
    """
    Formats raw analysis data into proper string format for the IncidentAnalysisOutput model
    
    Args:
        analysis_data: Raw dictionary with analysis data
        
    Returns:
        IncidentAnalysisOutput: Properly formatted analysis output
    """
    # Format the summary from dictionary to string
    if isinstance(analysis_data.get('summary'), dict):
        summary_dict = analysis_data['summary']
        summary = f"Incident #{summary_dict.get('incident_number', 'Unknown')} "
        summary += f"with severity {summary_dict.get('severity', 'Unknown')} "
        summary += f"was detected on {summary_dict.get('first_detected', 'Unknown date')}."
    else:
        summary = str(analysis_data.get('summary', 'No summary available'))
    
    # Format the significance from dictionary to string
    if isinstance(analysis_data.get('significance'), dict):
        sig_dict = analysis_data['significance']
        significance_points = []
        
        if sig_dict.get('reputation_block'):
            significance_points.append("Site has been reputation blocked")
        if sig_dict.get('blocked_zscaler'):
            significance_points.append("Connection was blocked by Zscaler")
        
        significance = ". ".join(significance_points) if significance_points else "No significant findings identified."
    else:
        significance = str(analysis_data.get('significance', 'Significance unknown'))
    
    # Create recommendation if available
    recommendation = analysis_data.get('recommendation')
    if isinstance(recommendation, dict):
        recommendation = ". ".join([f"{k}: {v}" for k, v in recommendation.items()])
    
    # Format entities info if available
    entities_info = None
    if 'entities' in analysis_data and analysis_data['entities']:
        entities = analysis_data['entities']
        if isinstance(entities, dict):
            entities_info = "\n".join([f"{k}: {', '.join(v) if isinstance(v, list) else v}" 
                                      for k, v in entities.items()])
        elif isinstance(entities, list):
            entities_info = "\n".join([str(e) for e in entities])
    
    return IncidentAnalysisOutput(
        summary=summary,
        significance=significance,
        recommendation=recommendation,
        entities_info=entities_info
    )

def generate_llm_analysis(incident_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Use the local LLM to analyze incident data and generate insights
    
    Args:
        incident_data: Raw incident data
        
    Returns:
        Dict: Analysis data including summary, significance, recommendations
    """
    # Prepare incident data for LLM prompt
    incident_json = json.dumps(incident_data, indent=2)
    
    # Create a prompt for the LLM
    prompt = f"""You are a skilled SOC analyst tasked with analyzing a security incident.
Review the following incident data and provide an analysis:

{incident_json}

Provide a structured analysis with:
1. Summary of the incident (severity, detection time, etc.)
2. Significance (reputation blocks, whether it was blocked by Zscaler, etc.)
3. Recommendations for handling the incident
4. Important entities identified (IPs, domains, etc.)

Format your response as valid JSON with these keys: "summary", "significance", "recommendation", "entities"
"""
    
    # Make API call to Ollama
    try:
        response = requests.post(
            f"{OLLAMA_API_BASE}/chat/completions",
            json={
                "model": OLLAMA_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2
            }
        )
        
        response.raise_for_status()
        llm_response = response.json()
        
        # Extract and parse the LLM response
        content = llm_response.get("choices", [{}])[0].get("message", {}).get("content", "{}")
        
        # Attempt to parse the response as JSON
        try:
            analysis_data = json.loads(content)
            return analysis_data
        except json.JSONDecodeError:
            # If LLM response isn't valid JSON, create a basic structure
            return {
                "summary": f"Incident analysis for #{incident_data.get('id', 'Unknown')}",
                "significance": "Significance could not be determined automatically.",
                "recommendation": "Review incident data manually.",
                "entities": incident_data.get("entities", {})
            }
            
    except Exception as e:
        return {
            "summary": f"Error: {str(e)}",
            "significance": "Unable to analyze using LLM",
            "recommendation": "Check LLM service availability and incident data format",
            "entities": {}
        }

def generate_analysis(incident_data: Dict[str, Any]) -> str:
    """
    Generate a formatted analysis from incident data
    
    Args:
        incident_data: Raw incident data
        
    Returns:
        str: Formatted analysis text
    """
    try:
        # Use LLM to analyze the incident data
        analysis_data = generate_llm_analysis(incident_data)
        
        # If LLM analysis failed, fall back to basic analysis
        if "Error" in str(analysis_data.get('summary', '')):
            # Basic analysis as fallback
            analysis_data = {
                'summary': {
                    'incident_number': incident_data.get('id', 'Unknown'),
                    'severity': incident_data.get('severity', 'Unknown'),
                    'first_detected': incident_data.get('firstDetectedOn', 'Unknown date')
                },
                'significance': {
                    'reputation_block': 'malicious' in str(incident_data).lower(),
                    'blocked_zscaler': 'zscaler' in str(incident_data).lower()
                },
                'entities': {
                    'IPs': incident_data.get('IPs', []),
                    'Domains': incident_data.get('Domains', [])
                }
            }
        
        # Format the analysis data
        formatted_output = format_analysis_output(analysis_data)
        
        # Generate the complete analysis text
        analysis_text = "SOC ANALYST INSIGHTS (Generated by AI):\n"
        analysis_text += "===================================\n"
        analysis_text += f"SUMMARY:\n{formatted_output.summary}\n\n"
        analysis_text += f"SIGNIFICANCE:\n{formatted_output.significance}\n\n"
        
        if formatted_output.recommendation:
            analysis_text += f"RECOMMENDATION:\n{formatted_output.recommendation}\n\n"
        
        if formatted_output.entities_info:
            analysis_text += f"ENTITIES INFORMATION:\n{formatted_output.entities_info}\n\n"
        
        return analysis_text
        
    except Exception as e:
        # Safe error handling
        return (f"Error generating analysis: {str(e)}\n"
                f"Please check the incident data manually.") 