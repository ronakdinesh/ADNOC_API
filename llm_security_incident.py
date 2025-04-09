import os
import json
import requests
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Union
from dotenv import load_dotenv

# Import functionality from security incidents script
from test_security_incidents import get_security_incidents, display_incidents, export_to_excel

# Load environment variables
load_dotenv()

# Ollama configuration
OLLAMA_API_BASE = "http://localhost:11434/v1"
OLLAMA_MODEL = "llama3.2:latest"

class QueryParameter:
    """Class to represent query parameters extracted from user query"""
    def __init__(self):
        self.hours = 168  # Default: last 168 hours (7 days)
        self.limit = 100  # Default: up to 100 results
        self.severity = None
        self.status = None
        self.owner = None
        self.classification = None
        self.provider = None
        self.contains_text = None
        self.aggregation_type = None  # count, group by, etc.
        self.time_aggregation = None  # daily, hourly, etc.
        self.sort_by = "TimeGenerated"
        self.sort_direction = "desc"

class SecurityIncidentAgent:
    """Main agent class for handling security incident queries"""
    
    def __init__(self, ollama_model=OLLAMA_MODEL, ollama_api_base=OLLAMA_API_BASE):
        self.conversation_history = []
        self.last_incidents = None
        self.last_params = None
        self.ollama_model = ollama_model
        self.ollama_api_base = ollama_api_base
    
    def add_to_history(self, role, content):
        """Add a message to the conversation history"""
        self.conversation_history.append({"role": role, "content": content})
        # Keep conversation history at a reasonable size
        if len(self.conversation_history) > 10:
            # Keep system message if it exists
            system_messages = [msg for msg in self.conversation_history if msg["role"] == "system"]
            user_assistant_messages = [msg for msg in self.conversation_history if msg["role"] != "system"][-9:]
            self.conversation_history = system_messages + user_assistant_messages
    
    def call_ollama_api(self, messages, temperature=0.7):
        """
        Call Ollama API using the requests library
        """
        url = f"{self.ollama_api_base}/chat/completions"
        headers = {
            "Content-Type": "application/json"
        }
        data = {
            "model": self.ollama_model,
            "messages": messages,
            "temperature": temperature,
            "stream": False
        }
        
        try:
            response = requests.post(url, headers=headers, json=data)
            
            if response.status_code != 200:
                raise Exception(f"Ollama API error: {response.status_code} - {response.text}")
            
            return response.json()
        except requests.exceptions.ConnectionError:
            raise Exception(f"Could not connect to Ollama at {self.ollama_api_base}. Make sure Ollama is running.")
    
    def parse_query_with_llm(self, user_query: str) -> QueryParameter:
        """
        Use LLM to parse the user's natural language query into structured parameters
        
        This is where the LLM is used to understand the user's intent and extract parameters
        """
        # Initialize the system message if it doesn't exist
        if not any(msg["role"] == "system" for msg in self.conversation_history):
            system_message = {
                "role": "system", 
                "content": """You are a security incident analysis assistant. Your job is to parse user queries about security incidents and extract parameters to build a query.
                
When parsing user queries, extract the following parameters:
- Time range: How far back to look (hours, days, weeks)
- Severity: Incident severity (High, Medium, Low, Informational)
- Status: Incident status (New, Active, Closed, etc.)
- Owner: Person or team assigned to the incident
- Classification: Incident classification (TruePositive, FalsePositive, etc.)
- Provider: Security solution provider
- Contains text: Text to search for in incident titles or descriptions
- Aggregation: Whether to count, group by, or analyze trends
- Sorting: How to sort results

Respond in JSON format with extracted parameters. For example:
```json
{
  "hours": 24,
  "limit": 50,
  "severity": "High",
  "status": "Active",
  "owner": null,
  "classification": null,
  "provider": null,
  "contains_text": null,
  "aggregation_type": "count",
  "time_aggregation": null,
  "sort_by": "TimeGenerated",
  "sort_direction": "desc",
  "response_type": "summary"
}
```

Use null for parameters not specified in the query. Infer reasonable values when they're implied but not explicitly stated.
"""
            }
            self.add_to_history("system", system_message["content"])
        
        # Add the user query to history
        self.add_to_history("user", user_query)
        
        # Create messages array for Ollama API
        messages = self.conversation_history.copy()
        
        # Add explicit instruction for response format
        messages.append({
            "role": "user",
            "content": f"Parse this query into parameters: '{user_query}'. Respond ONLY with a JSON object containing the parameters."
        })
        
        try:
            # Call Ollama API to parse the query
            # This is a key LLM utilization point
            response = self.call_ollama_api(messages, temperature=0.1)
            
            # Extract JSON from response
            llm_response = response["choices"][0]["message"]["content"].strip()
            
            # Try to extract JSON if it's wrapped in markdown code blocks
            if "```json" in llm_response:
                llm_response = llm_response.split("```json")[1].split("```")[0].strip()
            elif "```" in llm_response:
                llm_response = llm_response.split("```")[1].split("```")[0].strip()
            
            # Parse JSON response
            params_dict = json.loads(llm_response)
            
            # Convert to QueryParameter object
            params = QueryParameter()
            
            # Update parameters from parsed values
            if "hours" in params_dict and params_dict["hours"] is not None:
                params.hours = params_dict["hours"]
            if "limit" in params_dict and params_dict["limit"] is not None:
                params.limit = params_dict["limit"]
            if "severity" in params_dict:
                params.severity = params_dict["severity"]
            if "status" in params_dict:
                params.status = params_dict["status"]
            if "owner" in params_dict:
                params.owner = params_dict["owner"]
            if "classification" in params_dict:
                params.classification = params_dict["classification"]
            if "provider" in params_dict:
                params.provider = params_dict["provider"]
            if "contains_text" in params_dict:
                params.contains_text = params_dict["contains_text"]
            if "aggregation_type" in params_dict:
                params.aggregation_type = params_dict["aggregation_type"]
            if "time_aggregation" in params_dict:
                params.time_aggregation = params_dict["time_aggregation"]
            if "sort_by" in params_dict:
                params.sort_by = params_dict["sort_by"]
            if "sort_direction" in params_dict:
                params.sort_direction = params_dict["sort_direction"]
            
            return params
        
        except Exception as e:
            print(f"Error parsing query with LLM: {str(e)}")
            print("Falling back to basic parameter extraction...")
            
            # Fall back to simple keyword parsing
            params = QueryParameter()
            
            # Simple keyword matching for common cases
            query_lower = user_query.lower()
            
            # Time range
            if "hour" in query_lower:
                for i in range(1, 169):  # Check for 1-168 hours
                    if f"{i} hour" in query_lower or f"{i}h" in query_lower:
                        params.hours = i
                        break
            elif "day" in query_lower:
                for i in range(1, 31):  # Check for 1-30 days
                    if f"{i} day" in query_lower:
                        params.hours = i * 24
                        break
            elif "week" in query_lower:
                for i in range(1, 5):  # Check for 1-4 weeks
                    if f"{i} week" in query_lower:
                        params.hours = i * 24 * 7
                        break
            
            # Severity
            if "high" in query_lower and "severity" in query_lower:
                params.severity = "High"
            elif "medium" in query_lower and "severity" in query_lower:
                params.severity = "Medium"
            elif "low" in query_lower and "severity" in query_lower:
                params.severity = "Low"
            
            # Status
            if "new" in query_lower and "status" in query_lower:
                params.status = "New"
            elif "active" in query_lower:
                params.status = "Active"
            elif "closed" in query_lower:
                params.status = "Closed"
            
            # Classification
            if "true positive" in query_lower:
                params.classification = "TruePositive"
            elif "false positive" in query_lower:
                params.classification = "FalsePositive"
            
            # Aggregation
            if "count" in query_lower or "how many" in query_lower:
                params.aggregation_type = "count"
                
                if "owner" in query_lower:
                    params.aggregation_type = "group_by_owner"
                elif "classification" in query_lower:
                    params.aggregation_type = "group_by_classification"
                elif "provider" in query_lower:
                    params.aggregation_type = "group_by_provider"
            
            return params
    
    def generate_kql_query(self, params: QueryParameter) -> str:
        """
        Generate a KQL query based on the extracted parameters
        """
        # Start with the base SecurityIncident table
        query = "SecurityIncident\n"
        
        # Add time filter
        query += f"| where TimeGenerated > ago({params.hours}h)\n"
        
        # Add filters based on parameters
        if params.severity:
            query += f"| where Severity == \"{params.severity}\"\n"
        
        if params.status:
            query += f"| where Status == \"{params.status}\"\n"
        
        if params.owner:
            query += f"| where Owner == \"{params.owner}\"\n"
        
        if params.classification:
            query += f"| where Classification == \"{params.classification}\"\n"
            
        if params.provider:
            query += f"| where ProviderName == \"{params.provider}\"\n"
            
        if params.contains_text:
            query += f"| where Title has \"{params.contains_text}\" or Description has \"{params.contains_text}\"\n"
        
        # Handle aggregations if requested
        if params.aggregation_type == "count":
            if params.time_aggregation == "daily":
                query += "| summarize count() by bin(TimeGenerated, 1d)\n"
            elif params.time_aggregation == "hourly":
                query += "| summarize count() by bin(TimeGenerated, 1h)\n"
            else:
                query += "| summarize count() by Severity\n"
        elif params.aggregation_type == "group_by_owner":
            query += "| summarize count() by Owner\n"
        elif params.aggregation_type == "group_by_classification":
            query += "| summarize count() by Classification\n"
        elif params.aggregation_type == "group_by_provider":
            query += "| summarize count() by ProviderName\n"
        
        # Add sort order - ensure we have valid values
        if params.aggregation_type is None:
            # Default to ordering by TimeGenerated desc if sort_by is None
            sort_by = params.sort_by if params.sort_by else "TimeGenerated"
            sort_direction = params.sort_direction if params.sort_direction else "desc"
            query += f"| order by {sort_by} {sort_direction}\n"
        
        # Add limit
        query += f"| take {params.limit}"
        
        return query
    
    def generate_result_summary(self, incidents, params: QueryParameter) -> str:
        """
        Use LLM to generate a summary of the query results
        
        This is another key LLM utilization point
        """
        if not incidents:
            return "No incidents found matching your criteria."
        
        # Create a summary of the incidents for the LLM
        incident_summary = []
        for i, incident in enumerate(incidents[:10]):  # Limit to first 10 for LLM context
            summary = {
                "severity": incident.get("Severity", "Unknown"),
                "title": incident.get("Title", "Unnamed Incident"),
                "time": incident.get("TimeGenerated [Local]", "Unknown Time"),
                "provider": incident.get("ProviderName", "Unknown Provider"),
                "status": incident.get("Status", "Unknown Status"),
                "owner": incident.get("Owner", "Unassigned"),
                "incident_number": incident.get("IncidentNumber", "Unknown")
            }
            incident_summary.append(summary)
        
        # Create a prompt for the LLM to generate a summary
        prompt = f"""
I executed a query for security incidents with the following parameters:
- Time range: Last {params.hours} hours
- Severity: {params.severity if params.severity else 'Any'}
- Status: {params.status if params.status else 'Any'}
- Owner: {params.owner if params.owner else 'Any'}
- Classification: {params.classification if params.classification else 'Any'}
- Provider: {params.provider if params.provider else 'Any'}
- Text search: {params.contains_text if params.contains_text else 'None'}

The query returned {len(incidents)} incidents. Here's a sample of the results:
{json.dumps(incident_summary, indent=2)}

Please provide a concise summary of these security incidents, including:
1. Key patterns or trends
2. Most notable incidents
3. Potential security implications
4. Any recommended actions based on these findings
        """
        
        try:
            # Call Ollama API to generate summary
            response = self.call_ollama_api(
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7
            )
            
            # Extract and return the summary
            summary = response["choices"][0]["message"]["content"].strip()
            return summary
            
        except Exception as e:
            print(f"Error generating summary with LLM: {str(e)}")
            # Fallback to basic summary
            severities = {}
            statuses = {}
            
            for incident in incidents:
                sev = incident.get("Severity", "Unknown")
                if sev in severities:
                    severities[sev] += 1
                else:
                    severities[sev] = 1
                    
                status = incident.get("Status", "Unknown")
                if status in statuses:
                    statuses[status] += 1
                else:
                    statuses[status] = 1
            
            summary = f"Found {len(incidents)} incidents in the last {params.hours} hours.\n"
            summary += "Severity breakdown: " + ", ".join([f"{k}: {v}" for k, v in severities.items()]) + "\n"
            summary += "Status breakdown: " + ", ".join([f"{k}: {v}" for k, v in statuses.items()])
            
            return summary
    
    def process_query(self, user_query: str):
        """
        Main method to process a user query from start to finish
        """
        print("\nProcessing your query...")
        
        # Step 1: Parse the query with LLM
        params = self.parse_query_with_llm(user_query)
        self.last_params = params
        
        # Step 2: Generate KQL query
        kql_query = self.generate_kql_query(params)
        print(f"\nGenerated KQL Query:\n{kql_query}\n")
        
        # Step 3: Execute query via the existing API
        incidents = get_security_incidents(
            hours=params.hours,
            limit=params.limit,
            severity=params.severity,
            status=params.status
        )
        self.last_incidents = incidents
        
        if not incidents:
            print("No incidents found matching your criteria.")
            return
        
        # Step 4: Generate summary with LLM
        summary = self.generate_result_summary(incidents, params)
        print("\nSummary of Results:")
        print("===================")
        print(summary)
        print("===================")
        
        # Step 5: Ask if user wants to see detailed results
        if input("\nShow detailed incidents? (y/n): ").lower() == 'y':
            display_incidents(incidents)
        
        # Step 6: Ask if user wants to export to Excel
        if input("\nExport to Excel? (y/n): ").lower() == 'y':
            export_to_excel(incidents)
            
        # Add assistant response to conversation history
        self.add_to_history("assistant", f"I found {len(incidents)} incidents matching your query. {summary}")

def check_ollama_available():
    """Check if Ollama is available at the specified URL"""
    try:
        response = requests.get(f"{OLLAMA_API_BASE}/models")
        if response.status_code == 200:
            models = response.json().get("models", [])
            available_models = [model["name"] for model in models]
            print(f"Ollama is available. Available models: {', '.join(available_models)}")
            
            if OLLAMA_MODEL not in available_models:
                print(f"Warning: Model '{OLLAMA_MODEL}' not found in available models.")
                print(f"Using first available model: {available_models[0] if available_models else 'none'}")
                return available_models[0] if available_models else None
            return OLLAMA_MODEL
        return None
    except:
        return None

def main():
    """Main function to run the security incident agent"""
    print("Security Incident Analysis Agent")
    print("===============================")
    print("This agent can answer questions about security incidents from Microsoft Sentinel.")
    
    # Check Ollama availability
    print("\nChecking for Ollama availability...")
    model = check_ollama_available()
    
    if not model:
        print("Warning: Could not connect to Ollama. Make sure Ollama is running at", OLLAMA_API_BASE)
        print("The agent will fall back to basic parsing without LLM capabilities.")
        print("To use Ollama, start it with: 'ollama serve' and make sure it's running the model:", OLLAMA_MODEL)
    else:
        print(f"Using Ollama with model: {model}")
    
    print("\nAsk questions in natural language like:")
    print("- Show me high severity incidents from the last 24 hours")
    print("- Any active incidents assigned to John?")
    print("- Count incidents by classification")
    print("- Which incidents were closed this week?")
    print("Type 'exit' to quit.")
    print()
    
    # Initialize the agent
    agent = SecurityIncidentAgent(ollama_model=model or OLLAMA_MODEL)
    
    # Main interaction loop
    while True:
        user_input = input("\nAsk a question about security incidents (or 'exit' to quit): ")
        
        if user_input.lower() in ['exit', 'quit', 'q']:
            break
        
        # Process the user's query
        agent.process_query(user_input)

if __name__ == "__main__":
    main() 