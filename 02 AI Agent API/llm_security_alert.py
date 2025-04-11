import os
import json
import requests
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Union
from dotenv import load_dotenv
import pandas as pd
from tabulate import tabulate
import sys
import importlib

# Load environment variables
load_dotenv()

# Get Azure authentication details from environment variables
tenant_id = os.getenv('TENANT_ID')
client_id = os.getenv('CLIENT_ID')
client_secret = os.getenv('CLIENT_SECRET')
workspace_id = os.getenv('WORKSPACE_ID')

# Check if credentials are properly configured
if not all([tenant_id, client_id, client_secret, workspace_id]):
    missing = []
    if not tenant_id:
        missing.append("TENANT_ID")
    if not client_id:
        missing.append("CLIENT_ID")
    if not client_secret:
        missing.append("CLIENT_SECRET")
    if not workspace_id:
        missing.append("WORKSPACE_ID")
    
    print(f"Error: Missing required environment variables: {', '.join(missing)}")
    print("Please ensure these are set in your .env file or environment variables")
    sys.exit(1)

# Check for adal library
try:
    import adal
except ImportError:
    print("Error: The 'adal' library is required but not installed.")
    print("Please install it using: pip install adal")
    sys.exit(1)

def get_security_alerts(hours=24, limit=50, severity=None, status=None, entity=None, tactic=None, technique=None, provider=None):
    """
    Retrieve security alerts from Microsoft Sentinel via the Log Analytics API
    """
    try:
        # Authentication
        authority_url = f"https://login.microsoftonline.com/{tenant_id}"
        resource = "https://api.loganalytics.io"

        context = adal.AuthenticationContext(authority_url)
        token = context.acquire_token_with_client_credentials(
            resource,
            client_id,
            client_secret
        )

        access_token = token['accessToken']

        # Build KQL query with filters
        filters = []
        if severity:
            filters.append(f"AlertSeverity == '{severity}'")
        if status:
            filters.append(f"Status == '{status}'")
        if entity:
            filters.append(f"Entities contains '{entity}'")
        if tactic:
            filters.append(f"Tactics contains '{tactic}'")
        if technique:
            filters.append(f"Techniques contains '{technique}'")
        if provider:
            filters.append(f"ProviderName == '{provider}'")

        filter_string = " and ".join(filters)
        if filter_string:
            filter_string = f"| where {filter_string}"

        query = f"""
        SecurityAlert
        | where TimeGenerated > ago({hours}h)
        {filter_string}
        | project
            TimeGenerated,
            AlertName,
            AlertSeverity,
            Status,
            Description,
            Entities,
            Tactics,
            Techniques,
            ProviderName
        | order by TimeGenerated desc
        | limit {limit}
        """

        url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        request_body = {'query': query}

        response = requests.post(url, headers=headers, json=request_body)
        response.raise_for_status()

        results = response.json()
        return results

    except Exception as e:
        print(f"Error getting security alerts: {str(e)}")
        raise  # Re-raise the exception to let callers handle it

def display_alerts(alerts_data, format='table'):
    if not alerts_data or 'tables' not in alerts_data:
        print("No alert data to display")
        return

    table = alerts_data['tables'][0]
    column_names = [col['name'] for col in table['columns']]
    rows = table['rows']

    if format == 'table':
        # Create list of dictionaries for tabulate
        table_data = []
        for row in rows:
            row_dict = dict(zip(column_names, row))
            # Truncate long fields
            if 'Description' in row_dict:
                row_dict['Description'] = row_dict['Description'][:100] + '...'
            if 'Entities' in row_dict:
                row_dict['Entities'] = str(row_dict['Entities'])[:50] + '...'
            table_data.append(row_dict)
        
        print(tabulate(table_data, headers="keys", tablefmt="grid"))
    
    elif format == 'detailed':
        for row in rows:
            row_dict = dict(zip(column_names, row))
            print("\n" + "="*80)
            for key, value in row_dict.items():
                print(f"{key}:")
                print(f"{value}\n")

def export_to_excel(alerts_data, filename="security_alerts.xlsx"):
    if not alerts_data or 'tables' not in alerts_data:
        print("No alert data to export")
        return

    table = alerts_data['tables'][0]
    column_names = [col['name'] for col in table['columns']]
    rows = table['rows']

    # Convert to pandas DataFrame
    df = pd.DataFrame(rows, columns=column_names)
    
    # Export to Excel
    df.to_excel(filename, index=False)
    print(f"Alerts exported to {filename}")

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
        self.entity = None
        self.tactic = None
        self.technique = None
        self.provider = None
        self.contains_text = None
        self.aggregation_type = None  # count, group by, etc.
        self.time_aggregation = None  # daily, hourly, etc.
        self.sort_by = "TimeGenerated"
        self.sort_direction = "desc"

class SecurityAlertAgent:
    """Main agent class for handling security alert queries"""
    
    def __init__(self, ollama_model=OLLAMA_MODEL, ollama_api_base=OLLAMA_API_BASE):
        self.conversation_history = []
        self.last_alerts = None
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
                "content": """You are a security alert analysis assistant. Your job is to parse user queries about security alerts and extract parameters to build a query.
                
When parsing user queries, extract the following parameters:
- Time range: How far back to look (hours, days, weeks)
- Severity: Alert severity (High, Medium, Low, Informational)
- Status: Alert status (New, In Progress, Closed, etc.)
- Entity: Specific entity being affected
- Tactic: MITRE ATT&CK tactic
- Technique: MITRE ATT&CK technique
- Provider: Security solution provider
- Contains text: Text to search for in alert descriptions
- Aggregation: Whether to count, group by, or analyze trends
- Sorting: How to sort results

Respond in JSON format with extracted parameters. For example:
{
  "hours": 24,
  "limit": 50,
  "severity": "High",
  "status": null,
  "entity": null,
  "tactic": "InitialAccess",
  "technique": null,
  "provider": null,
  "contains_text": null,
  "aggregation_type": "count",
  "time_aggregation": null,
  "sort_by": "TimeGenerated",
  "sort_direction": "desc"
}

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
            if "entity" in params_dict:
                params.entity = params_dict["entity"]
            if "tactic" in params_dict:
                params.tactic = params_dict["tactic"]
            if "technique" in params_dict:
                params.technique = params_dict["technique"]
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
            elif "in progress" in query_lower:
                params.status = "In Progress"
            elif "closed" in query_lower:
                params.status = "Closed"
            
            # Aggregation
            if "count" in query_lower or "how many" in query_lower:
                params.aggregation_type = "count"
                
                if "tactic" in query_lower:
                    params.aggregation_type = "group_by_tactic"
                elif "technique" in query_lower:
                    params.aggregation_type = "group_by_technique"
                elif "provider" in query_lower:
                    params.aggregation_type = "group_by_provider"
            
            return params

    def process_query(self, user_query: str):
        """
        Main method to process a user query from start to finish
        """
        print("\nProcessing your query...")
        
        try:
            # Step 1: Parse the query with LLM
            params = self.parse_query_with_llm(user_query)
            self.last_params = params
            
            # Step 2: Generate KQL query
            kql_query = self.generate_kql_query(params)
            print(f"\nGenerated KQL Query:\n{kql_query}\n")
            
            # Step 3: Execute query via the API
            alerts = get_security_alerts(
                hours=params.hours,
                limit=params.limit,
                severity=params.severity,
                status=params.status,
                entity=params.entity,
                tactic=params.tactic,
                technique=params.technique,
                provider=params.provider
            )
            self.last_alerts = alerts
            
            if not alerts or 'tables' not in alerts or not alerts['tables'][0]['rows']:
                print("No alerts found matching your criteria.")
                return
            
            # Step 4: Generate summary with LLM
            summary = self.generate_result_summary(alerts, params)
            print("\nSummary of Results:")
            print("===================")
            print(summary)
            print("===================")
            
            # Step 5: Ask if user wants to see detailed results
            if input("\nShow detailed alerts? (y/n): ").lower() == 'y':
                display_alerts(alerts)
            
            # Step 6: Ask if user wants to export to Excel
            if input("\nExport to Excel? (y/n): ").lower() == 'y':
                export_to_excel(alerts)
                
            # Add assistant response to conversation history
            alert_count = 0
            if isinstance(alerts, dict) and 'tables' in alerts and 'rows' in alerts['tables'][0]:
                alert_count = len(alerts['tables'][0]['rows'])
            self.add_to_history("assistant", f"I found {alert_count} alerts matching your query. {summary}")
            
        except Exception as e:
            print(f"\nError processing query: {str(e)}")
            self.add_to_history("assistant", f"An error occurred while processing your query: {str(e)}")

    def generate_kql_query(self, params: QueryParameter) -> str:
        """
        Generate a KQL query based on the extracted parameters
        """
        # Start with the base SecurityAlert table
        query = "SecurityAlert\n"
        
        # Add time filter
        query += f"| where TimeGenerated > ago({params.hours}h)\n"
        
        # Add filters based on parameters
        if params.severity:
            query += f"| where AlertSeverity == \"{params.severity}\"\n"
        
        if params.status:
            query += f"| where Status == \"{params.status}\"\n"
        
        if params.entity:
            # Entity is more complex, needs to look in the Entities field which is JSON
            query += f"| where Entities has \"{params.entity}\"\n"
        
        if params.tactic:
            query += f"| where Tactics has \"{params.tactic}\"\n"
            
        if params.technique:
            query += f"| where Techniques has \"{params.technique}\"\n"
            
        if params.provider:
            query += f"| where ProviderName == \"{params.provider}\"\n"
            
        if params.contains_text:
            query += f"| where DisplayName has \"{params.contains_text}\" or Description has \"{params.contains_text}\"\n"
        
        # Handle aggregations if requested
        if params.aggregation_type == "count":
            if params.time_aggregation == "daily":
                query += "| summarize count() by bin(TimeGenerated, 1d)\n"
            elif params.time_aggregation == "hourly":
                query += "| summarize count() by bin(TimeGenerated, 1h)\n"
            else:
                query += "| summarize count() by AlertSeverity\n"
        elif params.aggregation_type == "group_by_tactic":
            query += "| summarize count() by tostring(Tactics)\n"
        elif params.aggregation_type == "group_by_technique":
            query += "| summarize count() by tostring(Techniques)\n"
        elif params.aggregation_type == "group_by_provider":
            query += "| summarize count() by ProviderName\n"
        
        # Add sort order
        if params.aggregation_type is None:
            # Ensure sort_by and sort_direction have valid values
            sort_by = params.sort_by if params.sort_by else "TimeGenerated"
            sort_direction = params.sort_direction if params.sort_direction else "desc"
            query += f"| order by {sort_by} {sort_direction}\n"
        
        # Add limit
        query += f"| take {params.limit}"
        
        return query
    
    def generate_result_summary(self, alerts, params: QueryParameter) -> str:
        """
        Use LLM to generate a summary of the query results
        
        This is another key LLM utilization point
        """
        if not alerts:
            return "No alerts found matching your criteria."
        
        # Extract alert data from the API response structure
        alert_data = []
        if isinstance(alerts, dict) and 'tables' in alerts:
            table = alerts['tables'][0]
            column_names = [col['name'] for col in table['columns']]
            rows = table['rows']
            
            for row in rows:
                alert = dict(zip(column_names, row))
                alert_data.append(alert)
        else:
            alert_data = alerts  # In case alerts is already a list
        
        # Create a summary of the alerts for the LLM
        alert_summary = []
        for i, alert in enumerate(alert_data[:10]):  # Limit to first 10 for LLM context
            summary = {
                "severity": alert.get("AlertSeverity", "Unknown"),
                "name": alert.get("DisplayName", alert.get("AlertName", "Unnamed Alert")),
                "time": alert.get("TimeGenerated [Local]", alert.get("TimeGenerated", "Unknown Time")),
                "provider": alert.get("ProviderName", "Unknown Provider"),
                "status": alert.get("Status", "Unknown Status")
            }
            alert_summary.append(summary)
        
        # Create a prompt for the LLM to generate a summary
        prompt = f"""
I executed a query for security alerts with the following parameters:
- Time range: Last {params.hours} hours
- Severity: {params.severity if params.severity else 'Any'}
- Status: {params.status if params.status else 'Any'}
- Entity: {params.entity if params.entity else 'Any'}
- Tactic: {params.tactic if params.tactic else 'Any'}
- Technique: {params.technique if params.technique else 'Any'}
- Provider: {params.provider if params.provider else 'Any'}
- Text search: {params.contains_text if params.contains_text else 'None'}

The query returned {len(alert_data)} alerts. Here's a sample of the results:
{json.dumps(alert_summary, indent=2)}

Please provide a concise summary of these security alerts, including:
1. Key patterns or trends
2. Most notable alerts
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
            providers = {}
            
            # Extract alert data if not already done
            if not locals().get('alert_data'):
                alert_data = []
                if isinstance(alerts, dict) and 'tables' in alerts:
                    table = alerts['tables'][0]
                    column_names = [col['name'] for col in table['columns']]
                    rows = table['rows']
                    
                    for row in rows:
                        alert = dict(zip(column_names, row))
                        alert_data.append(alert)
                else:
                    alert_data = alerts  # In case alerts is already a list
            
            for alert in alert_data:
                sev = alert.get("AlertSeverity", "Unknown")
                if sev in severities:
                    severities[sev] += 1
                else:
                    severities[sev] = 1
                    
                prov = alert.get("ProviderName", "Unknown")
                if prov in providers:
                    providers[prov] += 1
                else:
                    providers[prov] = 1
            
            summary = f"Found {len(alert_data)} alerts in the last {params.hours} hours.\n"
            summary += "Severity breakdown: " + ", ".join([f"{k}: {v}" for k, v in severities.items()]) + "\n"
            summary += "Provider breakdown: " + ", ".join([f"{k}: {v}" for k, v in providers.items()])
            
            return summary

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
    """Main function to run the security alert agent"""
    print("Security Alert Analysis Agent")
    print("============================")
    print("This agent can answer questions about security alerts from Microsoft Sentinel.")
    
    # Check Ollama availability for LLM features
    print("\nChecking for Ollama availability...")
    model = check_ollama_available()
    
    if not model:
        print("Warning: Could not connect to Ollama. Make sure Ollama is running at", OLLAMA_API_BASE)
        print("The agent will fall back to basic parsing without LLM capabilities.")
        print("To use Ollama, start it with: 'ollama serve' and make sure it's running the model:", OLLAMA_MODEL)
    else:
        print(f"Using Ollama with model: {model}")
    
    print("\nAsk questions in natural language like:")
    print("- Show me high severity alerts from the last 24 hours")
    print("- Any unusual login attempts in the past week?")
    print("- Count alerts by provider")
    print("- What are the most common attack tactics?")
    print("Type 'exit' to quit.")
    print()
    
    # Initialize the agent
    agent = SecurityAlertAgent(ollama_model=model or OLLAMA_MODEL)
    
    # Main interaction loop
    while True:
        user_input = input("\nAsk a question about security alerts (or 'exit' to quit): ")
        
        if user_input.lower() in ['exit', 'quit', 'q']:
            break
        
        # Process the user's query
        agent.process_query(user_input)

if __name__ == "__main__":
    main()