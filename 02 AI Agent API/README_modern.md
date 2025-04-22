# Modern SOC Analyst System

This module implements a modern SOC (Security Operations Center) analyst system with enhanced features over the traditional implementation:

1. **Latest Pydantic Techniques** - Uses modern Pydantic v2+ features
2. **Tool Calling Pattern** - Implements a structured tool registry for modular capabilities
3. **Context7 MCP Integration** - Connects to Context7 for security framework documentation
4. **Local LLM Support** - Leverages Ollama for privacy-focused local LLM processing

## Key Improvements

### Modern Pydantic Features

- Uses `ConfigDict` for model configuration
- Implements `field_validator` and `model_validator` decorators
- Leverages computed properties with the `@property` decorator
- Uses strict typing with Literal types and TypeAdapter

### Tool Calling Architecture

The system implements a tool registry pattern that:
- Automatically validates parameters
- Provides structured documentation for each tool
- Handles async operations seamlessly
- Records tool execution for better traceability

### Context7 MCP Integration

- Connects to Context7 MCP server for up-to-date security framework documentation
- Retrieves specific MITRE ATT&CK technique information
- Gets contextual guidance from OWASP, NIST, and other frameworks
- Incorporates framework insights into recommendations

### Local LLM Processing

- Uses Ollama for local LLM execution
- Implements robust error handling for LLM output parsing
- Includes fallback mechanisms when LLM responses don't meet expectations
- Optimizes prompts for better structured output

## Usage

### Basic Usage

```bash
python modern_soc_analyst.py
```

This will:
1. Run the demo with sample incident data
2. Extract security indicators
3. Generate a comprehensive SOC analyst report using Ollama
4. Save the report to a text file

### Integrating Into Your Workflow

```python
import asyncio
from modern_soc_analyst import extract_security_indicators, generate_soc_analyst_report, format_soc_analyst_report

async def analyze_incident(incident_data, logs):
    # Extract indicators
    indicators = await extract_security_indicators(incident_data, logs)
    
    # Generate report
    report = await generate_soc_analyst_report(
        incident_data=incident_data,
        logs=logs,
        indicators=indicators,
        ollama_model="llama3"  # Use any available Ollama model
    )
    
    # Format the report
    formatted_report = await format_soc_analyst_report(report)
    
    return formatted_report

# Run the analysis
incident_data = {...}  # Your incident data
logs = [...]  # Your logs
report = asyncio.run(analyze_incident(incident_data, logs))
print(report)
```

## Requirements

- Python 3.8+
- Pydantic v2+
- Ollama with the Llama 3 model installed
- Requests library

### Setting Up Ollama

1. Install Ollama from [https://ollama.com](https://ollama.com)
2. Run `ollama pull llama3` to download the model
3. Start Ollama with `ollama serve`

## Customization

### Adding New Tools

You can extend the system with your own tools:

```python
from modern_soc_analyst import tools

@tools.register(name="my_custom_tool")
async def my_custom_tool(param1: str, param2: int = 0) -> Dict[str, Any]:
    """
    My custom tool description
    
    Args:
        param1: Description of param1
        param2: Description of param2 (optional)
        
    Returns:
        Dictionary with results
    """
    # Your implementation here
    return {"result": "Success", "data": {...}}
```

### Using Different LLM Models

Modify the Ollama model used by specifying it in the `generate_soc_analyst_report` function:

```python
report = await generate_soc_analyst_report(
    incident_data=incident_data,
    logs=logs,
    ollama_model="llama3:70b"  # Use a larger model for better results
)
```

## Benefits Over Traditional Implementation

1. **Modularity**: Clear separation of concerns with the tool calling pattern
2. **Type Safety**: Enhanced validation through modern Pydantic features
3. **Framework Integration**: Up-to-date security guidance through Context7 MCP
4. **Privacy**: Local LLM processing for sensitive security data
5. **Extensibility**: Easy to add new capabilities as needed
6. **Robustness**: Improved error handling and fallback mechanisms 