# SOC Analyst System with Local LLM Support

This system provides an advanced Security Operations Center (SOC) analyst capability using local LLMs via Ollama. It generates comprehensive security incident reports with detailed, evidence-based recommendations.

## Features

- **Local LLM Processing**: Uses Ollama to run Llama 3.2 locally for enhanced privacy and reduced API costs
- **Structured Analysis**: Generates well-organized reports with executive summaries, identified techniques, and prioritized actions
- **Evidence-Based Recommendations**: All recommendations are linked to specific evidence from logs and incident data
- **Security Framework Integration**: Incorporates guidance from MITRE ATT&CK, OWASP, and NIST frameworks
- **Domain Reputation Checking**: Evaluates the risk level of domains involved in incidents
- **Technical Specificity**: Provides specific commands, tools, and procedures for remediation

## Installation

### Prerequisites

- Python 3.8+
- [Ollama](https://ollama.com/download) installed and running
- Llama 3.2 model pulled in Ollama

### Setup

1. Clone this repository or download the files
2. Install the required Python packages:
   ```
   pip install pydantic-ai requests
   ```
3. Run the setup script to verify Ollama is installed and the required model is available:
   ```
   python setup_ollama.py
   ```

The setup script will:
- Check if Ollama is running
- Install Ollama if needed (or provide download links)
- Pull the Llama 3.2 model if it's not already installed

## Usage

### Basic Usage

Run the main script:

```
python pydantic_soc_agent.py
```

This will:
1. Process a sample security incident (provided in the code)
2. Generate a comprehensive SOC analyst report
3. Save the report to a text file named after the incident ID

### Integrating with Your Own Data

To use with your own incident data, modify the `sample_incident` and `sample_logs` variables in the `main()` function of `pydantic_soc_agent.py`.

You can adapt the code to pull real data from your security tools by:
1. Creating connectors to your SIEM, EDR, or other security tools
2. Formatting the data to match the expected structure
3. Calling `generate_soc_analyst_report()` with your data

## Components

- **pydantic_soc_agent.py**: Main module implementing the SOC analyst system
- **context7_integration.py**: Integration with security frameworks
- **setup_ollama.py**: Utility to set up Ollama and required models

## Customization

### Using Different Ollama Models

To use a different model than Llama 3.2, modify the `OllamaAgent` initialization in `pydantic_soc_agent.py`:

```python
agent = OllamaAgent(
    output_model=IncidentAnalysisOutput,
    model="different-model:tag"  # Replace with your desired model
)
```

### Customizing Prompts

The system prompt can be customized in the `generate_system_prompt()` function to focus on specific aspects of security analysis or to align with your organization's practices.

## Troubleshooting

### Ollama Connection Issues

If you encounter connection errors:
1. Make sure Ollama is running (`ollama serve` command)
2. Check that the model is properly installed (`ollama list`)
3. Verify that the API endpoint is accessible (try `curl http://localhost:11434/api/tags`)

### Model Output Format Issues

If the model struggles to produce valid JSON output:
1. The system includes a fallback parser that will extract what information it can
2. Consider using a more capable model if available (like llama3:70b)
3. Simplify the output schema if needed

## License

This project is open source and available under the MIT License. 