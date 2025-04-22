# Modern SOC Analyst System

A next-generation Security Operations Center (SOC) analyst system that leverages local LLM capabilities through Ollama, structured data validation with Pydantic, and security framework integration through Context7.

## Overview

The Modern SOC Analyst System is designed to provide automated analysis of security incidents by:

1. Processing incident data from various security tools
2. Extracting and correlating security indicators (IPs, domains, users, etc.)
3. Generating detailed, actionable SOC reports using local LLM models
4. Providing technical recommendations backed by MITRE ATT&CK and other security frameworks

## Key Features

- **Local LLM Processing**: Uses Ollama to run inference locally with the DeepSeek model for data privacy
- **Structured Data Validation**: Employs Pydantic v2+ for robust data validation and transformation
- **MITRE ATT&CK Integration**: Maps incidents to MITRE techniques for standardized analysis
- **Tool Calling Framework**: Modular design for easy extension with new capabilities
- **Comprehensive Reporting**: Generates detailed reports with immediate actions and investigation steps

## System Architecture

The system consists of several key components:

```
┌─────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│                 │    │                  │    │                  │
│  Incident Data  │───>│  Modern SOC      │───>│  Local LLM       │
│  (JSON)         │    │  Analyst Module  │<───│  (Ollama)        │
│                 │    │                  │    │                  │
└─────────────────┘    └──────────────────┘    └──────────────────┘
                              │  ▲                      ▲
                              │  │                      │
                              ▼  │                      │
┌─────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│                 │    │                  │    │                  │
│  SOC Analyst    │<───│  Formatted       │<───│  Security        │
│  Report         │    │  Report          │    │  Frameworks      │
│                 │    │                  │    │  (MITRE, OWASP)  │
└─────────────────┘    └──────────────────┘    └──────────────────┘
```

## Setup Instructions

### Prerequisites

- Python 3.8 or higher
- Ollama installed (for local LLM)
- Required Python packages:
  - requests
  - pydantic (v2+)
  - pydantic-ai

### Installation Steps

1. **Install Ollama**:
   - Visit [Ollama.com](https://ollama.com) to download and install Ollama for your platform
   - Ollama provides secure local LLM inference capability

2. **Setup Environment**:
   - Clone this repository or download the files
   - Run the `setup_ollama.py` script to verify your Ollama installation and pull the required model:
     ```
     python setup_ollama.py
     ```

3. **Run the System**:
   - Use the provided batch file on Windows:
     ```
     run_modern_soc.bat
     ```
   - Or run the Python script directly:
     ```
     python run_modern_soc.py
     ```

## Usage

By default, the system will:

1. Load sample incident data from `sample_incident.json`
2. Extract security indicators (IPs, domains, users, etc.)
3. Generate a detailed SOC analyst report using the local LLM
4. Display the report in the console and save it to the `reports` directory

### Command Line Options

The `run_modern_soc.py` script supports several command-line arguments:

```
-m, --model      Specify which Ollama model to use (default: deepseek-r1:7b)
-d, --data       Path to incident data JSON file (default: sample_incident.json)
-o, --output     Directory to save generated reports (default: reports)
```

Example:
```
python run_modern_soc.py --model llama3:8b --data custom_incident.json --output custom_reports
```

## Components

### 1. Local LLM Integration

The `local_llm_integration.py` module provides a client for interacting with Ollama's local LLM capabilities. It handles:
- Model availability checking
- Text generation with customizable parameters
- Structured JSON output generation
- Streaming response handling

### 2. SOC Analyst Module

The `modern_soc_analyst.py` module implements the core SOC analyst functionality:
- Data extraction and indicator identification
- Security framework integration
- Report generation through the local LLM
- Report formatting and output

### 3. Pydantic Models

The system uses Pydantic for structured data validation with models such as:
- `TechniqueDetails`: Maps to MITRE ATT&CK techniques
- `ActionRecommendation`: Structured immediate action recommendations
- `InvestigationStep`: Detailed next steps for investigation
- `IncidentAnalysisOutput`: Complete incident analysis output

## Sample Output

The system generates detailed SOC reports with sections including:

- **Incident Details**: Basic information about the incident
- **Executive Summary**: Brief overview of the incident and findings
- **Immediate Actions**: Prioritized list of actions to take immediately
- **Future Steps**: Recommended next steps for investigation

## Customizing the System

The modular design allows for easy extension and customization:

1. **Add New Tool Functions**: Extend the tool registry in `modern_soc_analyst.py`
2. **Customize Report Format**: Modify the `format_soc_analyst_report` function
3. **Integrate New Data Sources**: Add new extraction functions for additional data sources

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- MITRE ATT&CK® is a registered trademark of The MITRE Corporation
- This project uses the DeepSeek model by DeepSeek AI
- Ollama provides the local LLM runtime capability 