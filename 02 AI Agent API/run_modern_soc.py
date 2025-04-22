#!/usr/bin/env python
"""
Modern SOC Analyst System Runner

This script is the entry point for running the Modern SOC Analyst system.
It loads sample incident data, initializes the local LLM client, and
processes security incidents to generate detailed SOC reports.
"""

import os
import sys
import json
import asyncio
import argparse
from datetime import datetime
from typing import Dict, List, Any, Optional

# Import our modules
try:
    from modern_soc_analyst import (
        tools, 
        extract_security_indicators, 
        generate_soc_analyst_report, 
        format_soc_analyst_report
    )
    from local_llm_integration import get_local_llm_client, LocalLLMClient
    from setup_ollama import validate_ollama_installation
except ImportError as e:
    print(f"Error importing required modules: {e}")
    print("Please ensure all dependencies are installed.")
    sys.exit(1)


async def load_sample_data(file_path: str) -> Dict[str, Any]:
    """
    Load sample incident data from a JSON file.
    
    Args:
        file_path: Path to the JSON file
        
    Returns:
        Dict[str, Any]: Loaded incident data
    """
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading sample data: {e}")
        print(f"Please ensure {file_path} exists and contains valid JSON.")
        sys.exit(1)


async def process_incident(
    incident_data: Dict[str, Any],
    llm_client: LocalLLMClient,
    output_dir: str = None
) -> None:
    """
    Process a security incident and generate a SOC analyst report.
    
    Args:
        incident_data: Incident data dictionary
        llm_client: LocalLLMClient instance
        output_dir: Directory to save report files
    """
    try:
        # Extract incident ID
        incident_id = incident_data.get("IncidentNumber", "unknown")
        print(f"\nProcessing incident {incident_id}...")
        
        # Extract security indicators from incident data
        print("Extracting security indicators...")
        indicators = await extract_security_indicators(
            incident_data=incident_data,
            logs=incident_data.get("logs", [])
        )
        
        # Print found indicators
        print(f"Found {indicators.indicator_count} indicators:")
        if indicators.ip_addresses:
            print(f"  - IPs: {', '.join(indicators.ip_addresses[:5])}" + 
                  (f" and {len(indicators.ip_addresses)-5} more" if len(indicators.ip_addresses) > 5 else ""))
        if indicators.domains:
            print(f"  - Domains: {', '.join(indicators.domains[:5])}" + 
                  (f" and {len(indicators.domains)-5} more" if len(indicators.domains) > 5 else ""))
        if indicators.users:
            print(f"  - Users: {', '.join(indicators.users[:5])}" + 
                  (f" and {len(indicators.users)-5} more" if len(indicators.users) > 5 else ""))
        
        # Generate SOC analyst report
        print("\nGenerating SOC analyst report using local LLM...")
        # This step might take some time depending on your local LLM performance
        report = await generate_soc_analyst_report(
            incident_data=incident_data,
            logs=incident_data.get("logs", []),
            indicators=indicators,
            ollama_model=llm_client.model
        )
        
        # Format report for human readability
        formatted_report = await format_soc_analyst_report(report)
        
        # Print report
        print("\n" + "="*80)
        print(formatted_report)
        print("="*80)
        
        # Save report to file if output directory specified
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            report_file = os.path.join(output_dir, f"incident_{incident_id}_report.txt")
            
            with open(report_file, 'w') as f:
                f.write(formatted_report)
            
            print(f"\nReport saved to {report_file}")
            
    except Exception as e:
        print(f"Error processing incident: {e}")


async def main():
    """Main function to run the SOC analyst system"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Modern SOC Analyst System")
    parser.add_argument("-m", "--model", default="deepseek-r1:7b", 
                       help="Ollama model to use (default: deepseek-r1:7b)")
    parser.add_argument("-d", "--data", default="sample_incident.json",
                       help="Path to sample incident data JSON file")
    parser.add_argument("-o", "--output", default="reports",
                       help="Directory to save generated reports")
    args = parser.parse_args()
    
    # Print welcome message
    print("="*80)
    print("Modern SOC Analyst System with Local LLM Integration")
    print("="*80)
    
    # Validate Ollama installation
    print("\nValidating Ollama installation...")
    if not validate_ollama_installation():
        print("Please install Ollama and pull the required model (deepseek-r1:7b)")
        print("Run setup_ollama.py to set up the environment")
        sys.exit(1)
    
    # Initialize local LLM client
    print(f"\nInitializing LLM client with model: {args.model}")
    llm_client = await get_local_llm_client(model=args.model)
    
    # Load sample incident data
    print(f"\nLoading sample incident data from: {args.data}")
    sample_data_file = os.path.join(os.path.dirname(__file__), args.data)
    incident_data = await load_sample_data(sample_data_file)
    
    # Process the incident
    await process_incident(
        incident_data=incident_data,
        llm_client=llm_client,
        output_dir=args.output
    )
    
    print("\nSOC analyst processing complete!")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nProcess interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1) 