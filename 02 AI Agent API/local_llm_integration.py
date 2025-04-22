"""
Local LLM Integration Module

This module provides integration with the Ollama local LLM service,
offering efficient text generation capabilities using locally hosted models.
It includes utilities for model status checking, response streaming, and 
structured output parsing.
"""

import os
import json
import asyncio
import requests
from typing import Dict, List, Optional, Any, Union, Literal, Callable
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class LocalLLMClient:
    """
    Client for interacting with local LLM models through Ollama.
    
    This class provides methods for generating text, checking model status,
    and handling structured outputs from locally hosted language models.
    """
    
    def __init__(
        self, 
        model: str = "deepseek-r1:7b", 
        host: str = "localhost", 
        port: int = 11434,
        temperature: float = 0.2,
        max_tokens: int = 4096
    ):
        """
        Initialize the LocalLLM client.
        
        Args:
            model: Name of the model to use (default: "deepseek-r1:7b")
            host: Hostname of the Ollama server (default: "localhost")
            port: Port of the Ollama server (default: 11434)
            temperature: Sampling temperature (default: 0.2)
            max_tokens: Maximum tokens to generate (default: 4096)
        """
        self.model = model
        self.base_url = f"http://{host}:{port}/api"
        self.temperature = temperature
        self.max_tokens = max_tokens
        logger.info(f"Initialized LocalLLM client with model {model}")
    
    async def check_model_available(self) -> bool:
        """
        Check if the specified model is available in Ollama.
        
        Returns:
            bool: True if the model is available, False otherwise
        """
        try:
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: requests.get(f"{self.base_url}/tags")
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to get model list: {response.status_code}")
                return False
                
            models = response.json().get("models", [])
            for model in models:
                if model.get("name") == self.model:
                    logger.info(f"Model {self.model} is available")
                    return True
                    
            logger.warning(f"Model {self.model} is not available in Ollama")
            return False
            
        except Exception as e:
            logger.error(f"Error checking model availability: {e}")
            return False
    
    async def generate(
        self, 
        prompt: str, 
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        format: Optional[str] = None
    ) -> str:
        """
        Generate text using Ollama API.
        
        Args:
            prompt: The prompt to generate from
            system_prompt: Optional system prompt to guide generation
            temperature: Optional temperature override
            max_tokens: Optional max_tokens override
            format: Optional output format (e.g., "json")
            
        Returns:
            str: Generated text from the model
        """
        url = f"{self.base_url}/generate"
        
        payload = {
            "model": self.model,
            "prompt": prompt,
            "temperature": temperature if temperature is not None else self.temperature,
            "max_tokens": max_tokens if max_tokens is not None else self.max_tokens
        }
        
        if system_prompt:
            payload["system"] = system_prompt
            
        if format:
            payload["format"] = format
        
        try:
            logger.info(f"Generating with prompt: {prompt[:50]}...")
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: requests.post(url, json=payload)
            )
            
            if response.status_code != 200:
                logger.error(f"Error from Ollama API: {response.status_code} - {response.text}")
                return f"Error: {response.status_code} - {response.text}"
                
            return response.json().get("response", "")
            
        except Exception as e:
            logger.error(f"Error calling Ollama API: {e}")
            return f"Error: {e}"
    
    async def generate_json(
        self, 
        prompt: str, 
        system_prompt: Optional[str] = None,
        schema: Optional[Dict[str, Any]] = None,
        retry_count: int = 3
    ) -> Dict[str, Any]:
        """
        Generate structured JSON output using Ollama API.
        
        Args:
            prompt: The prompt to generate from
            system_prompt: Optional system prompt to guide generation
            schema: Optional JSON schema to include in the prompt
            retry_count: Number of retries for malformed JSON
            
        Returns:
            Dict[str, Any]: Parsed JSON response
        """
        # Add JSON specific instructions
        full_prompt = prompt
        
        if schema:
            schema_str = json.dumps(schema, indent=2)
            full_prompt = f"{prompt}\n\nPlease respond with a JSON object following this schema:\n{schema_str}\n\nEnsure your response is valid JSON."
        else:
            full_prompt = f"{prompt}\n\nPlease respond with a valid JSON object."
            
        # Add system prompt if not provided
        if not system_prompt:
            system_prompt = "You are a helpful assistant that responds with well-structured JSON. Always ensure your responses are valid JSON objects."
            
        # Try to generate valid JSON with retries
        for attempt in range(retry_count):
            try:
                response = await self.generate(
                    prompt=full_prompt, 
                    system_prompt=system_prompt,
                    format="json"
                )
                
                # Try to parse the JSON
                try:
                    # Clean up the response to extract just the JSON part
                    # This handles cases where the model adds markdown code blocks
                    json_str = response
                    if "```json" in json_str:
                        json_str = json_str.split("```json")[1].split("```")[0].strip()
                    elif "```" in json_str:
                        json_str = json_str.split("```")[1].split("```")[0].strip()
                    
                    # Parse the JSON
                    result = json.loads(json_str)
                    logger.info(f"Successfully generated JSON (attempt {attempt+1})")
                    return result
                    
                except json.JSONDecodeError as e:
                    logger.warning(f"Invalid JSON on attempt {attempt+1}: {e}")
                    if attempt == retry_count - 1:
                        logger.error(f"Failed to generate valid JSON after {retry_count} attempts")
                        logger.error(f"Last response: {response}")
                        return {"error": "Failed to generate valid JSON", "raw_response": response}
            
            except Exception as e:
                logger.error(f"Error in JSON generation (attempt {attempt+1}): {e}")
                if attempt == retry_count - 1:
                    return {"error": str(e)}
        
        return {"error": "Maximum retry attempts reached"}
        
    async def stream_generate(
        self, 
        prompt: str, 
        system_prompt: Optional[str] = None,
        callback: Optional[Callable[[str], None]] = None
    ) -> str:
        """
        Stream text generation using Ollama API.
        
        Args:
            prompt: The prompt to generate from
            system_prompt: Optional system prompt to guide generation
            callback: Optional callback function to process streamed chunks
            
        Returns:
            str: Complete generated text
        """
        url = f"{self.base_url}/generate"
        
        payload = {
            "model": self.model,
            "prompt": prompt,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "stream": True
        }
        
        if system_prompt:
            payload["system"] = system_prompt
        
        complete_response = ""
        
        try:
            logger.info(f"Starting streaming generation")
            response = requests.post(url, json=payload, stream=True)
            
            if response.status_code != 200:
                error_msg = f"Error from Ollama API: {response.status_code}"
                logger.error(error_msg)
                return error_msg
                
            for line in response.iter_lines():
                if line:
                    chunk_data = json.loads(line.decode('utf-8'))
                    chunk = chunk_data.get("response", "")
                    complete_response += chunk
                    
                    if callback and callable(callback):
                        callback(chunk)
            
            logger.info(f"Streaming generation completed")
            return complete_response
            
        except Exception as e:
            logger.error(f"Error in streaming generation: {e}")
            return f"Error: {e}"


# Convenience function to get a pre-configured client
async def get_local_llm_client(model: str = "deepseek-r1:7b") -> LocalLLMClient:
    """
    Get a pre-configured LocalLLM client and verify model availability.
    
    Args:
        model: Name of the model to use
        
    Returns:
        LocalLLMClient: Configured client instance
    """
    client = LocalLLMClient(model=model)
    is_available = await client.check_model_available()
    
    if not is_available:
        logger.warning(f"Model {model} is not available, falling back to system defaults")
        # You could implement fallback logic here
    
    return client


# Simple test function
async def test_local_llm():
    """Test the local LLM integration"""
    client = await get_local_llm_client()
    
    # Test basic generation
    response = await client.generate(
        "Explain how a SOC analyst would investigate a potential data exfiltration incident in 3 sentences."
    )
    print("Basic generation test:")
    print(response)
    print("\n" + "-"*50 + "\n")
    
    # Test JSON generation
    json_response = await client.generate_json(
        "Create a security incident summary with title, severity, and 3 recommended actions",
        schema={
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "severity": {"type": "string", "enum": ["Low", "Medium", "High", "Critical"]},
                "recommended_actions": {
                    "type": "array", 
                    "items": {"type": "string"}
                }
            }
        }
    )
    print("JSON generation test:")
    print(json.dumps(json_response, indent=2))


if __name__ == "__main__":
    asyncio.run(test_local_llm()) 