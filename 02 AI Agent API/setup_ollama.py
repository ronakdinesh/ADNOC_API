"""
Ollama Setup Script for SOC Analyst System

This script checks if Ollama is installed and running, and pulls the Llama 3.2 model 
if not already available. Run this before using the SOC Analyst system.
"""

import os
import sys
import subprocess
import requests
import time
import platform
import json

def check_ollama_running():
    """Check if the Ollama server is running by making a request to its API endpoint"""
    try:
        response = requests.get("http://localhost:11434/api/tags")
        return response.status_code == 200
    except requests.exceptions.ConnectionError:
        return False

def get_installed_models():
    """Get list of models installed in Ollama"""
    try:
        response = requests.get("http://localhost:11434/api/tags")
        if response.status_code == 200:
            return [model["name"] for model in response.json().get("models", [])]
        return []
    except requests.exceptions.ConnectionError:
        return []

def install_ollama():
    """Install Ollama based on the current platform"""
    system = platform.system().lower()
    
    if system == "windows":
        print("Please download and install Ollama from https://ollama.com/download/windows")
        print("After installation, restart this script.")
        webbrowser_cmd = 'start "" "https://ollama.com/download/windows"'
        subprocess.call(webbrowser_cmd, shell=True)
        return False
    elif system == "darwin":  # macOS
        install_cmd = 'curl -fsSL https://ollama.com/install.sh | sh'
    elif system == "linux":
        install_cmd = 'curl -fsSL https://ollama.com/install.sh | sh'
    else:
        print(f"Unsupported platform: {system}")
        print("Please visit https://ollama.com/download for manual installation")
        return False
    
    print(f"Installing Ollama for {system}...")
    try:
        subprocess.check_call(install_cmd, shell=True)
        print("Ollama installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error installing Ollama: {e}")
        return False

def start_ollama_server():
    """Start the Ollama server"""
    system = platform.system().lower()
    
    if system == "windows":
        # On Windows, Ollama should be started from the Start Menu
        print("Please start Ollama from the Start Menu or Desktop shortcut")
        return False
    
    try:
        # Start Ollama as a background process
        if system == "darwin" or system == "linux":
            subprocess.Popen(["ollama", "serve"], 
                           stdout=subprocess.DEVNULL, 
                           stderr=subprocess.DEVNULL)
        
        # Wait for the server to start
        for _ in range(5):  # Try for 5 seconds
            if check_ollama_running():
                print("Ollama server started")
                return True
            time.sleep(1)
        
        print("Ollama server failed to start in the expected time")
        return False
    except Exception as e:
        print(f"Error starting Ollama server: {e}")
        return False

def pull_llama_model():
    """Pull the DeepSeek model"""
    print("Pulling the DeepSeek model from Ollama...")
    response = requests.post(
        "http://localhost:11434/api/pull",
        json={"name": "deepseek-r1:7b"}
    )
    
    # Parse the streaming response
    for line in response.iter_lines():
        if line:
            data = json.loads(line.decode('utf-8'))
            if 'status' in data:
                print(f"Status: {data['status']}")
            if 'completed' in data and data['completed']:
                print("DeepSeek model pulled successfully!")

def validate_ollama_installation():
    """Check if Ollama is installed and running"""
    try:
        # Try to connect to Ollama
        response = requests.get("http://localhost:11434/api/tags")
        if response.status_code == 200:
            models = response.json().get('models', [])
            deepseek_available = any(model['name'].startswith('deepseek-r1:7b') for model in models)
            
            if deepseek_available:
                print("DeepSeek model is already available.")
                return True
            else:
                print("Ollama is running, but DeepSeek model is not available.")
                return False
        else:
            print(f"Ollama responded with status code: {response.status_code}")
            return False
    except Exception as e:
        print(f"Error connecting to Ollama: {e}")
        return False

def main():
    """Main function to set up the Ollama environment"""
    print("Setting up the Ollama environment for the Modern SOC Analyst...")
    
    # Check if Ollama is already installed and running
    if validate_ollama_installation():
        print("Ollama is already set up with the DeepSeek model.")
    else:
        # Install Ollama if it's not already installed
        install_ollama()
        
        # Start Ollama
        start_ollama_server()
        
        # Pull the DeepSeek model
        pull_llama_model()
    
    print("Ollama setup completed. The Modern SOC Analyst is ready to use.")

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 