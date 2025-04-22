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
    """Pull the Llama 3.2 model"""
    models = get_installed_models()
    model_name = "llama3"
    
    if model_name in models or f"{model_name}:latest" in models:
        print(f"Model {model_name} is already installed")
        return True
    
    print(f"Pulling {model_name} model (this may take a while)...")
    try:
        # Make API request to pull the model
        response = requests.post(
            "http://localhost:11434/api/pull",
            json={"name": model_name}
        )
        
        if response.status_code == 200:
            print(f"Successfully pulled {model_name} model")
            return True
        else:
            print(f"Failed to pull model: {response.text}")
            return False
    except Exception as e:
        print(f"Error pulling model: {e}")
        return False

def main():
    """Main function to set up Ollama with Llama 3.2"""
    print("Setting up Ollama for SOC Analyst System...")
    
    # Check if Ollama is running
    if not check_ollama_running():
        print("Ollama is not running.")
        
        # Try to start Ollama
        if not start_ollama_server():
            # If starting fails, try to install
            if not install_ollama():
                print("Failed to set up Ollama. Please install it manually.")
                return False
            
            # Try to start again after installation
            if not start_ollama_server():
                print("Ollama installed but couldn't be started. Please start it manually.")
                return False
    
    print("Ollama is running!")
    
    # Pull the Llama 3.2 model
    if pull_llama_model():
        print("\nSetup complete! You can now run the SOC Analyst System with Ollama.")
        print("Run the main script with: python 02\\ AI\\ Agent\\ API/pydantic_soc_agent.py")
        return True
    else:
        print("\nSetup incomplete. Ollama is running but the model couldn't be pulled.")
        print("Please try pulling the model manually with: ollama pull llama3")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 