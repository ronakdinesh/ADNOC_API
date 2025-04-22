@echo off
echo SOC Analyst System with Ollama Local LLM
echo ==========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Python is not installed or not in PATH.
    echo Please install Python 3.8 or higher from https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

REM Check if required packages are installed
echo Checking required packages...
python -c "import requests" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Installing required packages...
    pip install requests
)

python -c "import pydantic" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Installing Pydantic...
    pip install pydantic
)

python -c "import pydantic_ai" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Installing Pydantic AI...
    pip install pydantic-ai
)

echo.
echo Setting up Ollama and checking for Llama 3.2 model...
python setup_ollama.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo There was an issue setting up Ollama.
    echo Please run setup_ollama.py manually and check the output.
    echo.
    pause
    exit /b 1
)

echo.
echo Running SOC Analyst System...
echo.
python pydantic_soc_agent.py

echo.
echo Report generation complete.
echo Check the generated text files for detailed SOC reports.
echo.
pause 