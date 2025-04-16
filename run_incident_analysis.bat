@echo off
echo Microsoft Sentinel Incident Analysis Tool
echo ======================================
echo.

REM Check if Python is available
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Error: Python not found in PATH. Please install Python or add it to your PATH.
    exit /b 1
)

REM Check for the right module
python -c "import pandas" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Installing required modules...
    pip install pandas openpyxl adal
)

echo.
echo Choose an operation:
echo 1 - Fetch DNS TI incidents from last 7 days (export only)
echo 2 - Fetch DNS TI incidents from last 7 days and analyze
echo 3 - Fetch DNS TI incidents from last 30 days (export only)
echo 4 - Fetch DNS TI incidents from last 30 days and analyze
echo 5 - Fetch ALL incidents from last 7 days (export only)
echo 6 - Fetch ALL incidents from last 7 days and analyze
echo 7 - Custom query (you'll be prompted for options)
echo.

set /p choice=Enter your choice (1-7): 

if "%choice%"=="1" (
    python "01 Test Connections/01_test_security_incidents.py" --days 7
) else if "%choice%"=="2" (
    python "01 Test Connections/01_test_security_incidents.py" --days 7 --analyze
) else if "%choice%"=="3" (
    python "01 Test Connections/01_test_security_incidents.py" --days 30
) else if "%choice%"=="4" (
    python "01 Test Connections/01_test_security_incidents.py" --days 30 --analyze
) else if "%choice%"=="5" (
    python "01 Test Connections/01_test_security_incidents.py" --days 7 --all-incidents
) else if "%choice%"=="6" (
    python "01 Test Connections/01_test_security_incidents.py" --days 7 --all-incidents --analyze
) else if "%choice%"=="7" (
    echo.
    echo Custom Query Configuration:
    echo.
    set /p days=Days back to search (e.g., 7, 14, 30): 
    
    set /p filter_option=Include only DNS TI incidents? (y/n): 
    if /i "%filter_option%"=="y" (
        set filter=
    ) else (
        set filter=--all-incidents
    )
    
    set /p analyze_option=Run LLM analysis on results? (y/n): 
    if /i "%analyze_option%"=="y" (
        set analyze=--analyze
    ) else (
        set analyze=
    )
    
    echo.
    echo Running custom query: %days% days back, DNS filter: %filter_option%, Analysis: %analyze_option%
    python "01 Test Connections/01_test_security_incidents.py" --days %days% %filter% %analyze%
) else (
    echo Invalid choice. Please run again and select a number from 1-7.
    exit /b 1
)

echo.
echo Operation completed. Press any key to exit.
pause > nul 