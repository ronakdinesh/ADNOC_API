# Joining Security Incidents and Alerts

This script joins data from security incidents and alerts Excel files, creating a new Excel file with the combined data.

## Requirements

- Python 3.6+
- pandas
- openpyxl

## Setup

1. Make sure you have Python installed
2. Install required packages:
   ```
   pip install pandas openpyxl
   ```

## Data Files

The script expects two Excel files in the `03 extracted data` folder:
- `security_incidents_20250410_141645.xlsx` - Contains security incidents data
- `security_alerts_20250410_135652.xlsx` - Contains security alerts data

## How to Run

1. Open a command prompt
2. Navigate to the `Sentinel API test` folder
3. Run the script:
   ```
   python "04 Joint table\joint_incidents_alerts.py"
   ```

## Data Transformation

The script performs the following operations:
1. Loads incidents and alerts data from Excel files
2. Cleans the AlertIds field from incidents to remove brackets and quotes (e.g., converts `["8bd1ce07-0c69-db21-a728-e3700ba82671"]` to `8bd1ce07-0c69-db21-a728-e3700ba82671`)
3. Joins the data on the cleaned AlertId and SystemAlertId
4. Renames columns to match the KQL query format
5. Saves the result to a new Excel file in the `03 extracted data` folder

## Output

The output file will be saved in the `03 extracted data` folder with the name format:
`joined_incidents_alerts_YYYYMMDD_HHMMSS.xlsx`

## Troubleshooting

If you encounter issues:
1. Check if pandas and openpyxl are installed
2. Verify that the Excel files exist in the `03 extracted data` folder
3. Check permissions for reading/writing files 