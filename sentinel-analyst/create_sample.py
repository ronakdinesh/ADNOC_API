import pandas as pd

# Create sample data
df = pd.DataFrame({
    'IncidentNumber': ['INC001'],
    'TenantId': ['TENANT1'],
    'Status': ['New'],
    'Severity': ['High'],
    'LastModifiedTime': ['2023-04-15 12:00:00'],
    'Owner': ['Security Analyst'],
    'Comments': ['Suspicious activity detected from IP 192.168.1.100 to domain malicious.example.com']
})

# Save to Excel file
df.to_excel('03 extracted data/data_15aprl/security_incidents_20250415_124725.xlsx', index=False)

print("Sample data file created successfully!") 