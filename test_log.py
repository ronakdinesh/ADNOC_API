import pandas as pd
import os

# Define file path
excel_file = r"C:\Users\kpmgpov\Desktop\Sentinel API test\03 extracted data\joined_incidents_alerts_full_20250410_153241.xlsx"

# Check if file exists
if os.path.exists(excel_file):
    # Load the Excel file
    df = pd.read_excel(excel_file)
    
    # Print basic information about the data
    print(f"Successfully loaded Excel file: {excel_file}")
    print(f"Shape: {df.shape}")
    print("\nFirst 5 rows:")
    print(df.head())
    
    # Print column names
    print("\nColumns:")
    print(df.columns.tolist())
else:
    print(f"Error: File not found at {excel_file}") 

    # Get the total count of rows in the dataframe
    total_rows = len(df)
    print(f"\nTotal number of rows in the dataframe: {total_rows}")


    # Create a new dataframe with just the first 10 rows
    df_first_10 = df.head(10)
    
    # Print information about the new dataframe
    print("\nCreated a new dataframe with the first 10 rows")
    print(f"Shape of new dataframe: {df_first_10.shape}")
    print("\nFirst 10 rows:")
    print(df_first_10)


    # Get the column names from the df_first_10 dataframe
    first_10_columns = df_first_10.columns.tolist()
    
    # Print the column names
    print("\nColumns in df_first_10:")
    for i, column in enumerate(first_10_columns, 1):
        print(f"{i}. {column}")
    
    # Print the total number of columns
    print(f"\nTotal number of columns in df_first_10: {len(first_10_columns)}")

    # Extract domain names from the 'Alert_Entities' column
    print("\nExtracting domain names from Alert_Entities column...")
    
    # Check if 'Alert_Entities' column exists
    if 'Alert_Entities' in df.columns:
        # Function to extract domain names from Alert_Entities column
        def extract_domains(entities):
            try:
                if pd.isna(entities) or entities is None:
                    return None
                
                # If entities is already a dictionary or list
                if isinstance(entities, dict) or isinstance(entities, list):
                    entity_data = entities
                # If entities is a string, try to parse it as JSON
                elif isinstance(entities, str):
                    import json
                    try:
                        entity_data = json.loads(entities)
                    except json.JSONDecodeError:
                        return None
                else:
                    return None
                
                # Handle different possible structures
                domains = []
                
                # If entity_data is a list
                if isinstance(entity_data, list):
                    for entity in entity_data:
                        if isinstance(entity, dict):
                            # Check for domain-related fields
                            if 'DomainName' in entity:
                                domains.append(entity['DomainName'])
                            elif 'Fqdn' in entity:
                                domains.append(entity['Fqdn'])
                            elif 'HostName' in entity:
                                domains.append(entity['HostName'])
                            elif 'Url' in entity and entity.get('Url'):
                                from urllib.parse import urlparse
                                try:
                                    parsed_url = urlparse(entity['Url'])
                                    if parsed_url.netloc:
                                        domains.append(parsed_url.netloc)
                                except:
                                    pass
                
                # If entity_data is a dictionary
                elif isinstance(entity_data, dict):
                    if 'DomainName' in entity_data:
                        domains.append(entity_data['DomainName'])
                    elif 'Fqdn' in entity_data:
                        domains.append(entity_data['Fqdn'])
                    elif 'HostName' in entity_data:
                        domains.append(entity_data['HostName'])
                    elif 'Url' in entity_data and entity_data.get('Url'):
                        from urllib.parse import urlparse
                        try:
                            parsed_url = urlparse(entity_data['Url'])
                            if parsed_url.netloc:
                                domains.append(parsed_url.netloc)
                        except:
                            pass
                
                # Return comma-separated domains if found, otherwise None
                return ', '.join(domains) if domains else None
            
            except Exception as e:
                print(f"Error extracting domains: {e}")
                return None
        
        # Apply the function to create a new 'Domain' column
        df['Domain'] = df['Alert_Entities'].apply(extract_domains)
        
        # Count non-null values in the new column
        domain_count = df['Domain'].count()
        print(f"Successfully extracted domains. Found domains in {domain_count} out of {len(df)} rows.")
        
        # Show a sample of the extracted domains
        print("\nSample of extracted domains:")
        domain_sample = df[['Alert_Entities', 'Domain']].head(5)
        print(domain_sample)
    else:
        print("Error: 'Alert_Entities' column not found in the dataframe.")

df_first_10['DomainName'] = df_first_10['Alert_Entities'].apply(extract_domains)

df_first_10['DomainName']
