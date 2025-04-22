import json
import requests
import sys

def normalize_domain(domain):
    """Normalize domain: lowercase, strip whitespace and trailing dots"""
    if not domain or not isinstance(domain, str):
        return None
    d = domain.strip().lower().rstrip('.')
    if '.' not in d or len(d.split('.')[-1]) < 2:
        return None
    return d

def extract_domains_from_entities(entities_json):
    """Extract domains from Entities JSON"""
    print(f"Extracting domains from: {entities_json}")
    
    domains = []
    
    try:
        # Parse entities
        if isinstance(entities_json, str):
            entities = json.loads(entities_json)
        else:
            entities = entities_json
            
        # Extract domains
        for entity in entities:
            if isinstance(entity, dict):
                if 'DomainName' in entity and entity['DomainName']:
                    normalized = normalize_domain(entity['DomainName'])
                    if normalized:
                        domains.append(normalized)
                        print(f"Found domain: {normalized}")
    
    except Exception as e:
        print(f"Error extracting domains: {str(e)}")
    
    return domains

def check_domain_reputation(domain):
    """Check domain reputation using VirusTotal API"""
    api_key = "0ffa3416da28d04b2aaa5eb121cfd1e7bad2cfdafe52f31b5fa2e4ea3a0bf01c"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    print(f"\nChecking VirusTotal reputation for: {domain}")
    
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ VirusTotal API request successful!")
            
            # Extract and display results
            attributes = data.get('data', {}).get('attributes', {})
            reputation = attributes.get('reputation', 0)
            stats = attributes.get('last_analysis_stats', {})
            categories = attributes.get('categories', {})
            
            print(f"\nDomain: {domain}")
            print(f"Reputation score: {reputation}")
            print(f"Analysis stats: {json.dumps(stats, indent=2)}")
            print(f"Categories: {json.dumps(categories, indent=2)}")
            
            # Calculate risk level
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            
            if malicious >= 3:
                risk = "HIGH RISK"
            elif malicious >= 1:
                risk = "MEDIUM RISK"
            elif suspicious > 0:
                risk = "LOW RISK"
            else:
                risk = "Clean"
                
            print(f"Risk assessment: {risk}")
            return True
            
        else:
            print(f"❌ API request failed: {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Error checking domain: {str(e)}")
        return False

def main():
    # Sample Entities JSON from the incident
    entities_json = '''[{"$id":"3","DomainName":"at-uat.myaspect.net","Type":"dns"},{"$id":"4","Address":"10.36.190.100","Type":"ip"},{"$id":"5","Address":"10.36.10.5","Type":"ip"}]'''
    
    print("=== Testing Domain Extraction and VirusTotal API ===\n")
    
    # Extract domains
    domains = extract_domains_from_entities(entities_json)
    
    if not domains:
        print("❌ No domains extracted from Entities!")
        sys.exit(1)
    
    # Check each domain with VirusTotal
    success = False
    for domain in domains:
        if check_domain_reputation(domain):
            success = True
    
    if success:
        print("\n✅ SUCCESS: Domain reputation checks completed!")
    else:
        print("\n❌ ERROR: Failed to check domain reputation!")

if __name__ == "__main__":
    main() 