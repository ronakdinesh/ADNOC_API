import requests
import json

def test_virustotal_api():
    """Test the VirusTotal API with the provided key"""
    api_key = "0ffa3416da28d04b2aaa5eb121cfd1e7bad2cfdafe52f31b5fa2e4ea3a0bf01c"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    # Test domain to check
    test_domain = "google.com"
    
    print(f"Testing VirusTotal API with domain: {test_domain}")
    print(f"Using API key: {api_key[:4]}...{api_key[-4:]}")
    
    try:
        # API endpoint for domain reports
        url = f"https://www.virustotal.com/api/v3/domains/{test_domain}"
        
        # Make the request
        response = requests.get(url, headers=headers)
        
        # Check the response
        if response.status_code == 200:
            data = response.json()
            print("\n✅ SUCCESS! API key is working.")
            print(f"Response status code: {response.status_code}")
            
            # Extract reputation data
            attributes = data.get('data', {}).get('attributes', {})
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            reputation = attributes.get('reputation', 0)
            
            print("\nDomain Reputation Results:")
            print(f"Reputation score: {reputation}")
            print(f"Analysis stats: {json.dumps(last_analysis_stats, indent=2)}")
            
            return True
        else:
            print(f"\n❌ ERROR: API request failed with status code: {response.status_code}")
            print(f"Response body: {response.text}")
            
            if response.status_code == 401:
                print("\nThe API key appears to be invalid or expired.")
            elif response.status_code == 403:
                print("\nAccess forbidden. Your API key may not have sufficient permissions.")
            elif response.status_code == 429:
                print("\nRate limit exceeded. Free API tier is limited to 4 requests per minute.")
                
            return False
            
    except Exception as e:
        print(f"\n❌ ERROR: {str(e)}")
        print("\nThis could be due to network issues or firewall restrictions.")
        return False

if __name__ == "__main__":
    print("======= VirusTotal API Test =======")
    test_virustotal_api()
    print("==================================") 