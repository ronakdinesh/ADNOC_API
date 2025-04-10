import requests
import json
import logging
from typing import Dict, Optional

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VirusTotalAPI:
    def __init__(self):
        self.api_key = "0ffa3416da28d04b2aaa5eb121cfd1e7bad2cfdafe52f31b5fa2e4ea3a0bf01c"
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }

    def get_url_report(self, domain: str) -> Optional[Dict]:
        """
        Get VirusTotal report for a URL/domain
        
        Args:
            domain: Domain/URL to analyze
            
        Returns:
            Dict containing the analysis results or None if error
        """
        try:
            # Submit URL for scanning
            scan_endpoint = f"{self.base_url}/urls"
            data = {
                "url": domain
            }
            response = requests.post(scan_endpoint, headers=self.headers, data=data)
            response.raise_for_status()
            
            # Extract analysis ID from response
            analysis_id = response.json()["data"]["id"]
            
            # Get analysis results
            analysis_endpoint = f"{self.base_url}/analyses/{analysis_id}"
            analysis = requests.get(analysis_endpoint, headers=self.headers)
            analysis.raise_for_status()
            
            return analysis.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error getting URL report: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return None

def check_domain_reputation(domain: str) -> Optional[Dict]:
    """Check domain reputation using VirusTotal API."""
    try:
        vt = VirusTotalAPI()
        url = f"{vt.base_url}/domains/{domain}"
        
        logger.info(f"Checking domain: {domain}")
        logger.info(f"URL: {url}")
        
        response = requests.get(url, headers=vt.headers)
        logger.info(f"Response status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            logger.info("Successfully got response from VirusTotal")
            
            last_analysis_stats = data['data']['attributes'].get('last_analysis_stats', {})
            result = {
                'reputation': data['data']['attributes'].get('reputation', 0),
                'malicious_votes': last_analysis_stats.get('malicious', 0),
                'suspicious_votes': last_analysis_stats.get('suspicious', 0),
                'clean_votes': last_analysis_stats.get('clean', 0),
                'detection_engines': sum(last_analysis_stats.values())
            }
            logger.info(f"Parsed result: {result}")
            return result
            
        logger.error(f"Error response from VirusTotal: {response.status_code}")
        if response.status_code == 401:
            logger.error("Authentication error - check API key")
        return None
    except Exception as e:
        logger.error(f"Error checking domain reputation: {str(e)}")
        return None

def main():
    vt = VirusTotalAPI()
    
    while True:
        domain = input("\nEnter domain to analyze (or 'quit' to exit): ")
        if domain.lower() == 'quit':
            break
            
        results = vt.get_url_report(domain)
        if results:
            print(json.dumps(results, indent=2))
        else:
            print("Error getting results")

if __name__ == "__main__":
    main()
