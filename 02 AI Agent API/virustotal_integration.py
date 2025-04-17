import requests
import json
import logging
from typing import Dict, Optional, List
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VirusTotalAPI:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY") or "0ffa3416da28d04b2aaa5eb121cfd1e7bad2cfdafe52f31b5fa2e4ea3a0bf01c"
        if not self.api_key:
            raise ValueError("VirusTotal API key not set. Please set the VIRUSTOTAL_API_KEY environment variable or use the hardcoded key.")
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

    def check_domain_reputation(self, domain: str) -> Optional[Dict]:
        """Check domain reputation using VirusTotal API."""
        try:
            url = f"{self.base_url}/domains/{domain}"
            
            logger.info(f"Checking domain: {domain}")
            
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                data = response.json()
                logger.info("Successfully got response from VirusTotal")
                
                last_analysis_stats = data['data']['attributes'].get('last_analysis_stats', {})
                result = {
                    'domain': domain,
                    'reputation': data['data']['attributes'].get('reputation', 0),
                    'malicious_votes': last_analysis_stats.get('malicious', 0),
                    'suspicious_votes': last_analysis_stats.get('suspicious', 0),
                    'clean_votes': last_analysis_stats.get('clean', 0),
                    'detection_engines': sum(last_analysis_stats.values()),
                    'categories': data['data']['attributes'].get('categories', {})
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


def analyze_domains(domains: List[str]) -> Dict[str, Dict]:
    """
    Analyze a list of domains with VirusTotal
    
    Args:
        domains: List of domains to analyze
        
    Returns:
        Dictionary mapping domains to their analysis results
    """
    results = {}
    vt = VirusTotalAPI()
    
    for domain in domains:
        if not domain:
            continue
            
        # Skip common benign domains and likely false positives
        if any(domain.endswith(suffix) for suffix in ['.microsoft.com', '.windows.com', '.office.com', '.azure.com', '.local']):
            continue
            
        # Skip Microsoft service domains that aren't actually web domains (like Microsoft.OperationalInsights)
        if domain.startswith('Microsoft.'):
            logger.info(f"Skipping Microsoft service name (not a web domain): {domain}")
            continue
            
        # Check if domain is an IP address - these need different handling
        if all(c.isdigit() or c == '.' for c in domain):
            continue
            
        # Validate domain format - must have at least one dot and valid TLD
        parts = domain.split('.')
        if len(parts) < 2 or len(parts[-1]) < 2:
            logger.info(f"Skipping invalid domain format: {domain}")
            continue
            
        try:
            result = vt.check_domain_reputation(domain)
            if result:
                results[domain] = result
        except Exception as e:
            logger.error(f"Error analyzing domain {domain}: {str(e)}")
    
    return results


def format_vt_results(results: Dict[str, Dict]) -> str:
    """Format VirusTotal results into a clear, concise per-domain reputation summary for the report"""
    if not results:
        return "No domains analyzed or no results found."
    
    lines = ["VIRUSTOTAL DOMAIN REPUTATION:", "----------------------------"]
    
    for domain, data in results.items():
        malicious_score = data.get('malicious_votes', 0)
        suspicious_score = data.get('suspicious_votes', 0)
        clean_score = data.get('clean_votes', 0)
        total_engines = data.get('detection_engines', 0)
        reputation = data.get('reputation', 0)
        
        risk_level = "Unknown"
        if malicious_score > 0:
            if malicious_score >= 3:
                risk_level = "HIGH RISK"
            elif malicious_score >= 1:
                risk_level = "MEDIUM RISK"
        elif suspicious_score > 0:
            risk_level = "LOW RISK"
        else:
            risk_level = "Clean"
        
        categories = data.get('categories', {})
        category_str = ", ".join(set([str(category) for category in categories.values()]))
        
        # Compose the summary line
        line = f"{domain}: {risk_level} ({malicious_score}/{total_engines} malicious, {suspicious_score} suspicious, {clean_score} clean) | Reputation: {reputation}"
        if category_str:
            line += f" | Categories: {category_str}"
        lines.append(line)
    
    return "\n".join(lines)


if __name__ == "__main__":
    # Test functionality
    test_domains = ["example.com", "google.com", "malware.wicar.org"]
    results = analyze_domains(test_domains)
    print(format_vt_results(results)) 