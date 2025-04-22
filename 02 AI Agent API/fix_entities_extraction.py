import json
import sys
import ast
from typing import Dict, List, Any, Optional
import requests

# API key for VirusTotal
API_KEY = "0ffa3416da28d04b2aaa5eb121cfd1e7bad2cfdafe52f31b5fa2e4ea3a0bf01c"

def extract_domains_from_entities(entities_data):
    """
    Extract domains from alert entities with robust parsing
    
    Args:
        entities_data: The Entities data (could be string JSON, Python dict, or list)
        
    Returns:
        list: List of unique domains
    """
    # Helper: normalise and validate domains
    def _normalise(domain):
        if not domain or not isinstance(domain, str):
            return None
        d = domain.strip().lower().rstrip('.')  # strip space / trailing dot
        # Very small sanity check: must contain a dot and at least 2‑char TLD
        if '.' not in d:
            return None
        if len(d.split('.')[-1]) < 2:
            return None
        return d
    
    domains = []
    print(f"Input data type: {type(entities_data)}")
    
    if not entities_data:
        print("No entities data provided")
        return []
    
    try:
        # Parse the entities data based on its type
        entities = None
        
        if isinstance(entities_data, list):
            # Already a list
            entities = entities_data
        elif isinstance(entities_data, str):
            # Try several parsing methods
            try:
                # First try JSON
                print("Trying JSON parse...")
                entities = json.loads(entities_data)
                print(f"JSON parse succeeded: {entities}")
            except json.JSONDecodeError:
                try:
                    # Then try Python literal eval (for single quotes)
                    print("Trying literal_eval...")
                    entities = ast.literal_eval(entities_data)
                    print(f"literal_eval succeeded: {entities}")
                except (SyntaxError, ValueError):
                    # Finally try regex extraction
                    print("Using regex extraction...")
                    import re
                    domain_matches = re.findall(r'DomainName":\s*"([^"]+)"', entities_data)
                    print(f"Regex found domains: {domain_matches}")
                    for domain in domain_matches:
                        dom = _normalise(domain)
                        if dom:
                            domains.append(dom)
        else:
            print(f"Unexpected entities data type: {type(entities_data)}")
            return []
            
        # Process structured entities list
        if entities and isinstance(entities, list):
            from urllib.parse import urlparse
            for entity in entities:
                if isinstance(entity, dict):
                    # Check all the possible domain fields
                    possible_values = [
                        entity.get('DomainName'),
                        entity.get('Fqdn'),
                        entity.get('HostName'),
                        entity.get('Host')
                    ]
                    
                    # Parse Url field separately
                    if 'Url' in entity and entity['Url']:
                        try:
                            parsed = urlparse(entity['Url'])
                            if parsed.netloc:
                                possible_values.append(parsed.netloc)
                        except Exception:
                            pass
                    
                    # Normalize and add all valid domains
                    for val in possible_values:
                        normalized = _normalise(val)
                        if normalized:
                            print(f"Found domain: {normalized}")
                            domains.append(normalized)
    
    except Exception as e:
        print(f"Error extracting domains: {str(e)}")
    
    # Filter out common benign Microsoft domains
    benign_suffixes = ('.microsoft.com', '.windows.com', '.office.com')
    filtered = [d for d in domains if d and not d.startswith('microsoft.') and not any(d.endswith(sfx) for sfx in benign_suffixes)]
    
    # De‑duplicate & return
    unique_domains = list(set(filtered))
    print(f"Extracted unique domains: {unique_domains}")
    return unique_domains

def check_domain_reputation(domain: str) -> Optional[Dict]:
    """Check domain reputation using VirusTotal API"""
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {
            "accept": "application/json",
            "x-apikey": API_KEY
        }
        
        print(f"Checking domain: {domain}")
        
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            
            # Extract reputation data
            attributes = data['data']['attributes']
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            result = {
                'domain': domain,
                'reputation': attributes.get('reputation', 0),
                'malicious_votes': last_analysis_stats.get('malicious', 0),
                'suspicious_votes': last_analysis_stats.get('suspicious', 0),
                'clean_votes': last_analysis_stats.get('harmless', 0),
                'detection_engines': sum(last_analysis_stats.values()),
                'categories': attributes.get('categories', {})
            }
            
            print(f"Domain: {domain}")
            print(f"  Reputation: {result['reputation']}")
            print(f"  Malicious: {result['malicious_votes']}")
            print(f"  Suspicious: {result['suspicious_votes']}")
            print(f"  Clean: {result['clean_votes']}")
            
            return result
                
        print(f"Error response from VirusTotal: {response.status_code}")
        return None
    except Exception as e:
        print(f"Error checking domain reputation: {str(e)}")
        return None

def format_vt_results(results: Dict[str, Dict]) -> str:
    """Format VirusTotal results for display"""
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

def test_with_example_entities():
    """Test the domain extraction and VirusTotal API with example Entities"""
    # Example from the incident
    entities_str = '''[{"$id":"3","DomainName":"at-uat.myaspect.net","Type":"dns"},{"$id":"4","Address":"10.36.190.100","Type":"ip"},{"$id":"5","Address":"10.36.10.5","Type":"ip"}]'''
    
    print("=" * 60)
    print("TESTING DOMAIN EXTRACTION AND VIRUSTOTAL API")
    print("=" * 60)
    
    # Extract domains
    print("\nEXTRACTING DOMAINS FROM ENTITIES...")
    domains = extract_domains_from_entities(entities_str)
    
    if not domains:
        print("ERROR: No domains found in the Entities!")
        return
    
    # Check domain reputation
    print("\nCHECKING DOMAIN REPUTATION...")
    results = {}
    for domain in domains:
        result = check_domain_reputation(domain)
        if result:
            results[domain] = result
    
    # Format results
    print("\nVIRUSTOTAL RESULTS:")
    formatted_results = format_vt_results(results)
    print(formatted_results)
    
    print("\n" + "=" * 60)
    print(f"Test complete - found {len(domains)} domains, received {len(results)} VirusTotal results")
    print("=" * 60)

if __name__ == "__main__":
    test_with_example_entities() 