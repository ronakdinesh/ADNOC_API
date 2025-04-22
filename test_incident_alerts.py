import json
import sys
import os
sys.path.append('02 AI Agent API')  # Add the directory to path

try:
    from virustotal_integration import analyze_domains, format_vt_results
    VIRUSTOTAL_AVAILABLE = True
except ImportError:
    print("Failed to import VirusTotal integration")
    VIRUSTOTAL_AVAILABLE = False

# Import the domain extraction function
from llm_read_security_incidents import extract_domains_from_alerts

def test_incident_investigation():
    """
    Test the incident investigation process using the provided entity data
    """
    print("=" * 80)
    print("TEST INCIDENT INVESTIGATION WITH VIRUSTOTAL INTEGRATION")
    print("=" * 80)
    
    # Simulate an alert with our entity data
    alert_with_entities = {
        'SystemAlertId': '7f2823fe-596d-b965-fba4-914401a0493c',
        'AlertName': 'Test Alert for VirusTotal Integration',
        'Entities': '''[{"$id":"3","DomainName":"at-uat.myaspect.net","Type":"dns"},{"$id":"4","Address":"10.36.190.100","Type":"ip"},{"$id":"5","Address":"10.36.10.5","Type":"ip"}]'''
    }
    
    # Create a list of alerts
    alerts = [alert_with_entities]
    
    # 1. Extract domains from alert entities
    print("\n1. EXTRACTING DOMAINS FROM ALERT ENTITIES...")
    domains = extract_domains_from_alerts(alerts)
    
    if not domains:
        print("\nERROR: No domains extracted from alert entities!")
        return False
    
    print(f"\nSuccessfully extracted {len(domains)} domains: {domains}")
    
    # 2. Check domain reputation with VirusTotal
    if VIRUSTOTAL_AVAILABLE:
        print("\n2. CHECKING DOMAIN REPUTATION WITH VIRUSTOTAL...")
        try:
            vt_results = analyze_domains(domains)
            print(f"VirusTotal analysis complete. Found results for {len(vt_results)} domain(s).")
            
            # Format VirusTotal results
            if vt_results:
                formatted_results = format_vt_results(vt_results)
                print("\n" + formatted_results)
            else:
                print("\nNo suspicious domains found in VirusTotal.")
                
            return True
        except Exception as e:
            print(f"\nError checking domains with VirusTotal: {str(e)}")
            return False
    else:
        print("\nVirusTotal integration not available. Domain reputation checks skipped.")
        return False

if __name__ == "__main__":
    # Run the test
    success = test_incident_investigation()
    
    if success:
        print("\n✅ TEST PASSED: Domain extraction and VirusTotal integration worked!")
        sys.exit(0)
    else:
        print("\n❌ TEST FAILED: Domain extraction or VirusTotal integration failed!")
        sys.exit(1) 