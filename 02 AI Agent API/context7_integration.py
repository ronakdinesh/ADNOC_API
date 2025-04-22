"""
Context7 Integration for Security Framework Documentation

This module provides integration with Context7 for retrieving security documentation
and best practices from various frameworks like MITRE ATT&CK, OWASP, NIST, and others.
It can be used to enrich security incident reports with relevant framework guidance.
"""

import os
import json
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime

from pydantic import BaseModel, Field


class SecurityDocumentation(BaseModel):
    """Model for security documentation retrieved from Context7"""
    title: str = Field(description="Title of the documentation")
    content: str = Field(description="Content of the documentation")
    source: str = Field(description="Source framework (MITRE, OWASP, etc.)")
    last_updated: Optional[datetime] = Field(description="Last update timestamp", default=None)


class Context7Integration:
    """Integration with Context7 for retrieving security documentation"""
    
    def __init__(self):
        self.initialized = False
        self.libraries = {
            "owasp": None,
            "mitre-attack": None,
            "nist": None
        }
    
    async def initialize(self):
        """Initialize the Context7 integration by resolving library IDs"""
        if self.initialized:
            return
        
        # In a real implementation, this would call the resolve-library-id function
        # For now, we'll simulate the library IDs
        self.libraries = {
            "owasp": "owasp/top10-2021",
            "mitre-attack": "mitre/attack-enterprise",
            "nist": "nist/cybersecurity-framework"
        }
        
        self.initialized = True
        return self.libraries
    
    async def get_library_documentation(self, library_id: str, topic: Optional[str] = None) -> str:
        """Get documentation from a specific library with optional topic filter"""
        # In a real implementation, this would call the get-library-docs function
        # For now, we'll return hardcoded responses
        
        if "owasp" in library_id.lower():
            if topic and "injection" in topic.lower():
                return """
                OWASP Top 10 - A03:2021 Injection
                
                Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query.
                Attackers can use injection flaws to execute malicious commands or access data without authorization.
                
                Prevention measures:
                1. Use parameterized queries for database access
                2. Input validation and sanitization
                3. Prepared statements with parameterized queries
                4. Escape special characters based on the interpreter
                5. Implement proper error handling to prevent information disclosure
                
                For more details: https://owasp.org/Top10/A03_2021-Injection/
                """
            elif topic and "broken" in topic.lower() and "auth" in topic.lower():
                return """
                OWASP Top 10 - A07:2021 Identification and Authentication Failures
                
                Authentication failures can allow attackers to assume other users' identities temporarily or permanently.
                
                Prevention measures:
                1. Implement multi-factor authentication
                2. Do not deploy with default credentials
                3. Implement weak-password checks
                4. Implement proper password recovery mechanisms
                5. Use server-side session management with secure session IDs
                
                For more details: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
                """
            else:
                return """
                OWASP Top 10 - 2021
                
                The OWASP Top 10 is a standard awareness document for developers and web application security. 
                It represents a broad consensus about the most critical security risks to web applications.
                
                Top risks include:
                1. Broken Access Control
                2. Cryptographic Failures
                3. Injection
                4. Insecure Design
                5. Security Misconfiguration
                
                For more details: https://owasp.org/Top10/
                """
                
        elif "mitre" in library_id.lower():
            if topic and "credential" in topic.lower():
                return """
                MITRE ATT&CK - Credential Access
                
                Credential Access consists of techniques for stealing credentials like account names and passwords.
                
                Common techniques:
                - T1110: Brute Force
                - T1555: Credentials from Password Stores
                - T1556: Modify Authentication Process
                - T1539: Steal Web Session Cookie
                - T1003: OS Credential Dumping
                
                Mitigation strategies:
                1. Implement multi-factor authentication
                2. Use password managers with strong, unique passwords
                3. Audit credential access and password policies
                4. Secure credential storage with encryption
                5. Implement account lockouts after failed attempts
                
                For more details: https://attack.mitre.org/tactics/TA0006/
                """
            elif topic and "lateral" in topic.lower():
                return """
                MITRE ATT&CK - Lateral Movement
                
                Lateral Movement consists of techniques that enable adversaries to access and control remote systems.
                
                Common techniques:
                - T1021: Remote Services
                - T1091: Replication Through Removable Media
                - T1570: Lateral Tool Transfer
                - T1563: Remote Service Session Hijacking
                - T1550: Use Alternate Authentication Material
                
                Mitigation strategies:
                1. Network segmentation and Zero Trust architecture
                2. Restrict remote service access
                3. Monitor for unusual authentication events
                4. Implement principle of least privilege
                5. Use jump servers for administrative access
                
                For more details: https://attack.mitre.org/tactics/TA0008/
                """
            elif topic and ("dns" in topic.lower() or "domain" in topic.lower()):
                return """
                MITRE ATT&CK - Command and Control: DNS
                
                Adversaries may use the Domain Name System (DNS) for command and control communications.
                
                Relevant Techniques:
                - T1071.004: Application Layer Protocol: DNS
                - T1568.002: Dynamic Resolution: Domain Generation Algorithms
                - T1573.001: Encrypted Channel: Symmetric Cryptography
                
                Detection strategies:
                1. Monitor for suspicious DNS traffic patterns (high volumes, unusual domains)
                2. Look for long DNS request strings that may contain encoded data
                3. Analyze DNS request timing and frequency
                4. Monitor for DNS requests to newly registered or uncommon TLDs
                5. Deploy DNS security monitoring tools
                
                For more details: https://attack.mitre.org/techniques/T1071/004/
                """
            else:
                return """
                MITRE ATT&CK Framework
                
                MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on 
                real-world observations. It provides a common language for describing attacker behaviors.
                
                The framework consists of:
                - 14 Tactics (the why of an attack technique)
                - 185+ Techniques (the how of an attack)
                - 367+ Sub-techniques (specific implementations)
                
                For more details: https://attack.mitre.org/
                """
                
        elif "nist" in library_id.lower():
            return """
            NIST Cybersecurity Framework
            
            The NIST Cybersecurity Framework provides a policy framework of computer security guidance for
            organizations to assess and improve their ability to prevent, detect, and respond to cyber attacks.
            
            The framework consists of five core functions:
            1. IDENTIFY: Develop an organizational understanding to manage cybersecurity risk
            2. PROTECT: Develop safeguards to ensure delivery of critical services
            3. DETECT: Develop activities to identify occurrence of cybersecurity events
            4. RESPOND: Develop activities to take action regarding detected cybersecurity incidents
            5. RECOVER: Develop activities to maintain resilience and restore capabilities
            
            For more details: https://www.nist.gov/cyberframework
            """
        
        return "Documentation not available for the requested library."
    
    async def get_documentation(self, topic: str) -> Dict[str, str]:
        """Retrieve documentation based on the incident topic"""
        
        if not self.initialized:
            await self.initialize()
        
        result = {
            "framework_guidance": "",
            "mitre_guidance": "",
            "owasp_guidance": "",
            "nist_guidance": ""
        }
        
        # Determine which documentation to fetch based on topic
        
        # MITRE ATT&CK documentation
        if any(keyword in topic.lower() for keyword in ["dns", "domain", "c2", "command", "control"]):
            mitre_docs = await self.get_library_documentation(
                self.libraries["mitre-attack"], 
                "dns domain"
            )
            result["mitre_guidance"] = mitre_docs
            
        elif any(keyword in topic.lower() for keyword in ["credential", "password", "authentication"]):
            mitre_docs = await self.get_library_documentation(
                self.libraries["mitre-attack"], 
                "credential access"
            )
            result["mitre_guidance"] = mitre_docs
            
        elif any(keyword in topic.lower() for keyword in ["lateral", "movement", "pivot"]):
            mitre_docs = await self.get_library_documentation(
                self.libraries["mitre-attack"], 
                "lateral movement"
            )
            result["mitre_guidance"] = mitre_docs
            
        # OWASP documentation
        if any(keyword in topic.lower() for keyword in ["injection", "sql", "command"]):
            owasp_docs = await self.get_library_documentation(
                self.libraries["owasp"], 
                "injection"
            )
            result["owasp_guidance"] = owasp_docs
            
        elif any(keyword in topic.lower() for keyword in ["authentication", "login", "credential"]):
            owasp_docs = await self.get_library_documentation(
                self.libraries["owasp"], 
                "broken authentication"
            )
            result["owasp_guidance"] = owasp_docs
            
        # NIST guidance is general and applicable to most incidents
        nist_docs = await self.get_library_documentation(self.libraries["nist"])
        result["nist_guidance"] = nist_docs
        
        # Get general MITRE guidance if no specific match
        if not result["mitre_guidance"]:
            mitre_docs = await self.get_library_documentation(self.libraries["mitre-attack"])
            result["mitre_guidance"] = mitre_docs
            
        # Compile framework guidance
        if result["owasp_guidance"]:
            result["framework_guidance"] += "OWASP GUIDANCE:\n" + result["owasp_guidance"] + "\n\n"
            
        if result["nist_guidance"]:
            result["framework_guidance"] += "NIST GUIDANCE:\n" + result["nist_guidance"]
            
        return result


async def test_context7_integration():
    """Test the Context7 integration"""
    integration = Context7Integration()
    await integration.initialize()
    
    print("Context7 integration initialized with libraries:")
    print(integration.libraries)
    
    # Test getting documentation for different topics
    dns_docs = await integration.get_documentation("dns attack")
    print("\nDNS Attack Documentation:")
    print(f"Framework guidance length: {len(dns_docs['framework_guidance'])}")
    print(f"MITRE guidance length: {len(dns_docs['mitre_guidance'])}")
    
    malware_docs = await integration.get_documentation("malware incident")
    print("\nMalware Incident Documentation:")
    print(f"Framework guidance length: {len(malware_docs['framework_guidance'])}")
    print(f"MITRE guidance length: {len(malware_docs['mitre_guidance'])}")


if __name__ == "__main__":
    asyncio.run(test_context7_integration()) 