#!/usr/bin/env python3
"""
Web Vulnerability Scanner - OWASP Top 10 compliant
Lightweight Python CLI scanner for security headers, SQL injection, and open redirects
"""

import argparse
import json
import sys
import re
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import Dict, List, Tuple, Optional

import requests
from colorama import init, Fore, Style, Back

# Initialize colorama for cross-platform colored output
init(autoreset=True)


class WebVulnerabilityScanner:
    """Main scanner class that handles all vulnerability checks"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip('/')
        self.timestamp = datetime.now().isoformat()
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WebVulnScanner/1.0 (Security Tool)'
        })
    
    def print_header(self):
        """Display scanner header with target information"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}🔒 Web Vulnerability Scanner - OWASP Top 10")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}📡 Target: {Fore.WHITE}{self.target_url}")
        print(f"{Fore.YELLOW}🕐 Time: {Fore.WHITE}{self.timestamp}")
        print(f"{Fore.CYAN}{'='*60}\n")
    
    def add_finding(self, name: str, severity: str, owasp_category: str, 
                    description: str, remediation: str, evidence: str = ""):
        """Add a vulnerability finding to the report"""
        finding = {
            "name": name,
            "severity": severity.upper(),
            "owasp_category": owasp_category,
            "description": description,
            "remediation": remediation,
            "evidence": evidence,
            "timestamp": self.timestamp,
            "url": self.target_url
        }
        self.findings.append(finding)
        
        # Color-coded console output
        if severity.lower() == "critical":
            print(f"{Fore.RED}❌ CRITICAL: {name}")
        elif severity.lower() == "high":
            print(f"{Fore.RED}⚠️  HIGH: {name}")
        elif severity.lower() == "medium":
            print(f"{Fore.YELLOW}⚠️  MEDIUM: {name}")
        else:
            print(f"{Fore.YELLOW}ℹ️  INFO: {name}")
        
        print(f"   {description}")
        print(f"   {Fore.CYAN}🔧 Remediation: {remediation}\n")
    
    # ============ STEP 2: Security Headers Check ============
    
    def check_security_headers(self):
        """Check for missing OWASP recommended security headers"""
        print(f"{Fore.MAGENTA}[*] Checking security headers...")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers
            
            # Define required headers with their OWASP categories and remediation
            required_headers = {
                "X-Content-Type-Options": {
                    "value": "nosniff",
                    "owasp": "A05:2021 - Security Misconfiguration",
                    "remediation": "Add 'X-Content-Type-Options: nosniff' to prevent MIME type sniffing"
                },
                "X-Frame-Options": {
                    "value": ["DENY", "SAMEORIGIN"],
                    "owasp": "A05:2021 - Security Misconfiguration", 
                    "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking"
                },
                "Content-Security-Policy": {
                    "value": None,
                    "owasp": "A05:2021 - Security Misconfiguration",
                    "remediation": "Implement CSP header to prevent XSS and data injection attacks"
                },
                "Strict-Transport-Security": {
                    "value": None,
                    "owasp": "A05:2021 - Security Misconfiguration",
                    "remediation": "Add HSTS header to enforce HTTPS connections"
                }
            }
            
            missing_headers = []
            for header, info in required_headers.items():
                if header not in headers:
                    missing_headers.append(header)
                    self.add_finding(
                        name=f"Missing Security Header: {header}",
                        severity="Medium",
                        owasp_category=info["owasp"],
                        description=f"Security header '{header}' is not present in HTTP response",
                        remediation=info["remediation"]
                    )
            
            if not missing_headers:
                print(f"{Fore.GREEN}✓ All security headers present\n")
            
        except requests.RequestException as e:
            print(f"{Fore.RED}⚠️  Could not fetch headers: {e}\n")
    
    # ============ STEP 3: SQL Injection Detection ============
    
    def extract_parameters(self) -> List[Tuple[str, str]]:
        """Extract URL parameters from target URL"""
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        
        # Return list of (param_name, param_value) tuples
        param_list = []
        for key, values in params.items():
            if values:
                param_list.append((key, values[0]))
        return param_list
    
    def test_sql_injection(self, url: str, param: str, original_value: str) -> Dict:
        """Test a single parameter for SQL injection vulnerabilities"""
        findings = []
        
        # SQL injection payloads
        payloads = [
            ("' OR '1'='1", "Basic tautology"),
            ("' OR '1'='1' --", "MySQL comment"),
            ("1; DROP TABLE users", "Destructive payload"),
            ("' UNION SELECT NULL--", "Union-based"),
            ("admin' --", "Auth bypass"),
            ("1' AND '1'='1", "AND condition"),
            ("' OR 1=1#", "Hash comment")
        ]
        
        # SQL error keywords to detect
        error_keywords = [
            "sql", "syntax", "mysql", "oracle", "postgresql",
            "microsoft access", "sql server", "database error",
            "unclosed quotation", "mysql_fetch", "ora-", "pls-",
            "division by zero", "sqlstate", "sql syntax"
        ]
        
        for payload, description in payloads:
            # Build test URL
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param] = [payload]
            new_query = urlencode(params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))
            
            try:
                response = self.session.get(test_url, timeout=10)
                response_lower = response.text.lower()
                
                # Check for SQL errors in response
                for keyword in error_keywords:
                    if keyword in response_lower:
                        return {
                            "vulnerable": True,
                            "payload": payload,
                            "keyword": keyword,
                            "description": description
                        }
                
                # Check for content length differences (basic boolean detection)
                normal_response = self.session.get(url, timeout=10)
                if abs(len(response.text) - len(normal_response.text)) > 200:
                    if "error" not in response_lower and "exception" not in response_lower:
                        return {
                            "vulnerable": True,
                            "payload": payload,
                            "keyword": "significant_content_change",
                            "description": description
                        }
                        
            except requests.RequestException:
                continue
        
        return {"vulnerable": False}
    
    def check_sql_injection(self):
        """Main SQL injection detection routine"""
        print(f"{Fore.MAGENTA}[*] Checking for SQL injection vulnerabilities...")
        
        params = self.extract_parameters()
        
        if not params:
            print(f"{Fore.YELLOW}⚠️  No URL parameters found to test\n")
            return
        
        for param, value in params:
            print(f"   Testing parameter: {param}")
            result = self.test_sql_injection(self.target_url, param, value)
            
            if result["vulnerable"]:
                self.add_finding(
                    name=f"SQL Injection in parameter '{param}'",
                    severity="Critical",
                    owasp_category="A03:2021 - Injection",
                    description=f"Parameter '{param}' is vulnerable to SQL injection",
                    remediation="Use parameterized queries/prepared statements and input validation",
                    evidence=f"Payload: {result['payload']} - Triggered keyword: {result['keyword']}"
                )
            else:
                print(f"{Fore.GREEN}   ✓ Parameter '{param}' appears safe")
        
        print()
    
    # ============ STEP 4: Open Redirect Detection ============
    
    def check_open_redirect(self):
        """Check for open redirect vulnerabilities in URL parameters"""
        print(f"{Fore.MAGENTA}[*] Checking for open redirect vulnerabilities...")
        
        # Common redirect parameter names
        redirect_params = ['redirect', 'url', 'next', 'return', 'return_to', 
                          'redirect_uri', 'redirect_url', 'callback', 'goto', 
                          'dest', 'destination', 'out', 'view', 'redir']
        
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        
        malicious_url = "https://evil.com"
        encoded_malicious = "https%3A//evil.com"
        
        vulnerable_params = []
        
        for param in redirect_params:
            if param in params:
                # Test with regular URL
                test_params = params.copy()
                test_params[param] = [malicious_url]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                
                try:
                    # Don't follow redirects to see the Location header
                    response = self.session.get(test_url, timeout=10, allow_redirects=False)
                    
                    # Check if redirect Location header points to evil.com
                    if 'location' in response.headers:
                        location = response.headers['location'].lower()
                        if 'evil.com' in location:
                            vulnerable_params.append(param)
                            
                except requests.RequestException:
                    pass
                
                # Test with encoded URL
                test_params_encoded = params.copy()
                test_params_encoded[param] = [encoded_malicious]
                new_query_encoded = urlencode(test_params_encoded, doseq=True)
                test_url_encoded = urlunparse(parsed._replace(query=new_query_encoded))
                
                try:
                    response = self.session.get(test_url_encoded, timeout=10, allow_redirects=False)
                    if 'location' in response.headers:
                        location = response.headers['location'].lower()
                        if 'evil.com' in location or '%3A//evil.com' in location:
                            if param not in vulnerable_params:
                                vulnerable_params.append(param)
                except requests.RequestException:
                    pass
        
        if vulnerable_params:
            for param in vulnerable_params:
                self.add_finding(
                    name=f"Open Redirect in parameter '{param}'",
                    severity="Medium",
                    owasp_category="A06:2021 - Vulnerable and Outdated Components",
                    description=f"Parameter '{param}' allows redirection to arbitrary external domains",
                    remediation="Validate and whitelist allowed redirect domains, use indirect references",
                    evidence=f"Parameter accepts https://evil.com as redirect target"
                )
        else:
            print(f"{Fore.GREEN}✓ No open redirect vulnerabilities found\n")
    
    # ============ STEP 5: Generate Report ============
    
    def generate_json_report(self, filename: str = "report.json"):
        """Export findings to JSON file"""
        report = {
            "scan_info": {
                "target": self.target_url,
                "timestamp": self.timestamp,
                "scanner": "Web Vulnerability Scanner v1.0",
                "total_findings": len(self.findings)
            },
            "findings": self.findings,
            "summary": {
                "critical": sum(1 for f in self.findings if f["severity"] == "CRITICAL"),
                "high": sum(1 for f in self.findings if f["severity"] == "HIGH"),
                "medium": sum(1 for f in self.findings if f["severity"] == "MEDIUM"),
                "info": sum(1 for f in self.findings if f["severity"] == "INFO")
            }
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"{Fore.GREEN}📄 JSON report saved to: {filename}")
        return report
    
    def print_summary(self):
        """Print a colored summary of all findings"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}📊 SCAN SUMMARY")
        print(f"{Fore.CYAN}{'='*60}")
        
        if not self.findings:
            print(f"{Fore.GREEN}✅ No vulnerabilities found! Great job!")
        else:
            print(f"{Fore.YELLOW}Found {len(self.findings)} issues:\n")
            
            critical = [f for f in self.findings if f["severity"] == "CRITICAL"]
            high = [f for f in self.findings if f["severity"] == "HIGH"]
            medium = [f for f in self.findings if f["severity"] == "MEDIUM"]
            
            if critical:
                print(f"{Fore.RED}🔴 CRITICAL: {len(critical)}")
            if high:
                print(f"{Fore.LIGHTRED_EX}🟠 HIGH: {len(high)}")
            if medium:
                print(f"{Fore.YELLOW}🟡 MEDIUM: {len(medium)}")
        
        print(f"{Fore.CYAN}{'='*60}\n")
    
    def run_full_scan(self):
        """Execute all vulnerability checks"""
        self.print_header()
        
        # Step 2: Security headers
        self.check_security_headers()
        
        # Step 3: SQL injection
        self.check_sql_injection()
        
        # Step 4: Open redirect
        self.check_open_redirect()
        
        # Step 5: Generate report
        self.print_summary()
        self.generate_json_report()


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Web Vulnerability Scanner - OWASP Top 10 compliant",
        epilog="⚠️  Only scan URLs you own or have explicit permission to test!"
    )
    parser.add_argument(
        "--url", 
        required=True, 
        help="Target URL to scan (e.g., https://example.com/page?id=1)"
    )
    parser.add_argument(
        "--no-color", 
        action="store_true", 
        help="Disable colored output"
    )
    
    args = parser.parse_args()
    
    # Disable colorama if requested
    if args.no_color:
        from colorama import just_fix_windows_console
        just_fix_windows_console()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print(f"{Fore.RED}Error: URL must start with http:// or https://")
        sys.exit(1)
    
    # Disclaimer
    print(f"{Fore.YELLOW}{Style.BRIGHT}⚠️  LEGAL DISCLAIMER:")
    print(f"{Fore.YELLOW}Only scan URLs you own or have written permission to test.")
    print(f"{Fore.YELLOW}Unauthorized scanning may be illegal.\n")
    
    confirm = input(f"{Fore.WHITE}Do you have permission to scan {args.url}? (yes/no): ")
    if confirm.lower() != 'yes':
        print(f"{Fore.RED}Exiting. Please obtain proper authorization first.")
        sys.exit(0)
    
    # Run scanner
    scanner = WebVulnerabilityScanner(args.url)
    scanner.run_full_scan()


if __name__ == "__main__":
    main()