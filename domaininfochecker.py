#!/usr/bin/env python3
"""
Domain & Email Information Gatherer
====================================

This tool collects domain information, email addresses, subdomains,
and other useful information from a given URL. Designed for security research
and penetration testing purposes.

Features:
- Domain WHOIS information
- DNS records and reverse lookup
- Email address extraction (including Gmail)
- Subdomain discovery
- CDN detection
- Server information
- Contact information extraction
- Timestamped output
"""

import requests
import re
import socket
import whois
import argparse
import json
import subprocess
from urllib.parse import urlparse
from datetime import datetime
import dns.resolver
import whois.parser

def format_output(data, level=0):
    """Format output with proper indentation and categories"""
    output = ""
    indent = "  " * level
    
    if isinstance(data, dict):
        for key, value in data.items():
            output += f"{indent}{key.upper()}:\n"
            if isinstance(value, dict):
                output += format_output(value, level + 1)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        output += f"{indent}  - "
                        output += format_output(item, level + 2)
                    else:
                        output += f"{indent}  - {item}\n"
            else:
                output += f"{indent}  {value}\n"
    else:
        output += f"{indent}{data}\n"
    
    return output

class DomainInfoGatherer:
    """
    Main class for collecting domain information.
    
    Methods:
        gather_domain_info: Collects WHOIS and DNS information
        gather_emails: Extracts email addresses from webpages
        gather_subdomains: Attempts to discover subdomains
        gather_cdn_info: Detects CDN services
        gather_server_info: Gathers server information
        gather_contact_info: Extracts contact information from webpages
    """
    
    def __init__(self):
        """Initialize the gatherer with empty info dictionary."""
        self.info = {}
        
    def gather_domain_info(self, url):
        """
        Gather domain information including WHOIS and DNS records.
        
        Args:
            url (str): Target URL to analyze
        """
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Get WHOIS information
            try:
                whois_data = whois.whois(domain)
                self.info['whois'] = {
                    'domain': domain,
                    'registrar': whois_data.registrar,
                    'creation_date': str(whois_data.creation_date) if whois_data.creation_date else None,
                    'expiration_date': str(whois_data.expiration_date) if whois_data.expiration_date else None,
                    'nameservers': whois_data.name_servers,
                    'contacts': self._extract_whois_contacts(whois_data)
                }
            except Exception as e:
                self.info['whois_error'] = str(e)
                
            # Get DNS information
            try:
                ip = socket.gethostbyname(domain)
                self.info['dns'] = {
                    'ip_address': ip,
                    'reverse_dns': socket.gethostbyaddr(ip)[0],
                    'dns_records': self._get_all_dns_records(domain)
                }
            except Exception as e:
                self.info['dns_error'] = str(e)
                
        except Exception as e:
            self.info['domain_error'] = str(e)
    
    def _extract_whois_contacts(self, whois_data):
        """Extract contact information from WHOIS data."""
        contacts = []
        
        # Standard contact fields
        contact_fields = [
            'registrant_name', 'registrant_email', 'registrant_organization',
            'admin_name', 'admin_email', 'admin_organization',
            'tech_name', 'tech_email', 'tech_organization',
            'billing_name', 'billing_email', 'billing_organization'
        ]
        
        for field in contact_fields:
            if hasattr(whois_data, field):
                value = getattr(whois_data, field)
                if value:
                    contacts.append({
                        'type': field.split('_')[0],  # registrant, admin, tech, billing
                        'name': value if isinstance(value, str) else str(value)
                    })
        
        # Handle emails separately
        if hasattr(whois_data, 'emails'):
            for email in whois_data.emails:
                contacts.append({
                    'type': 'contact',
                    'email': email
                })
                
        return contacts
    
    def _get_all_dns_records(self, domain):
        """Get all DNS records for a domain."""
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except:
                pass
                
        return records
    
    def gather_emails(self, url):
        """Extract email addresses from the webpage."""
        try:
            response = requests.get(url)
            text = response.text
            
            # Email regex pattern
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            emails = re.findall(email_pattern, text)
            
            # Filter Gmail addresses
            gmail_addresses = [email for email in emails if '@gmail.com' in email]
            
            self.info['emails'] = list(set(emails))  # Remove duplicates
            self.info['gmail_addresses'] = gmail_addresses
            
        except Exception as e:
            self.info['email_error'] = str(e)
    
    def gather_subdomains(self, url):
        """Attempt to find subdomains using common patterns."""
        try:
            parsed_url = urlparse(url)
            base_domain = parsed_url.netloc
            
            # Common subdomain patterns
            subdomains = []
            for prefix in ['www', 'mail', 'ftp', 'test', 'dev', 'admin', 'api', 'blog', 'shop', 'support', 'help']:
                try:
                    subdomain = f"{prefix}.{base_domain}"
                    socket.gethostbyname(subdomain)
                    subdomains.append(subdomain)
                except:
                    continue
                    
            self.info['subdomains'] = subdomains
            
        except Exception as e:
            self.info['subdomain_error'] = str(e)
    
    def gather_cdn_info(self, url):
        """Detect CDN services."""
        try:
            response = requests.get(url)
            headers = response.headers
            
            cdn_services = {
                'cloudflare': 'Cloudflare',
                'akamai': 'Akamai',
                'aws': 'AWS CloudFront',
                'fastly': 'Fastly',
                'google': 'Google Cloud CDN'
            }
            
            detected_cdns = []
            for service, name in cdn_services.items():
                if service in headers.get('Server', '').lower():
                    detected_cdns.append(name)
                    
            self.info['cdn_services'] = detected_cdns
            
        except Exception as e:
            self.info['cdn_error'] = str(e)
    
    def gather_server_info(self, url):
        """Gather server information."""
        try:
            response = requests.get(url)
            headers = response.headers
            
            self.info['server_info'] = {
                'server': headers.get('Server', 'Unknown'),
                'x-powered-by': headers.get('X-Powered-By', 'Not specified'),
                'x-frame-options': headers.get('X-Frame-Options', 'Not set')
            }
            
        except Exception as e:
            self.info['server_error'] = str(e)
    
    def gather_contact_info(self, url):
        """Extract contact information from webpages."""
        try:
            response = requests.get(url)
            text = response.text
            
            # Phone number regex
            phone_pattern = r'\b(?:\+?1[-. ]?)?\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})\b'
            phones = re.findall(phone_pattern, text)
            phone_numbers = [' '.join(match) for match in phones]
            
            # Name pattern
            name_pattern = r'\b(?:Mr|Mrs|Ms|Dr|Prof)\.?\s+[A-Z][a-z]+\s+[A-Z][a-z]+\b'
            names = re.findall(name_pattern, text)
            
            # Address pattern
            address_pattern = r'\b\d{1,4}\s+(?:[A-Za-z0-9]+\.?\s+)+,\s+[A-Za-z]+,\s+[A-Z]{2}\s+\d{5}(?:-\d{4})?\b'
            addresses = re.findall(address_pattern, text)
            
            self.info['contact_info'] = {
                'phone_numbers': list(set(phone_numbers)),
                'names': list(set(names)),
                'addresses': list(set(addresses))
            }
            
        except Exception as e:
            self.info['contact_error'] = str(e)

def main():
    """Main function to handle command-line arguments and execute the tool."""
    parser = argparse.ArgumentParser(
        description="Domain & Email Information Gatherer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u https://example.com
  %(prog)s -u https://github.com --full
  %(prog)s -u https://example.com -o results.txt
        """
    )
    parser.add_argument(
        "-u", "--url", 
        required=True, 
        help="Target URL to gather information from"
    )
    parser.add_argument(
        "-o", "--output", 
        help="Output file for results"
    )
    parser.add_argument(
        "--full", 
        action="store_true", 
        help="Run full scan including passive recon"
    )
    args = parser.parse_args()
    
    gatherer = DomainInfoGatherer()
    gatherer.gather_domain_info(args.url)
    gatherer.gather_emails(args.url)
    gatherer.gather_subdomains(args.url)
    gatherer.gather_cdn_info(args.url)
    gatherer.gather_server_info(args.url)
    gatherer.gather_contact_info(args.url)
    
    # Add timestamp
    gatherer.info['timestamp'] = datetime.now().isoformat()
    
    # Convert datetime objects to strings for JSON serialization
    for key, value in gatherer.info.items():
        if isinstance(value, dict):
            for subkey, subvalue in value.items():
                if isinstance(subvalue, datetime):
                    value[subkey] = str(subvalue)
    
    # Output formatted results
    formatted_output = format_output(gatherer.info)
    print(formatted_output)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(formatted_output)
        print(f"Results saved to {args.output}")

if __name__ == "__main__":
    main()
