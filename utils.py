import re
from urllib.parse import urlparse

def extract_domains(text):
    """
    Extract domains from a given text.
    Can handle both URLs and domain names.
    """
    domains = set()
    lines = text.split('\n')
    for line in lines:
        if '://' in line:  # It's likely a URL
            parsed_url = urlparse(line.strip())
            domain = parsed_url.netloc
        else:  # It's likely just a domain
            domain = line.strip()
        
        if domain:
            domains.add(domain)
    
    return list(domains)