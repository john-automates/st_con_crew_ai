import pytest
import sys
import os

# Add the parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ip_researcher_tools import get_ip_info, scan_ports, get_associated_urls

def test_get_ip_info():
    ip = "8.8.8.8"  # Google's public DNS
    result = get_ip_info(ip)  # Directly call the function
    assert "IP: 8.8.8.8" in result
    assert "Organization:" in result
    assert "Country:" in result
    assert "City:" in result
    assert "ISP:" in result

def test_scan_ports():
    ip = "8.8.8.8"  # Google's public DNS
    result = scan_ports(ip)  # Directly call the function
    assert f"Port scan results for {ip}:" in result
    # Add more specific assertions based on expected port scan results

def test_get_associated_urls():
    ip = "172.217.16.142"  # One of Google's IPs
    result = get_associated_urls(ip)  # Directly call the function
    assert "Associated URLs for 172.217.16.142:" in result
    # Add more specific assertions based on expected associated URLs