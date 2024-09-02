import os
import requests
import shodan
from crewai_tools import tool

# Initialize API keys
shodan_api_key = os.getenv('SHODAN_API_KEY')
portscanner_api_key = os.getenv('PORTSCANNER_API_KEY')

# Initialize Shodan client
shodan_client = shodan.Shodan(shodan_api_key)

def get_ip_info(ip_address: str) -> str:
    """
    Retrieve detailed information about an IP address using Shodan.
    """
    try:
        results = shodan_client.host(ip_address)
        
        summary = f"IP: {ip_address}\n"
        summary += f"Organization: {results.get('org', 'N/A')}\n"
        summary += f"Country: {results.get('country_name', 'N/A')}\n"
        summary += f"City: {results.get('city', 'N/A')}\n"
        summary += f"ISP: {results.get('isp', 'N/A')}\n"
        
        # Add associated domains
        domains = results.get('domains', [])
        if domains:
            summary += f"Associated Domains: {', '.join(domains)}\n"
        
        # Add associated hostnames
        hostnames = results.get('hostnames', [])
        if hostnames:
            summary += f"Associated Hostnames: {', '.join(hostnames)}\n"
        
        return summary
    except Exception as e:
        return f"An error occurred while looking up {ip_address}: {str(e)}"

def scan_ports(ip_address: str) -> str:
    """
    Scan ports of the specified IP address using Port Scanner Online.
    """
    url = "https://api.portscanner.online/v01/start_scan"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "PORTSCANNER-API-KEY": portscanner_api_key
    }
    data = {
        "command": "simple",
        "target": ip_address
    }
    
    try:
        response = requests.post(url, headers=headers, data=data)
        response.raise_for_status()
        scan_id = response.json().get("scan_id")
        
        # Wait for scan to complete
        status_url = "https://api.portscanner.online/v01/check_scan_status"
        status_data = {"scan_id": scan_id}
        while True:
            status_response = requests.post(status_url, headers=headers, data=status_data)
            status_response.raise_for_status()
            if status_response.json().get("scan_status") == "Finished":
                break
        
        # Get scan results
        result_url = "https://api.portscanner.online/v01/scan_result"
        result_data = {"scan_id": scan_id}
        result_response = requests.post(result_url, headers=headers, data=result_data)
        result_response.raise_for_status()
        
        scan_result = result_response.json().get("result", "No result available")
        return f"Port scan results for {ip_address}:\n{scan_result}"
    except Exception as e:
        return f"An error occurred while scanning ports for {ip_address}: {str(e)}"

def get_associated_urls(ip_address: str) -> str:
    """
    Retrieve URLs associated with the given IP address using Shodan.
    """
    try:
        results = shodan_client.search(f"ip:{ip_address}")
        
        urls = set()
        for result in results['matches']:
            if 'http' in result and 'host' in result:
                protocol = 'https' if result['port'] == 443 else 'http'
                url = f"{protocol}://{result['http'].get('host', result['ip_str'])}"
                urls.add(url)
        
        if urls:
            return f"Associated URLs for {ip_address}:\n" + "\n".join(urls)
        else:
            return f"No associated URLs found for {ip_address}"
    except Exception as e:
        return f"An error occurred while retrieving associated URLs for {ip_address}: {str(e)}"

# Create Tool objects for use in the main application
get_ip_info_tool = tool("Get IP Info")(get_ip_info)
scan_ports_tool = tool("Scan Ports")(scan_ports)
get_associated_urls_tool = tool("Get Associated URLs")(get_associated_urls)