import os
import requests
import shodan
from crewai_tools import tool

# Initialize API keys
shodan_api_key = os.getenv('SHODAN_API_KEY')

# Initialize Shodan client
shodan_client = shodan.Shodan(shodan_api_key)

# Common ports and their usual services
common_ports_services = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP Proxy"
}

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
    Scan ports of the specified IP address using Shodan.
    """
    try:
        results = shodan_client.host(ip_address)
        
        open_ports = results.get('ports', [])
        if open_ports:
            port_details = []
            for service in results['data']:
                port = service['port']
                product = service.get('product', 'N/A')
                version = service.get('version', 'N/A')
                data = service['data']
                port_details.append(
                    f"Port: {port}\nService: {product}\nVersion: {version}\nData: {data}\n{'-' * 60}"
                )
            port_guesses = [f"{port}: {common_ports_services.get(port, 'Unknown')}" for port in open_ports]
            return (
                f"Open ports for {ip_address}: {', '.join(port_guesses)}\n"
                f"This is MY BEST GUESS for what services usually run on these ports.\n\n"
                f"Detailed service information:\n{''.join(port_details)}"
            )
        else:
            return f"No open ports found for {ip_address}"
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