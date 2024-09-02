from crewai import Task
from agents import ip_researcher, domain_researcher, url_researcher, manager_agent
import re

# In-memory set to keep track of analyzed domains
analyzed_domains = set()

def create_ip_task(ip_address):
    if not is_valid_ip(ip_address):
        return None  # Skip if the IP address is invalid
    return Task(
        description=f"Analyze the IP address {ip_address} for potential threats. Use all available tools to gather comprehensive information.",
        expected_output='Detailed findings on IP address research, including geolocation, open ports, and associated domains or URLs.',
        agent=ip_researcher
    )

def create_domain_task(domain_name):
    if not is_valid_domain(domain_name):
        return None  # Skip if the domain is invalid
    if has_already_been_analyzed(domain_name):
        return None  # Skip if the domain has already been analyzed
    return Task(
        description=f"Investigate the domain {domain_name} for any malicious activity and summarize its content.",
        expected_output='Brief summary of domain research, including website content summary and any suspicious patterns.',
        agent=domain_researcher
    )

def create_url_task(url):
    return Task(
        description=f"Analyze the URL {url} for potential threats.",
        expected_output='Short report on URL analysis, highlighting any signs of phishing or malware distribution.',
        agent=url_researcher
    )

def create_evaluation_task(initial_results, detection_info):
    if initial_results and detection_info:
        return Task(
            description=f"Evaluate the research results for the following detection information: {detection_info}. "
                        f"Identify any domains or URLs that need further investigation, and compile a comprehensive threat analysis. "
                        f"Initial results: {initial_results}",
            expected_output="Comprehensive threat analysis and list of additional domains or URLs to investigate, "
                            "focusing on the provided detection information.",
            agent=manager_agent
        )
    return None

def create_final_report_task(initial_results, evaluation_result, additional_results, detection_info):
    return Task(
        description=f"Compile a final comprehensive report based on all gathered information and analyses. "
                    f"Focus on the following detection information: {detection_info}. "
                    f"Initial results: {initial_results}. "
                    f"Evaluation: {evaluation_result}. "
                    f"Additional research: {additional_results}.",
        expected_output="Final comprehensive cybersecurity threat report, specifically addressing the provided detection information.",
        agent=manager_agent
    )

# Additional utility functions for validation
def is_valid_ip(ip_address):
    # Regular expression for validating an IP address
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if ip_pattern.match(ip_address):
        return all(0 <= int(part) < 256 for part in ip_address.split('.'))
    return False

def is_valid_domain(domain_name):
    # Regular expression for validating a domain name
    domain_pattern = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\."
        r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)$"
    )
    return bool(domain_pattern.match(domain_name))

def has_already_been_analyzed(domain_name):
    # Check if the domain has already been analyzed
    if domain_name in analyzed_domains:
        return True
    analyzed_domains.add(domain_name)
    return False