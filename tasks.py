from crewai import Task
from agents import ip_researcher, domain_researcher, url_researcher, manager_agent

def create_ip_task(ip_address):
    return Task(
        description=f"Analyze the IP address {ip_address} for potential threats. Use all available tools to gather comprehensive information.",
        expected_output='Detailed findings on IP address research, including geolocation, open ports, and associated domains or URLs.',
        agent=ip_researcher
    )

def create_domain_task(domain_name):
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
    return Task(
        description=f"Evaluate the research results for the following detection information: {detection_info}. "
                    f"Identify any domains or URLs that need further investigation, and compile a comprehensive threat analysis. "
                    f"Initial results: {initial_results}",
        expected_output="Comprehensive threat analysis and list of additional domains or URLs to investigate, "
                        "focusing on the provided detection information.",
        agent=manager_agent
    )

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