import os
from dotenv import load_dotenv
from crewai import Agent, Task, Crew, Process
from ip_researcher_tools import get_ip_info, scan_ports, get_associated_urls
from domain_researcher_tools import scrape_and_summarize
import re

# Load environment variables from .env file
load_dotenv()

# Define the specialized agents
ip_researcher = Agent(
    role='IP Address Researcher',
    goal='Analyze IP address for threats, open ports, and associated domains/URLs',
    verbose=True,
    allow_delegation=False,
    backstory=(
        "You specialize in IP address analysis, checking for malicious activities, open ports, reputation, geolocation, "
        "and associated domains or URLs."
    ),
    tools=[get_ip_info, scan_ports, get_associated_urls]
)

domain_researcher = Agent(
    role='Domain Researcher',
    goal='Investigate domain information for potential threats and summarize website content',
    verbose=True,
    allow_delegation=False,
    backstory=(
        "You are an expert in domain research, analyzing WHOIS, DNS records, historical data for signs of compromise, "
        "and summarizing website content to understand its purpose and potential risks."
    ),
    tools=[scrape_and_summarize]
)

url_researcher = Agent(
    role='URL Researcher',
    goal='Analyze URLs for potential malicious behavior',
    verbose=True,
    allow_delegation=False,
    backstory=(
        "Your expertise is in investigating URLs for phishing, malware distribution, and other malicious activities."
    ),
    tools=[scrape_and_summarize]
)

# Define the manager agent that oversees the operation
manager_agent = Agent(
    role='Cybersecurity Research Manager',
    goal='Coordinate research activities and compile comprehensive threat analysis',
    verbose=True,
    allow_delegation=True,
    backstory=(
        "As the Cybersecurity Research Manager, you coordinate the research activities of specialized agents, "
        "delegate tasks, and compile their findings to provide a comprehensive threat analysis."
    ),
    tools=[]
)

def extract_domains(text):
    """Extract domain names from text."""
    domain_pattern = r'\b(?:[a-z0-9]+(?:-[a-z0-9]+)*\.)+[a-z]{2,}\b'
    return list(set(re.findall(domain_pattern, text, re.IGNORECASE)))

def cybersecurity_manager_converse(detection_info):
    print(f"Manager received detection info: {detection_info}")
    
    tasks = []
    
    if 'ip_address' in detection_info:
        ip_task = Task(
            description=f"Analyze the IP address {detection_info['ip_address']} for potential threats. Use all available tools to gather comprehensive information.",
            expected_output='Detailed findings on IP address research, including geolocation, open ports, and associated domains or URLs.',
            agent=ip_researcher
        )
        tasks.append(ip_task)
    
    if 'domain_name' in detection_info:
        domain_task = Task(
            description=f"Investigate the domain {detection_info['domain_name']} for any malicious activity and summarize its content.",
            expected_output='Brief summary of domain research, including website content summary and any suspicious patterns.',
            agent=domain_researcher
        )
        tasks.append(domain_task)
    
    if 'url' in detection_info:
        url_task = Task(
            description=f"Analyze the URL {detection_info['url']} for potential threats.",
            expected_output='Short report on URL analysis, highlighting any signs of phishing or malware distribution.',
            agent=url_researcher
        )
        tasks.append(url_task)
    
    if not tasks:
        return "No valid detection information provided."
    
    # Create a Crew instance for the initial research
    research_crew = Crew(
        agents=[ip_researcher, domain_researcher, url_researcher, manager_agent],
        tasks=tasks,
        process=Process.sequential
    )
    
    # Manager delegates tasks and collects initial results
    initial_results = research_crew.kickoff()
    
    # Manager evaluates results and decides on additional research
    evaluation_task = Task(
        description="Evaluate the research results, identify any domains or URLs that need further investigation, and compile a comprehensive threat analysis.",
        expected_output="Comprehensive threat analysis and list of additional domains or URLs to investigate.",
        agent=manager_agent
    )
    
    evaluation_crew = Crew(
        agents=[manager_agent],
        tasks=[evaluation_task],
        process=Process.sequential
    )
    
    evaluation_result = evaluation_crew.kickoff()
    
    # Extract the string content from the CrewOutput object
    evaluation_text = str(evaluation_result)
    
    # Extract domains and URLs from the evaluation result
    domains_to_investigate = extract_domains(evaluation_text)
    
    # Perform additional research on extracted domains
    additional_tasks = []
    for domain in domains_to_investigate:
        if domain not in detection_info.values():
            additional_task = Task(
                description=f"Investigate the newly identified domain {domain} for potential threats.",
                expected_output='Additional findings on the newly identified domain.',
                agent=domain_researcher
            )
            additional_tasks.append(additional_task)
    
    if additional_tasks:
        additional_crew = Crew(
            agents=[domain_researcher, manager_agent],
            tasks=additional_tasks,
            process=Process.sequential
        )
        additional_results = additional_crew.kickoff()
    else:
        additional_results = "No additional domains required investigation."
    
    # Manager compiles final report
    final_report_task = Task(
        description="Compile a final comprehensive report based on all gathered information and analyses.",
        expected_output="Final comprehensive cybersecurity threat report.",
        agent=manager_agent
    )
    
    final_crew = Crew(
        agents=[manager_agent],
        tasks=[final_report_task],
        process=Process.sequential
    )
    
    final_report = final_crew.kickoff()
    
    return str(final_report)  # Ensure we return a string

# Example input and execution
detection_info_example = {
    'ip_address': '188.114.96.3',
    #'domain_name': 'example.com',
    #'url': 'http://example.com'
}

# Simulate the manager processing the input
result = cybersecurity_manager_converse(detection_info_example)
print(result)
