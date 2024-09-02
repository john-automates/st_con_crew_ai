from crewai import Agent
from ip_researcher_tools import get_ip_info_tool, scan_ports_tool, get_associated_urls_tool
from domain_researcher_tools import scrape_and_summarize_tool

ip_researcher = Agent(
    role='IP Address Researcher',
    goal='Analyze IP address for threats, open ports, and associated domains/URLs',
    verbose=True,
    allow_delegation=False,
    backstory=(
        "You specialize in IP address analysis, checking for malicious activities, open ports, reputation, geolocation, "
        "and associated domains or URLs."
    ),
    tools=[get_ip_info_tool, scan_ports_tool, get_associated_urls_tool]
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
    tools=[scrape_and_summarize_tool]
)

url_researcher = Agent(
    role='URL Researcher',
    goal='Analyze URLs for potential malicious behavior',
    verbose=True,
    allow_delegation=False,
    backstory=(
        "Your expertise is in investigating URLs for phishing, malware distribution, and other malicious activities."
    ),
    tools=[scrape_and_summarize_tool]
)

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