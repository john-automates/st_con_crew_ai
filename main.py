import os
import logging
from dotenv import load_dotenv
from crewai import Crew, Process
from agents import ip_researcher, domain_researcher, url_researcher, manager_agent
from tasks import create_ip_task, create_domain_task, create_url_task, create_evaluation_task, create_final_report_task
from utils import extract_domains
from ip_researcher_tools import get_associated_urls

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(filename='cybersecurity_manager.log', level=logging.DEBUG, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def cybersecurity_manager_converse(detection_info):
    logging.info(f"Manager received detection info: {detection_info}")
    
    tasks = []
    
    if 'ip_address' in detection_info:
        ip_task = create_ip_task(detection_info['ip_address'])
        if ip_task:
            tasks.append(ip_task)
        
        # Get associated URLs for the IP address
        associated_urls = get_associated_urls(detection_info['ip_address'])
        logging.info(f"Associated URLs: {associated_urls}")
        
        # Extract domains from the associated URLs
        domains = extract_domains(associated_urls)
        
        # Create domain tasks for each associated domain
        for domain in domains:
            domain_task = create_domain_task(domain)
            if domain_task:
                tasks.append(domain_task)
    
    if 'domain_name' in detection_info:
        domain_task = create_domain_task(detection_info['domain_name'])
        if domain_task:
            tasks.append(domain_task)
    
    if 'url' in detection_info:
        url_task = create_url_task(detection_info['url'])
        if url_task:
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
    logging.info(f"Initial results: {initial_results}")
    
    # Manager evaluates results and decides on additional research
    evaluation_task = create_evaluation_task(initial_results, detection_info)
    
    if evaluation_task:
        evaluation_crew = Crew(
            agents=[manager_agent],
            tasks=[evaluation_task],
            process=Process.sequential
        )
        
        evaluation_result = evaluation_crew.kickoff()
        logging.info(f"Evaluation result: {evaluation_result}")
        
        # Extract the string content from the CrewOutput object
        evaluation_text = str(evaluation_result)
        
        # Extract domains and URLs from the evaluation result
        domains_to_investigate = extract_domains(evaluation_text)
        
        # Perform additional research on extracted domains
        additional_tasks = []
        for domain in domains_to_investigate:
            if domain not in detection_info.values():
                additional_task = create_domain_task(domain)
                if additional_task:
                    additional_tasks.append(additional_task)
        
        if additional_tasks:
            additional_crew = Crew(
                agents=[domain_researcher, manager_agent],
                tasks=additional_tasks,
                process=Process.sequential
            )
            additional_results = additional_crew.kickoff()
            logging.info(f"Additional results: {additional_results}")
        else:
            additional_results = "No additional domains required investigation."
            logging.info(additional_results)
        
        # Manager compiles final report
        final_report_task = create_final_report_task(initial_results, evaluation_result, additional_results, detection_info)
        
        final_crew = Crew(
            agents=[manager_agent],
            tasks=[final_report_task],
            process=Process.sequential
        )
        
        final_report = final_crew.kickoff()
        logging.info(f"Final report: {final_report}")
        
        return str(final_report)  # Ensure we return a string
    else:
        return "Evaluation task could not be created."

if __name__ == "__main__":
    # Example input and execution
    detection_info_example = {
        'ip_address': '188.114.96.3',
        #'domain_name': 'example.com',
        #'url': 'https://extendica.com'
    }

    # Simulate the manager processing the input
    result = cybersecurity_manager_converse(detection_info_example)
    print(result)