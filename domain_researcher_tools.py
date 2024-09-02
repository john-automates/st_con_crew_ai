import os
import requests
from crewai_tools import tool
from firecrawl import FirecrawlApp

# Initialize Firecrawl client
firecrawl_api_key = os.getenv('FIRECRAWL_API_KEY')
firecrawl_client = FirecrawlApp(api_key=firecrawl_api_key)

# Initialize VirusTotal API key
virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')

def scrape_and_summarize(domain: str) -> str:
    """
    Scrape the given domain using Firecrawl and provide a summary of the website content.
    """
    try:
        # Ensure the domain starts with http:// or https://
        if not domain.startswith(('http://', 'https://')):
            domain = 'https://' + domain

        # Scrape the website
        scrape_result = firecrawl_client.scrape_url(domain, params={'formats': ['markdown']})
        
        # Extract the markdown content
        markdown_content = scrape_result.get('markdown', '')
        
        # Generate a summary (you might want to use an LLM for better summarization)
        summary = f"Summary of {domain}:\n\n"
        summary += "The website appears to be about: "
        
        # Simple keyword extraction for demonstration
        keywords = extract_keywords(markdown_content)
        summary += ", ".join(keywords[:5])  # List top 5 keywords
        
        summary += f"\n\nContent preview:\n{markdown_content[:500]}..."  # First 500 characters
        
        return summary
    except Exception as e:
        return f"An error occurred while scraping and summarizing {domain}: {str(e)}"

def extract_keywords(text):
    """
    Simple keyword extraction function.
    In a real-world scenario, you might want to use more sophisticated NLP techniques.
    """
    # Remove common words and punctuation
    common_words = set(['the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'])
    words = text.lower().split()
    words = [word.strip('.,!?()[]{}') for word in words if word not in common_words]
    
    # Count word frequencies
    word_freq = {}
    for word in words:
        if len(word) > 3:  # Only consider words longer than 3 characters
            word_freq[word] = word_freq.get(word, 0) + 1
    
    # Sort by frequency
    sorted_words = sorted(word_freq.items(), key=lambda x: x[1], reverse=True)
    
    return [word for word, freq in sorted_words]

def get_virustotal_report(url: str) -> str:
    """
    Get the URL analysis report from VirusTotal.
    """
    try:
        headers = {
            "x-apikey": virustotal_api_key
        }
        params = {
            "url": url
        }
        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, params=params)
        response.raise_for_status()
        analysis_id = response.json()["data"]["id"]
        
        # Get the analysis report
        report_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
        report_response.raise_for_status()
        report = report_response.json()
        
        return f"VirusTotal URL analysis report for {url}:\n{report}"
    except Exception as e:
        return f"An error occurred while retrieving the VirusTotal report for {url}: {str(e)}"

# Create Tool objects for use in the main application
scrape_and_summarize_tool = tool("Scrape and Summarize Website")(scrape_and_summarize)
get_virustotal_report_tool = tool("Get VirusTotal URL Report")(get_virustotal_report)