import pytest
import sys
import os

# Add the parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from domain_researcher_tools import scrape_and_summarize

def test_scrape_and_summarize():
    domain = "example.com"
    result = scrape_and_summarize(domain)  # Directly call the function
    assert f"Summary of {domain}:" in result
    assert "The website appears to be about:" in result
    assert "Content preview:" in result
    # Add more specific assertions based on expected content