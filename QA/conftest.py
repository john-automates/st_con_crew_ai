import pytest
import os
import sys
from dotenv import load_dotenv

# Add the parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

@pytest.fixture(scope="session", autouse=True)
def load_env():
    # Load .env file from the parent directory
    dotenv_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env')
    load_dotenv(dotenv_path)
    
    # Verify that required environment variables are set
    required_vars = ['SHODAN_API_KEY', 'PORTSCANNER_API_KEY', 'FIRECRAWL_API_KEY', 'SERPER_API_KEY', 'OPENAI_API_KEY']
    for var in required_vars:
        assert os.getenv(var), f"{var} is not set in the environment"