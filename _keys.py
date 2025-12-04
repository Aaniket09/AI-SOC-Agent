# Get your API Key: https://platform.openai.com/settings/organization/api-keys
import os
from dotenv import load_dotenv

# Load environment variables from the .env file
load_dotenv()

# Access the variables
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
LOG_ANALYTICS_WORKSPACE_ID = os.getenv("LOG_ANALYTICS_WORKSPACE_ID")

# Sentinel / Azure Management Variables
SUBSCRIPTION_ID = os.getenv("SUBSCRIPTION_ID")
RESOURCE_GROUP_NAME = os.getenv("RESOURCE_GROUP_NAME")
SENTINEL_WORKSPACE_NAME = os.getenv("SENTINEL_WORKSPACE_NAME")

# Optional: Add a check to ensure keys are loaded
if not OPENAI_API_KEY:
    raise ValueError("FATAL ERROR: OPENAI_API_KEY not found in .env file.")