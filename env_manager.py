#!/usr/bin/env python3
"""
Environment Variable Manager for Ragnar
Manages OpenAI API token storage in .env file
"""

import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class EnvManager:
    def __init__(self, project_root=None):
        """
        Initializes the EnvManager.
        It determines the project root and the path to the .env file.
        """
        if project_root:
            self.project_root = project_root
        else:
            # This logic assumes the script is in the root or a direct subfolder.
            # Adjust if the project structure is different.
            self.project_root = os.path.dirname(os.path.abspath(__file__))

        self.env_file_path = os.path.join(self.project_root, '.env')
        logger.info(f"Project root identified as: {self.project_root}")
        logger.info(f".env file path set to: {self.env_file_path}")

    def get_token(self):
        """
        Gets the token from the RAGNAR_OPENAI_API_KEY in the .env file.
        It also checks the environment variables as a fallback.
        """
        # 1. Check environment variable first (for already loaded envs)
        token = os.environ.get('RAGNAR_OPENAI_API_KEY')
        if token:
            logger.info("Token found in process environment variables.")
            return token

        # 2. If not in env, check .env file
        if not os.path.exists(self.env_file_path):
            logger.warning(f".env file not found at {self.env_file_path}")
            return None
        
        with open(self.env_file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('RAGNAR_OPENAI_API_KEY='):
                    token = line.split('=', 1)[1]
                    logger.info("Token found in .env file.")
                    return token
        
        logger.info("RAGNAR_OPENAI_API_KEY not found in .env file.")
        return None

    def save_token(self, token):
        """
        Saves the token to the .env file. This will create or overwrite the file.
        """
        try:
            with open(self.env_file_path, 'w') as f:
                f.write(f'RAGNAR_OPENAI_API_KEY={token}\n')
            
            # Also set it in the current running process's environment for immediate use
            os.environ['RAGNAR_OPENAI_API_KEY'] = token
            
            logger.info(f"Token saved to {self.env_file_path}")
            return {"success": True, "message": "✓ API token saved. Please restart the Ragnar service to apply the changes."}
        except Exception as e:
            logger.error(f"Failed to save token to .env file: {e}", exc_info=True)
            return {"success": False, "message": f"✗ Failed to save token to .env file: {e}"}

    def get_token_status(self):
        """
        Checks if the token exists and returns a preview.
        """
        token = self.get_token()
        if token:
            return {"token_set": True, "preview": f"{token[:5]}...{token[-4:]}"}
        return {"token_set": False}

def load_env(project_root=None):
    """
    Loads environment variables from the .env file into the process environment.
    This should be called at the very start of the application.
    """
    # Determine project root relative to this file's location
    if not project_root:
        project_root = os.path.dirname(os.path.abspath(__file__))

    env_path = os.path.join(project_root, '.env')

    if not os.path.exists(env_path):
        logger.warning(f"Cannot load environment: .env file not found at {env_path}")
        return

    try:
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    # Don't overwrite existing environment variables
                    if key not in os.environ:
                        os.environ[key] = value
                        logger.info(f"Loaded '{key}' from .env file into process environment.")
        logger.info(".env file processed.")
    except Exception as e:
        logger.error(f"Failed to load .env file at {env_path}: {e}", exc_info=True)
