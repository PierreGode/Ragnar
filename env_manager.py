#!/usr/bin/env python3
"""
Environment Variable Manager for Ragnar
Manages OpenAI API token storage in .bashrc as environment variable
"""

import os
import re
import logging
from pathlib import Path
from logger import Logger


class EnvManager:
    """Manages environment variables in .bashrc"""
    
    def __init__(self):
        self.logger = Logger(name="EnvManager", level=logging.INFO)
        self.bashrc_path = Path.home() / '.bashrc'
        self.env_var_name = 'RAGNAR_OPENAI_API_KEY'
        self.marker_start = '# >>> Ragnar OpenAI Configuration >>>'
        self.marker_end = '# <<< Ragnar OpenAI Configuration <<<'
    
    def get_token(self) -> str:
        """Get OpenAI API token from environment variable"""
        token = os.environ.get(self.env_var_name, '')
        if token:
            self.logger.info(f"Retrieved token from environment: {self.env_var_name}")
        return token
    
    def save_token(self, token: str) -> bool:
        """
        Save OpenAI API token to .bashrc as environment variable
        
        Args:
            token: The OpenAI API key to save
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not token:
                self.logger.warning("Attempted to save empty token")
                return False
            
            # Validate token format (OpenAI keys start with 'sk-')
            if not token.startswith('sk-'):
                self.logger.error("Invalid token format - must start with 'sk-'")
                return False
            
            # Log the user and bashrc path being used
            import getpass
            current_user = getpass.getuser()
            self.logger.info(f"Saving token for user: {current_user}")
            self.logger.info(f"Target .bashrc path: {self.bashrc_path}")
            self.logger.info(f".bashrc exists: {self.bashrc_path.exists()}")
            
            # Read existing .bashrc content
            bashrc_content = []
            if self.bashrc_path.exists():
                try:
                    with open(self.bashrc_path, 'r') as f:
                        bashrc_content = f.readlines()
                    self.logger.info(f"Read {len(bashrc_content)} lines from .bashrc")
                except PermissionError as e:
                    self.logger.error(f"Permission denied reading .bashrc: {e}")
                    return False
            else:
                self.logger.warning(f".bashrc does not exist at {self.bashrc_path}, will create it")
            
            # Remove existing Ragnar configuration block if present
            new_content = []
            skip_block = False
            removed_lines = 0
            for line in bashrc_content:
                if self.marker_start in line:
                    skip_block = True
                    removed_lines += 1
                    continue
                if self.marker_end in line:
                    skip_block = False
                    removed_lines += 1
                    continue
                if not skip_block:
                    new_content.append(line)
                else:
                    removed_lines += 1
            
            if removed_lines > 0:
                self.logger.info(f"Removed existing Ragnar config block ({removed_lines} lines)")
            
            # Ensure file ends with newline
            if new_content and not new_content[-1].endswith('\n'):
                new_content[-1] += '\n'
            
            # Add new Ragnar configuration block
            config_block = [
                '\n',
                f'{self.marker_start}\n',
                f'export {self.env_var_name}="{token}"\n',
                f'{self.marker_end}\n'
            ]
            
            # Write updated content back to .bashrc
            try:
                with open(self.bashrc_path, 'w') as f:
                    f.writelines(new_content + config_block)
                self.logger.info(f"Successfully wrote {len(new_content) + len(config_block)} lines to .bashrc")
            except PermissionError as e:
                self.logger.error(f"Permission denied writing to .bashrc: {e}")
                return False
            except Exception as e:
                self.logger.error(f"Error writing to .bashrc: {e}")
                return False
            
            # Verify the write was successful
            if self.bashrc_path.exists():
                try:
                    with open(self.bashrc_path, 'r') as f:
                        content = f.read()
                        if self.env_var_name in content:
                            self.logger.info("✓ Verified token was written to .bashrc")
                        else:
                            self.logger.error("✗ Token not found in .bashrc after write!")
                            return False
                except Exception as e:
                    self.logger.warning(f"Could not verify .bashrc write: {e}")
            
            # Set in current environment immediately
            os.environ[self.env_var_name] = token
            self.logger.info(f"✓ Set {self.env_var_name} in current environment")
            
            self.logger.info(f"Successfully saved token to {self.bashrc_path}")
            self.logger.info("Token will be available in new shell sessions")
            self.logger.info(f"To load in current session, run: source ~/.bashrc")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving token to .bashrc: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            return False
    
    def remove_token(self) -> bool:
        """
        Remove OpenAI API token from .bashrc
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not self.bashrc_path.exists():
                self.logger.info(".bashrc does not exist, nothing to remove")
                return True
            
            # Read existing .bashrc content
            with open(self.bashrc_path, 'r') as f:
                bashrc_content = f.readlines()
            
            # Remove Ragnar configuration block
            new_content = []
            skip_block = False
            for line in bashrc_content:
                if self.marker_start in line:
                    skip_block = True
                    continue
                if self.marker_end in line:
                    skip_block = False
                    continue
                if not skip_block:
                    new_content.append(line)
            
            # Write updated content back to .bashrc
            with open(self.bashrc_path, 'w') as f:
                f.writelines(new_content)
            
            # Remove from current environment
            if self.env_var_name in os.environ:
                del os.environ[self.env_var_name]
            
            self.logger.info(f"Successfully removed token from {self.bashrc_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error removing token from .bashrc: {e}")
            return False
    
    def validate_token(self, token: str) -> bool:
        """
        Validate OpenAI API token format
        
        Args:
            token: The token to validate
            
        Returns:
            bool: True if valid format, False otherwise
        """
        if not token:
            return False
        
        # OpenAI API keys start with 'sk-' and are typically 48-51 characters
        if not token.startswith('sk-'):
            return False
        
        if len(token) < 20:  # Minimum reasonable length
            return False
        
        return True
