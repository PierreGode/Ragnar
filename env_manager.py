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
        
        # Get the actual user's home directory, not root's
        # When running with sudo, SUDO_USER contains the actual user
        actual_user = os.environ.get('SUDO_USER') or os.environ.get('USER')
        
        # If still root, try to detect the real user from the Ragnar directory ownership
        if not actual_user or actual_user == 'root':
            try:
                # Get the owner of the current working directory (Ragnar directory)
                import pwd
                ragnar_dir = Path.cwd()
                stat_info = ragnar_dir.stat()
                owner_uid = stat_info.st_uid
                owner_info = pwd.getpwuid(owner_uid)
                actual_user = owner_info.pw_name
                self.logger.info(f"Detected actual user from directory ownership: {actual_user}")
            except Exception as e:
                self.logger.warning(f"Could not detect user from directory: {e}")
                actual_user = os.getlogin()
        
        if actual_user and actual_user != 'root':
            # Use the actual user's home directory
            import pwd
            try:
                user_info = pwd.getpwnam(actual_user)
                self.bashrc_path = Path(user_info.pw_dir) / '.bashrc'
                self.actual_user = actual_user
                self.logger.info(f"Using bashrc for user: {actual_user} at {self.bashrc_path}")
            except KeyError:
                # Fallback to Path.home() if user not found
                self.bashrc_path = Path.home() / '.bashrc'
                self.actual_user = actual_user
                self.logger.warning(f"Could not find user {actual_user}, using Path.home()")
        else:
            # Running as root without sudo - use root's bashrc
            self.bashrc_path = Path.home() / '.bashrc'
            self.actual_user = 'root'
            self.logger.warning("Running as root - using /root/.bashrc")
        
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
            effective_user = os.environ.get('SUDO_USER', current_user)
            self.logger.info(f"Current process user: {current_user}")
            self.logger.info(f"Saving token for actual user: {self.actual_user}")
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
            
            # Validate .bashrc syntax
            if not self._validate_bashrc():
                self.logger.error("✗ .bashrc validation failed - syntax errors detected!")
                return False
            
            # Set in current environment immediately
            os.environ[self.env_var_name] = token
            self.logger.info(f"✓ Set {self.env_var_name} in current environment")
            
            # Automatically source .bashrc to load the token
            if self._source_bashrc():
                self.logger.info("✓ Successfully sourced .bashrc")
            else:
                self.logger.warning("⚠ Could not automatically source .bashrc - may need manual reload")
            
            self.logger.info(f"Successfully saved token to {self.bashrc_path}")
            self.logger.info("Token will be available in new shell sessions")
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
    
    def _validate_bashrc(self) -> bool:
        """
        Validate .bashrc syntax by running bash -n
        
        Returns:
            bool: True if valid, False if syntax errors
        """
        try:
            import subprocess
            result = subprocess.run(
                ['bash', '-n', str(self.bashrc_path)],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                self.logger.info("✓ .bashrc syntax validation passed")
                return True
            else:
                self.logger.error(f"✗ .bashrc syntax errors: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error("✗ .bashrc validation timeout")
            return False
        except Exception as e:
            self.logger.warning(f"Could not validate .bashrc: {e}")
            # Don't fail the operation if validation fails
            return True
    
    def _source_bashrc(self) -> bool:
        """
        Source .bashrc to load environment variables into current process
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            import subprocess
            
            # If running as root but targeting another user's bashrc, run as that user
            current_user = os.getlogin() if hasattr(os, 'getlogin') else os.environ.get('USER', 'root')
            
            if current_user == 'root' and self.actual_user != 'root':
                # Run as the actual user using su
                self.logger.info(f"Running source as user {self.actual_user} (current: {current_user})")
                result = subprocess.run(
                    ['su', '-', self.actual_user, '-c', f'source {self.bashrc_path} && echo ${self.env_var_name}'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
            else:
                # Run normally
                result = subprocess.run(
                    ['bash', '-c', f'source {self.bashrc_path} && echo ${self.env_var_name}'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
            
            if result.returncode == 0 and result.stdout.strip():
                token_from_source = result.stdout.strip()
                if token_from_source and token_from_source != '':
                    self.logger.info(f"✓ Sourced .bashrc and verified token is set")
                    # Update current environment with the sourced value
                    os.environ[self.env_var_name] = token_from_source
                    return True
            
            self.logger.warning("⚠ Could not verify token after sourcing .bashrc")
            return False
            
        except subprocess.TimeoutExpired:
            self.logger.error("✗ .bashrc sourcing timeout")
            return False
        except Exception as e:
            self.logger.warning(f"Could not source .bashrc: {e}")
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
