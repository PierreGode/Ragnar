#!/usr/bin/env python3
"""
Ragnar Web Server - Standalone Service
Runs the Flask/SocketIO web interface as an independent systemd service.
This service can be started/stopped independently of ragnar-core.
"""

import sys
import os
import signal
import logging
from init_shared import shared_data
from webapp_modern import run_server, handle_exit
from logger import Logger

# Initialize logger
logger = Logger(name="ragnar_web", level=logging.DEBUG)

def main():
    """Main entry point for ragnar-web service"""
    logger.info("=" * 70)
    logger.info("RAGNAR WEB SERVER STARTING")
    logger.info("=" * 70)
    
    try:
        # Load shared data configuration
        logger.info("Loading shared data config...")
        shared_data.load_config()
        
        # Check if web server is enabled in config
        # Since this is now a dedicated web service, we default to True
        # This allows the service to run independently of the config setting
        if not shared_data.config.get("websrv", True):
            logger.warning("Note: 'websrv' is disabled in config, but ragnar-web service is running anyway.")
            logger.warning("To fully disable the web UI, use: sudo systemctl stop ragnar-web")
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, lambda sig, frame: handle_exit(sig, frame))
        signal.signal(signal.SIGTERM, lambda sig, frame: handle_exit(sig, frame))
        
        # Start the web server
        logger.info("Starting Flask/SocketIO web server on port 8000...")
        run_server(host='0.0.0.0', port=8000)
        
    except Exception as e:
        logger.error(f"Fatal error in ragnar-web: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
