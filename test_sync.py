#!/usr/bin/env python3
"""
Test script to manually trigger synchronization and show debug output
"""

import os
import sys
import json
import logging

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Configure logging to show debug messages
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

try:
    # Import shared modules
    import shared
    from shared import SharedData
    import webapp_modern
    
    print("=" * 60)
    print("RAGNAR SYNCHRONIZATION TEST")
    print("=" * 60)
    
    # Initialize shared data
    print("\n1. Initializing shared data...")
    shared_data = SharedData()
    
    # Show current directory paths
    print(f"\n2. Current working directory: {os.getcwd()}")
    print(f"   Vulnerabilities dir: {shared_data.vulnerabilities_dir}")
    print(f"   Scan results dir: {shared_data.scan_results_dir}")
    print(f"   Crackedpwd dir: {shared_data.crackedpwddir}")
    
    # Check if test data directories exist
    print(f"\n3. Checking test data directories:")
    for dir_name, dir_path in [
        ("Vulnerabilities", shared_data.vulnerabilities_dir),
        ("Scan Results", shared_data.scan_results_dir),
        ("Crackedpwd", shared_data.crackedpwddir)
    ]:
        exists = os.path.exists(dir_path)
        print(f"   {dir_name}: {dir_path} - {'EXISTS' if exists else 'MISSING'}")
        
        if exists:
            try:
                files = os.listdir(dir_path)
                txt_files = [f for f in files if f.endswith('.txt')]
                print(f"     Files: {files}")
                print(f"     .txt files: {txt_files}")
            except Exception as e:
                print(f"     Error listing files: {e}")
    
    # Show current counts before sync
    print(f"\n4. Current counts before sync:")
    print(f"   Targets: {getattr(shared_data, 'targetnbr', 0)}")
    print(f"   Ports: {getattr(shared_data, 'portnbr', 0)}")
    print(f"   Vulnerabilities: {getattr(shared_data, 'vulnnbr', 0)}")
    print(f"   Credentials: {getattr(shared_data, 'crednbr', 0)}")
    
    # Need to set the global shared_data for webapp_modern
    webapp_modern.shared_data = shared_data
    
    # Run synchronization
    print(f"\n5. Running synchronization...")
    print("   sync_vulnerability_count()...")
    vuln_count = webapp_modern.sync_vulnerability_count()
    print(f"   Vulnerability count result: {vuln_count}")
    
    print("   sync_all_counts()...")
    webapp_modern.sync_all_counts()
    
    # Show counts after sync
    print(f"\n6. Counts after sync:")
    print(f"   Targets: {getattr(shared_data, 'targetnbr', 0)}")
    print(f"   Ports: {getattr(shared_data, 'portnbr', 0)}")
    print(f"   Vulnerabilities: {getattr(shared_data, 'vulnnbr', 0)}")
    print(f"   Credentials: {getattr(shared_data, 'crednbr', 0)}")
    
    # Show the test data we created  
    print(f"\n7. Verifying test data files:")
    
    # Check vulnerability files
    vuln_dir = shared_data.vulnerabilities_dir
    if os.path.exists(vuln_dir):
        for filename in os.listdir(vuln_dir):
            if filename.endswith('.txt'):
                filepath = os.path.join(vuln_dir, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        print(f"   {filename}: {len(content)} chars, content preview: {repr(content[:100])}")
                except Exception as e:
                    print(f"   {filename}: Error reading - {e}")
    
    print("\n" + "=" * 60)
    print("TEST COMPLETE")
    print("=" * 60)
    
except Exception as e:
    print(f"Error in test script: {e}")
    import traceback
    traceback.print_exc()