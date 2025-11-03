#!/usr/bin/env python3
"""
Test script for the threat intelligence enrich-target endpoint
This tests the newly added endpoint that was missing from the webapp.
"""

import requests
import json
import time
import sys

def test_enrich_target_endpoint(base_url="http://localhost:8000"):
    """Test the /api/threat-intelligence/enrich-target endpoint"""
    
    # Test data
    test_targets = [
        "192.168.1.1",           # IP address
        "example.com",           # Domain
        "8.8.8.8",              # Public IP
        "CVE-2023-1234"         # CVE ID
    ]
    
    print("Testing threat intelligence enrich-target endpoint...")
    print(f"Base URL: {base_url}")
    print("-" * 50)
    
    for target in test_targets:
        try:
            print(f"\nTesting target: {target}")
            
            # Make POST request to the endpoint
            response = requests.post(
                f"{base_url}/api/threat-intelligence/enrich-target",
                headers={'Content-Type': 'application/json'},
                json={'target': target},
                timeout=30
            )
            
            print(f"Status Code: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                print("✅ SUCCESS")
                print(f"  Risk Score: {data.get('risk_score', 'N/A')}/100")
                print(f"  Dynamic Risk Score: {data.get('dynamic_risk_score', 'N/A')}/10")
                print(f"  Threat Contexts: {data.get('threat_contexts_count', 0)}")
                print(f"  Executive Summary: {data.get('executive_summary', 'N/A')[:100]}...")
            else:
                print("❌ FAILED")
                try:
                    error_data = response.json()
                    print(f"  Error: {error_data.get('error', 'Unknown error')}")
                except:
                    print(f"  HTTP Error: {response.status_code}")
                    
        except requests.exceptions.ConnectionError:
            print(f"❌ CONNECTION ERROR - Is the webapp running on {base_url}?")
            return False
        except Exception as e:
            print(f"❌ ERROR: {e}")
            
        time.sleep(1)  # Small delay between requests
    
    return True

def test_endpoint_availability(base_url="http://localhost:8000"):
    """Test if the endpoint responds to requests (even if it returns an error)"""
    try:
        response = requests.post(
            f"{base_url}/api/threat-intelligence/enrich-target",
            headers={'Content-Type': 'application/json'},
            json={'target': 'test'},
            timeout=10
        )
        
        # Any response (even error) means the endpoint exists
        if response.status_code != 404:
            print("✅ Endpoint exists and responds")
            return True
        else:
            print("❌ Endpoint not found (404)")
            return False
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to webapp - is it running?")
        return False
    except Exception as e:
        print(f"❌ Error testing endpoint: {e}")
        return False

if __name__ == "__main__":
    print("Threat Intelligence Endpoint Test")
    print("=" * 50)
    
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
    
    # First test if endpoint exists
    if test_endpoint_availability(base_url):
        # If endpoint exists, run full tests
        test_enrich_target_endpoint(base_url)
    else:
        print("\nEndpoint not available. Make sure:")
        print("1. The webapp is running")
        print("2. The URL is correct")
        print("3. The enrich-target endpoint has been added")