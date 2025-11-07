#!/usr/bin/env python3
"""
Local test script for Nmap Vulnerability Scanner
Tests the vulnerability scanning functionality without running the full orchestrator
"""

import os
import sys
import subprocess
import logging
from datetime import datetime

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from init_shared import shared_data
from actions.nmap_vuln_scanner import NmapVulnScanner
from logger import Logger

# Setup logging
logger = Logger(name="test_vuln_scanner", level=logging.DEBUG)

def test_nmap_installation():
    """Test if nmap is installed and accessible"""
    print("\n" + "="*70)
    print("TEST 1: Checking nmap installation")
    print("="*70)
    
    try:
        result = subprocess.run(['nmap', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ PASSED: nmap is installed")
            print(f"   Version: {result.stdout.splitlines()[0]}")
            return True
        else:
            print("❌ FAILED: nmap returned error")
            print(f"   Error: {result.stderr}")
            return False
    except FileNotFoundError:
        print("❌ FAILED: nmap not found in PATH")
        print("   Install nmap: https://nmap.org/download.html")
        return False
    except Exception as e:
        print(f"❌ FAILED: {e}")
        return False

def test_vulners_script():
    """Test if vulners.nse script is available"""
    print("\n" + "="*70)
    print("TEST 2: Checking vulners.nse script")
    print("="*70)
    
    try:
        result = subprocess.run(
            ['nmap', '--script-help', 'vulners'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if 'vulners' in result.stdout.lower():
            print("✅ PASSED: vulners.nse script is available")
            return True
        else:
            print("❌ FAILED: vulners.nse script not found")
            print("\n   To install vulners.nse:")
            print("   1. Download from: https://github.com/vulnersCom/nmap-vulners")
            print("   2. Copy vulners.nse to nmap scripts directory")
            print("   3. Run: nmap --script-updatedb")
            return False
    except subprocess.TimeoutExpired:
        print("⚠️  WARNING: Script check timed out")
        return False
    except Exception as e:
        print(f"❌ FAILED: {e}")
        return False

def test_basic_scan(target_ip="127.0.0.1"):
    """Test a basic nmap scan"""
    print("\n" + "="*70)
    print(f"TEST 3: Basic nmap scan on {target_ip}")
    print("="*70)
    
    try:
        print(f"   Running: nmap -T4 -p 80,443 {target_ip}")
        result = subprocess.run(
            ['nmap', '-T4', '-p', '80,443', target_ip],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode == 0:
            print("✅ PASSED: Basic scan completed")
            print(f"   Output preview: {result.stdout[:200]}...")
            return True
        else:
            print("❌ FAILED: Scan returned error")
            print(f"   Stderr: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print("❌ FAILED: Scan timed out (>60s)")
        return False
    except Exception as e:
        print(f"❌ FAILED: {e}")
        return False

def test_vulnerability_scan(target_ip="scanme.nmap.org"):
    """Test vulnerability scanning on a safe test target"""
    print("\n" + "="*70)
    print(f"TEST 4: Vulnerability scan on {target_ip}")
    print("="*70)
    print("   This may take 30-60 seconds...")
    
    try:
        command = [
            'nmap',
            '-T4',
            '-sV',
            '--script', 'vulners.nse',
            '-p', '22,80,443',
            target_ip
        ]
        
        print(f"   Command: {' '.join(command)}")
        
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if result.returncode == 0:
            print("✅ PASSED: Vulnerability scan completed")
            
            # Check for vulnerabilities in output
            if 'CVE-' in result.stdout or 'vulners:' in result.stdout:
                print("   ✓ Vulnerabilities detected in output")
            else:
                print("   ℹ  No vulnerabilities found (or target has none)")
            
            # Save output to file
            output_file = f"test_vuln_output_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(output_file, 'w') as f:
                f.write(result.stdout)
            print(f"   Output saved to: {output_file}")
            
            return True
        else:
            print("❌ FAILED: Scan returned error")
            print(f"   Stderr: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ FAILED: Scan timed out (>120s)")
        return False
    except Exception as e:
        print(f"❌ FAILED: {e}")
        return False

def test_scanner_class():
    """Test the NmapVulnScanner class initialization"""
    print("\n" + "="*70)
    print("TEST 5: NmapVulnScanner class initialization")
    print("="*70)
    
    try:
        scanner = NmapVulnScanner(shared_data)
        print("✅ PASSED: Scanner initialized successfully")
        print(f"   Summary file: {scanner.summary_file}")
        print(f"   Vulnerabilities dir: {shared_data.vulnerabilities_dir}")
        return True
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_scan_single_host(target_ip=None):
    """Test scanning a single host using the scanner class"""
    print("\n" + "="*70)
    print("TEST 6: Scan single host with NmapVulnScanner")
    print("="*70)
    
    if not target_ip:
        target_ip = input("   Enter target IP to scan (or press Enter to skip): ").strip()
        if not target_ip:
            print("   ⊘ SKIPPED: No target IP provided")
            return None
    
    try:
        scanner = NmapVulnScanner(shared_data)
        
        # Create a test row
        test_row = {
            "IPs": target_ip,
            "Hostnames": "test-host",
            "MAC Address": "00:00:00:00:00:00",
            "Ports": "22,80,443",
            "Alive": "1"
        }
        
        print(f"   Scanning {target_ip}...")
        print("   This may take 30-60 seconds...")
        
        result = scanner.execute(target_ip, test_row, "NmapVulnScanner")
        
        if result == 'success':
            print("✅ PASSED: Scan completed successfully")
            
            # Check if results were saved
            sanitized_mac = test_row["MAC Address"].replace(":", "")
            result_file = os.path.join(
                shared_data.vulnerabilities_dir,
                f"{sanitized_mac}_{target_ip}_vuln_scan.txt"
            )
            
            if os.path.exists(result_file):
                print(f"   Results saved to: {result_file}")
                
                # Show first few lines
                with open(result_file, 'r') as f:
                    lines = f.readlines()[:10]
                    print("   Preview:")
                    for line in lines:
                        print(f"      {line.rstrip()}")
            
            return True
        else:
            print(f"❌ FAILED: Scan returned '{result}'")
            return False
            
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_config():
    """Test configuration values"""
    print("\n" + "="*70)
    print("TEST 7: Configuration check")
    print("="*70)
    
    try:
        print(f"   nmap_scan_aggressivity: {shared_data.nmap_scan_aggressivity}")
        print(f"   scan_vuln_running: {shared_data.scan_vuln_running}")
        print(f"   scan_vuln_interval: {shared_data.scan_vuln_interval}")
        print(f"   default_vulnerability_ports: {shared_data.config.get('default_vulnerability_ports')}")
        print(f"   vulnerabilities_dir: {shared_data.vulnerabilities_dir}")
        print(f"   vuln_summary_file: {shared_data.vuln_summary_file}")
        print("✅ PASSED: Configuration loaded")
        return True
    except Exception as e:
        print(f"❌ FAILED: {e}")
        return False

def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("NMAP VULNERABILITY SCANNER - LOCAL TEST SUITE")
    print("="*70)
    print(f"Test started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    results = {}
    
    # Run tests
    results['nmap_installation'] = test_nmap_installation()
    results['vulners_script'] = test_vulners_script()
    results['config'] = test_config()
    results['basic_scan'] = test_basic_scan()
    
    if results['vulners_script']:
        results['vulnerability_scan'] = test_vulnerability_scan()
    else:
        print("\n   ⊘ Skipping vulnerability scan test (vulners.nse not available)")
        results['vulnerability_scan'] = None
    
    results['scanner_class'] = test_scanner_class()
    results['single_host'] = test_scan_single_host()
    
    # Print summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    passed = sum(1 for v in results.values() if v is True)
    failed = sum(1 for v in results.values() if v is False)
    skipped = sum(1 for v in results.values() if v is None)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else ("⊘ SKIP" if result is None else "❌ FAIL")
        print(f"   {test_name:25s} {status}")
    
    print(f"\n   Total: {total} | Passed: {passed} | Failed: {failed} | Skipped: {skipped}")
    
    if failed == 0 and passed > 0:
        print("\n🎉 All tests passed! Vulnerability scanner is working correctly.")
    elif failed > 0:
        print(f"\n⚠️  {failed} test(s) failed. Review the output above for details.")
    
    print("\n" + "="*70)
    
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
