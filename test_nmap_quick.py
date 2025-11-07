#!/usr/bin/env python3
"""
Quick vulnerability scanner test - minimal setup
Tests the exact nmap command that Ragnar uses
"""

import subprocess
import sys

def test_nmap_vuln_command(target_ip="scanme.nmap.org", ports="22,80,443"):
    """
    Test the exact nmap command used by Ragnar vulnerability scanner
    """
    print("="*70)
    print("QUICK NMAP VULNERABILITY SCAN TEST")
    print("="*70)
    print(f"Target: {target_ip}")
    print(f"Ports: {ports}")
    print("")
    
    # This is the exact command Ragnar uses
    command = [
        "nmap",
        "-T4",           # Aggressive timing (from config)
        "-sV",           # Service version detection
        "--script",      # Use NSE script
        "vulners.nse",   # Vulners vulnerability detection
        "-p",            # Port specification
        ports,           # Ports to scan
        target_ip        # Target IP
    ]
    
    print("Command:")
    print(f"  {' '.join(command)}")
    print("")
    print("Running scan (this may take 30-60 seconds)...")
    print("-"*70)
    
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        # Print output
        print(result.stdout)
        
        if result.stderr:
            print("\nSTDERR:")
            print(result.stderr)
        
        print("-"*70)
        print(f"\nReturn code: {result.returncode}")
        
        # Analyze results
        if result.returncode == 0:
            print("✅ Scan completed successfully")
            
            if 'CVE-' in result.stdout:
                cve_count = result.stdout.count('CVE-')
                print(f"✅ Found {cve_count} CVE references")
            
            if 'vulners:' in result.stdout:
                print("✅ Vulners script executed")
            else:
                print("⚠️  Vulners script output not detected")
                print("    This might mean the script is not installed")
                
        else:
            print("❌ Scan failed")
            
        return result.returncode == 0
        
    except FileNotFoundError:
        print("❌ ERROR: nmap not found!")
        print("   Install nmap: https://nmap.org/download.html")
        return False
        
    except subprocess.TimeoutExpired:
        print("❌ ERROR: Scan timed out (>120 seconds)")
        return False
        
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return False

if __name__ == "__main__":
    # Get target from command line or use default
    target = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
    ports = sys.argv[2] if len(sys.argv) > 2 else "22,80,443"
    
    print(f"\nUsage: python {sys.argv[0]} [target_ip] [ports]")
    print(f"Example: python {sys.argv[0]} 192.168.1.1 80,443\n")
    
    success = test_nmap_vuln_command(target, ports)
    
    sys.exit(0 if success else 1)
