#!/usr/bin/env python3
"""
Network Intelligence Demo Script
Demonstrates the smart network-based persistence features of Ragnar

This script shows how vulnerabilities and credentials are tracked
per WiFi network and how they transition between active and resolved states.
"""

import sys
import time
import json
from datetime import datetime

def demo_network_intelligence():
    """Demonstrate network intelligence functionality"""
    try:
        # Import after adding to path
        from network_intelligence import NetworkIntelligence
        from shared import SharedData
        
        print("🔧 Initializing Ragnar Network Intelligence Demo...")
        
        # Initialize shared data
        shared_data = SharedData()
        
        # Initialize network intelligence
        network_intel = NetworkIntelligence(shared_data)
        
        print("✅ Network Intelligence System initialized")
        print(f"📍 Current Network: {network_intel.get_current_network_id()}")
        print()
        
        # Demo 1: Add some vulnerabilities
        print("🔍 DEMO 1: Adding Vulnerabilities")
        print("-" * 40)
        
        vuln1 = network_intel.add_vulnerability(
            host="192.168.1.100",
            port=22,
            service="ssh",
            vulnerability="SSH Weak Authentication",
            severity="high",
            details={"cve": "CVE-2023-1234", "description": "Weak SSH configuration"}
        )
        print(f"🚨 Added vulnerability: {vuln1}")
        
        vuln2 = network_intel.add_vulnerability(
            host="192.168.1.101",
            port=80,
            service="http",
            vulnerability="Apache Directory Traversal",
            severity="medium",
            details={"cve": "CVE-2023-5678", "description": "Path traversal vulnerability"}
        )
        print(f"🚨 Added vulnerability: {vuln2}")
        
        # Demo 2: Add some credentials
        print("\n🔑 DEMO 2: Adding Credentials")
        print("-" * 40)
        
        cred1 = network_intel.add_credential(
            host="192.168.1.100",
            service="ssh",
            username="admin",
            password="password123",
            protocol="ssh",
            details={"method": "brute_force", "attempts": 5}
        )
        print(f"🔓 Added credential: {cred1}")
        
        cred2 = network_intel.add_credential(
            host="192.168.1.101",
            service="ftp",
            username="anonymous",
            password="guest@domain.com",
            protocol="ftp",
            details={"method": "anonymous_login", "attempts": 1}
        )
        print(f"🔓 Added credential: {cred2}")
        
        # Demo 3: Show active findings
        print("\n📊 DEMO 3: Active Findings (Dashboard View)")
        print("-" * 50)
        
        dashboard_data = network_intel.get_active_findings_for_dashboard()
        print(f"🌐 Network: {dashboard_data['network_id']}")
        print(f"🚨 Active Vulnerabilities: {dashboard_data['counts']['vulnerabilities']}")
        print(f"🔑 Active Credentials: {dashboard_data['counts']['credentials']}")
        
        for vuln_id, vuln_data in dashboard_data['vulnerabilities'].items():
            print(f"  • {vuln_data['host']}:{vuln_data['port']} - {vuln_data['vulnerability']} ({vuln_data['severity']})")
        
        for cred_id, cred_data in dashboard_data['credentials'].items():
            print(f"  • {cred_data['host']} - {cred_data['username']}:{cred_data['password']} ({cred_data['service']})")
        
        # Demo 4: Show all findings (NetKB view)
        print("\n📚 DEMO 4: All Findings (NetKB View)")
        print("-" * 40)
        
        netkb_data = network_intel.get_all_findings_for_netkb()
        print(f"📊 Total Vulnerabilities: {netkb_data['counts']['total_vulnerabilities']}")
        print(f"📊 Total Credentials: {netkb_data['counts']['total_credentials']}")
        print(f"🟢 Active Vulnerabilities: {netkb_data['counts']['active_vulnerabilities']}")
        print(f"🟢 Active Credentials: {netkb_data['counts']['active_credentials']}")
        print(f"🔴 Resolved Vulnerabilities: {netkb_data['counts']['resolved_vulnerabilities']}")
        print(f"🔴 Resolved Credentials: {netkb_data['counts']['resolved_credentials']}")
        
        # Demo 5: Network summary
        print("\n🌐 DEMO 5: Network Summary")
        print("-" * 30)
        
        summary = network_intel.get_network_summary()
        print(f"📡 Current Network: {summary['current_network']}")
        print(f"🏢 Total Networks Seen: {summary['total_networks']}")
        print(f"🚨 Current Network Vulnerabilities: {summary['current_network_active']['vulnerabilities']}")
        print(f"🔑 Current Network Credentials: {summary['current_network_active']['credentials']}")
        
        # Demo 6: Simulate network change behavior
        print("\n🔄 DEMO 6: Network Change Simulation")
        print("-" * 40)
        
        print("💡 In a real scenario:")
        print("   1. When you move to a different WiFi network, findings are marked for resolution")
        print("   2. Dashboard shows only current network findings")
        print("   3. NetKB tracks historical findings across all networks")
        print("   4. Findings auto-resolve if not confirmed on new network")
        print("   5. Manual resolution available via API endpoints")
        
        # Demo 7: Show file structure
        print("\n📁 DEMO 7: Intelligence Files")
        print("-" * 30)
        
        print(f"📂 Intelligence Directory: {network_intel.intelligence_dir}")
        print(f"📄 Network Profiles: {network_intel.network_profiles_file}")
        print(f"📄 Active Findings: {network_intel.active_findings_file}")
        print(f"📄 Resolved Findings: {network_intel.resolved_findings_file}")
        
        # Save demonstration data
        network_intel.save_intelligence_data()
        print("\n💾 Demo data saved to intelligence files")
        
        print("\n✅ Network Intelligence Demo Complete!")
        print("\n🚀 Integration Points:")
        print("   • WebApp APIs: /api/network-intelligence")
        print("   • Dashboard: Shows current network findings")
        print("   • NetKB: Shows all findings (active + resolved)")
        print("   • Action Modules: Can add findings via API")
        print("   • Auto-resolution: Based on network presence")
        
        return True
        
    except Exception as e:
        print(f"❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    print("🌟 Ragnar Network Intelligence Demo")
    print("=" * 50)
    print()
    
    success = demo_network_intelligence()
    
    if success:
        print("\n🎉 Demo completed successfully!")
        print("💡 The network intelligence system is ready for integration")
    else:
        print("\n❌ Demo failed - check error messages above")
        sys.exit(1)