#!/usr/bin/env python3
"""
AI Intelligence Monitor for Ragnar
Monitor AI-generated intelligence and change detection

Usage: python3 ai_intel_monitor.py [command]
Commands: stats, targets, pending, history, watch
"""

import os
import sys
import time
import argparse
from datetime import datetime

# Add parent directory to path
parent_dir = os.path.dirname(os.path.abspath(__file__))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from ai_intelligence_manager import get_ai_intelligence_manager


def print_separator(char='=', length=100):
    print(char * length)


def show_stats(manager):
    """Show AI intelligence statistics"""
    stats = manager.get_statistics()
    
    print_separator()
    print("🤖 RAGNAR AI INTELLIGENCE STATISTICS")
    print_separator()
    print(f"Total Targets Tracked:          {stats.get('total_targets', 0)}")
    print(f"Targets Needing Evaluation:     {stats.get('targets_needing_evaluation', 0)}")
    print(f"Total AI Analyses Performed:    {stats.get('total_ai_analyses', 0)}")
    print(f"Total Changes Recorded:         {stats.get('total_changes_recorded', 0)}")
    print(f"Avg Tokens per Analysis:        {stats.get('avg_tokens_per_analysis', 0)}")
    print_separator()


def show_targets(manager, status='active'):
    """Show all targets with AI intelligence"""
    targets = manager.get_all_target_intelligence(status=status)
    
    if not targets:
        print(f"No targets found with status: {status}")
        return
    
    print_separator()
    print(f"🎯 AI INTELLIGENCE TARGETS - {status.upper()} ({len(targets)} total)")
    print_separator()
    print(f"{'IP':<15} {'Hostname':<20} {'AI Analyses':<12} {'Needs Eval':<11} {'Last Analysis':<20}")
    print_separator('-')
    
    for target in targets:
        ip = target.get('ip_address', '')[:15]
        hostname = target.get('hostname', '')[:20] or 'N/A'
        ai_count = str(target.get('ai_analysis_count', 0))
        needs_eval = '✅ Yes' if target.get('needs_ai_evaluation') else '❌ No'
        last_analysis = target.get('last_ai_analysis', 'Never')[:20]
        
        print(f"{ip:<15} {hostname:<20} {ai_count:<12} {needs_eval:<11} {last_analysis:<20}")
    
    print_separator()


def show_pending(manager):
    """Show targets that need AI evaluation"""
    targets = manager.get_targets_needing_evaluation()
    
    if not targets:
        print("✅ No targets need AI evaluation - all up to date!")
        return
    
    print_separator()
    print(f"⏳ TARGETS NEEDING AI EVALUATION ({len(targets)} total)")
    print_separator()
    print(f"{'IP':<15} {'Hostname':<20} {'Ports':<20} {'Last Change':<20}")
    print_separator('-')
    
    for target in targets:
        ip = target.get('ip_address', '')[:15]
        hostname = target.get('hostname', '')[:20] or 'N/A'
        ports = target.get('current_ports', '')[:20]
        last_change = target.get('last_state_change', 'Unknown')[:20]
        
        print(f"{ip:<15} {hostname:<20} {ports:<20} {last_change:<20}")
    
    print_separator()


def show_target_detail(manager, target_id):
    """Show detailed intelligence for a specific target"""
    intel = manager.get_target_intelligence(target_id)
    
    if not intel:
        print(f"❌ No intelligence found for target: {target_id}")
        return
    
    print_separator()
    print(f"🎯 TARGET INTELLIGENCE: {target_id}")
    print_separator()
    print(f"IP Address:           {intel.get('ip_address', 'N/A')}")
    print(f"MAC Address:          {intel.get('mac_address', 'N/A')}")
    print(f"Hostname:             {intel.get('hostname', 'N/A')}")
    print(f"Status:               {intel.get('status', 'N/A')}")
    print()
    print(f"Current Ports:        {intel.get('current_ports', 'None')}")
    print(f"Current Services:     {intel.get('current_services', 'None')}")
    print(f"Vulnerabilities:      {intel.get('current_vulnerabilities', 'None')}")
    print()
    print(f"First Seen:           {intel.get('first_seen', 'N/A')}")
    print(f"Last Seen:            {intel.get('last_seen', 'N/A')}")
    print(f"Last AI Analysis:     {intel.get('last_ai_analysis', 'Never')}")
    print(f"AI Analysis Count:    {intel.get('ai_analysis_count', 0)}")
    print(f"Needs Evaluation:     {'Yes' if intel.get('needs_ai_evaluation') else 'No'}")
    print()
    
    if intel.get('ai_summary'):
        print("AI SUMMARY:")
        print(intel.get('ai_summary'))
        print()
    
    if intel.get('ai_risk_assessment'):
        print("RISK ASSESSMENT:")
        print(intel.get('ai_risk_assessment'))
        print()
    
    if intel.get('ai_recommendations'):
        print("RECOMMENDATIONS:")
        print(intel.get('ai_recommendations'))
        print()
    
    if intel.get('ai_attack_vectors'):
        print("ATTACK VECTORS:")
        print(intel.get('ai_attack_vectors'))
        print()
    
    print_separator()


def show_change_history(manager, target_id, limit=20):
    """Show change history for a target"""
    changes = manager.get_target_change_history(target_id, limit=limit)
    
    if not changes:
        print(f"No change history found for target: {target_id}")
        return
    
    print_separator()
    print(f"📋 CHANGE HISTORY: {target_id} (last {len(changes)})")
    print_separator()
    print(f"{'Timestamp':<20} {'Change Type':<15} {'Description':<50} {'AI Triggered':<13}")
    print_separator('-')
    
    for change in changes:
        timestamp = change.get('timestamp', '')[:20]
        change_type = change.get('change_type', '')[:15]
        description = change.get('change_description', '')[:50]
        ai_triggered = '✅ Yes' if change.get('triggered_ai_analysis') else '❌ No'
        
        print(f"{timestamp:<20} {change_type:<15} {description:<50} {ai_triggered:<13}")
    
    print_separator()


def show_analysis_history(manager, target_id, limit=10):
    """Show AI analysis history for a target"""
    analyses = manager.get_target_analysis_history(target_id, limit=limit)
    
    if not analyses:
        print(f"No AI analysis history found for target: {target_id}")
        return
    
    print_separator()
    print(f"🤖 AI ANALYSIS HISTORY: {target_id} (last {len(analyses)})")
    print_separator()
    print(f"{'Timestamp':<20} {'Trigger':<20} {'Tokens Used':<12} {'Duration (ms)':<15}")
    print_separator('-')
    
    for analysis in analyses:
        timestamp = analysis.get('timestamp', '')[:20]
        trigger = analysis.get('analysis_trigger', '')[:20]
        tokens = str(analysis.get('tokens_used', 0))
        duration = str(analysis.get('analysis_duration_ms', 0))
        
        print(f"{timestamp:<20} {trigger:<20} {tokens:<12} {duration:<15}")
    
    print_separator()
    
    # Show most recent analysis details
    if analyses:
        latest = analyses[0]
        print("\nMOST RECENT ANALYSIS:")
        print_separator('-')
        if latest.get('ai_summary'):
            print("Summary:", latest.get('ai_summary')[:200], "...")
        if latest.get('ai_risk_assessment'):
            print("Risk:", latest.get('ai_risk_assessment')[:200], "...")
        print_separator()


def watch_intelligence(manager, interval=5):
    """Watch AI intelligence changes in real-time"""
    print(f"👁️  Watching AI intelligence (refresh every {interval}s, Ctrl+C to stop)...")
    print()
    
    try:
        while True:
            os.system('clear' if os.name != 'nt' else 'cls')
            print(f"🕐 Last update: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print()
            show_stats(manager)
            print()
            show_pending(manager)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n\n✋ Stopped watching")


def main():
    parser = argparse.ArgumentParser(
        description='Ragnar AI Intelligence Monitor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s stats                        Show AI intelligence statistics
  %(prog)s targets                      Show all targets with AI intelligence
  %(prog)s pending                      Show targets needing AI evaluation
  %(prog)s detail <target_id>          Show detailed intelligence for target
  %(prog)s changes <target_id>         Show change history for target
  %(prog)s analysis <target_id>        Show AI analysis history for target
  %(prog)s watch                        Watch AI intelligence in real-time
        """
    )
    
    parser.add_argument('command',
                       choices=['stats', 'targets', 'pending', 'detail', 'changes', 'analysis', 'watch'],
                       help='Command to execute')
    parser.add_argument('target_id', nargs='?',
                       help='Target ID (required for detail, changes, analysis commands)')
    parser.add_argument('--limit', type=int, default=20,
                       help='Limit number of results (default: 20)')
    parser.add_argument('--interval', type=int, default=5,
                       help='Watch interval in seconds (default: 5)')
    parser.add_argument('--status', default='active',
                       help='Filter targets by status (default: active)')
    
    args = parser.parse_args()
    
    # Initialize AI intelligence manager
    manager = get_ai_intelligence_manager()
    
    # Execute command
    if args.command == 'stats':
        show_stats(manager)
    elif args.command == 'targets':
        show_targets(manager, status=args.status)
    elif args.command == 'pending':
        show_pending(manager)
    elif args.command == 'detail':
        if not args.target_id:
            print("❌ Error: target_id required for detail command")
            sys.exit(1)
        show_target_detail(manager, args.target_id)
    elif args.command == 'changes':
        if not args.target_id:
            print("❌ Error: target_id required for changes command")
            sys.exit(1)
        show_change_history(manager, args.target_id, limit=args.limit)
    elif args.command == 'analysis':
        if not args.target_id:
            print("❌ Error: target_id required for analysis command")
            sys.exit(1)
        show_analysis_history(manager, args.target_id, limit=args.limit)
    elif args.command == 'watch':
        watch_intelligence(manager, interval=args.interval)


if __name__ == '__main__':
    main()
