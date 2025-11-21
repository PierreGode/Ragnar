#!/usr/bin/env python3
"""
AI Intelligence Manager for Ragnar
Manages AI-generated intelligence about targets in a separate database (aiintel.db)
Implements dynamic change detection to trigger AI re-evaluation only when needed

Features:
- Separate aiintel.db for AI-generated intelligence
- Change detection for target state (ports, vulnerabilities, patches)
- Dynamic AI re-evaluation triggers (not time-based)
- API token optimization by avoiding unnecessary AI calls
- Per-target intelligence tracking
"""

import os
import sqlite3
import json
import hashlib
import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from contextlib import contextmanager

from logger import Logger

logger = Logger(name="AIIntelligenceManager", level=logging.INFO)


class AIIntelligenceManager:
    """
    Manages AI-generated intelligence about network targets.
    Tracks target state changes and triggers AI re-evaluation dynamically.
    """
    
    def __init__(self, datadir: str = None):
        """
        Initialize the AI Intelligence Manager.
        
        Args:
            datadir: Path to data directory (default: data/)
        """
        self.datadir = datadir or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
        self.db_path = os.path.join(self.datadir, 'aiintel.db')
        self.lock = threading.RLock()
        
        # Initialize database
        self._init_database()
        
        logger.info(f"AI Intelligence Manager initialized: {self.db_path}")
    
    @contextmanager
    def get_connection(self):
        """
        Context manager for database connections.
        Ensures thread-safe access and automatic cleanup.
        """
        conn = None
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path, check_same_thread=False)
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA foreign_keys = ON")
                yield conn
                conn.commit()
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    def _init_database(self):
        """Initialize aiintel database schema."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Target intelligence table - stores AI analysis per target
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS target_intelligence (
                    target_id TEXT PRIMARY KEY,
                    ip_address TEXT NOT NULL,
                    mac_address TEXT,
                    hostname TEXT,
                    
                    -- Target state snapshot (for change detection)
                    ports_hash TEXT,
                    vulnerabilities_hash TEXT,
                    services_hash TEXT,
                    
                    -- Raw target data (for AI context)
                    current_ports TEXT,
                    current_vulnerabilities TEXT,
                    current_services TEXT,
                    
                    -- AI-generated intelligence
                    ai_summary TEXT,
                    ai_risk_assessment TEXT,
                    ai_recommendations TEXT,
                    ai_attack_vectors TEXT,
                    
                    -- Metadata
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_ai_analysis TIMESTAMP,
                    ai_analysis_count INTEGER DEFAULT 0,
                    
                    -- Change tracking
                    state_changed BOOLEAN DEFAULT 0,
                    last_state_change TIMESTAMP,
                    needs_ai_evaluation BOOLEAN DEFAULT 1,
                    
                    -- Status
                    status TEXT DEFAULT 'active',
                    notes TEXT,
                    
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Change history table - tracks all target state changes
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS target_change_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id TEXT NOT NULL,
                    change_type TEXT NOT NULL,
                    change_description TEXT,
                    old_value TEXT,
                    new_value TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    triggered_ai_analysis BOOLEAN DEFAULT 0,
                    FOREIGN KEY (target_id) REFERENCES target_intelligence(target_id) ON DELETE CASCADE
                )
            """)
            
            # AI analysis history table - stores all AI evaluations
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ai_analysis_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id TEXT NOT NULL,
                    analysis_trigger TEXT,
                    ai_summary TEXT,
                    ai_risk_assessment TEXT,
                    ai_recommendations TEXT,
                    ai_attack_vectors TEXT,
                    tokens_used INTEGER,
                    analysis_duration_ms INTEGER,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (target_id) REFERENCES target_intelligence(target_id) ON DELETE CASCADE
                )
            """)
            
            # Create indexes for performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_target_ip ON target_intelligence(ip_address)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_target_mac ON target_intelligence(mac_address)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_target_needs_eval ON target_intelligence(needs_ai_evaluation)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_target_status ON target_intelligence(status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_change_history_target ON target_change_history(target_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_change_history_timestamp ON target_change_history(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_analysis_history_target ON ai_analysis_history(target_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_analysis_history_timestamp ON ai_analysis_history(timestamp)")
            
            conn.commit()
            logger.info("AI Intelligence database schema initialized")
    
    def _calculate_hash(self, data: Any) -> str:
        """Calculate hash of data for change detection."""
        if data is None:
            return ""
        
        # Convert to string representation
        if isinstance(data, (dict, list)):
            data_str = json.dumps(data, sort_keys=True)
        else:
            data_str = str(data)
        
        # Calculate hash
        return hashlib.sha256(data_str.encode()).hexdigest()
    
    def _create_target_id(self, ip: str, mac: str = None) -> str:
        """
        Create a stable target ID from IP and MAC.
        
        Args:
            ip: IP address (required)
            mac: MAC address (optional)
        
        Returns:
            Target ID string
        """
        if not ip:
            raise ValueError("IP address is required for target ID")
        
        # Sanitize IP address
        ip_clean = ip.strip()
        
        if mac:
            # Validate and normalize MAC address
            mac_clean = mac.strip().lower().replace(':', '').replace('-', '')
            # Basic validation - MAC should be 12 hex characters
            if len(mac_clean) == 12 and all(c in '0123456789abcdef' for c in mac_clean):
                return f"{ip_clean}_{mac_clean}"
            else:
                # Invalid MAC format - use IP only
                logger.warning(f"Invalid MAC address format '{mac}', using IP only for target ID")
        
        # Use IP only (with hash to avoid conflicts)
        return f"{ip_clean}_ip{hashlib.md5(ip_clean.encode()).hexdigest()[:8]}"
    
    def check_target_changes(self, target_id: str, ports: str = None, 
                           vulnerabilities: str = None, services: str = None) -> bool:
        """
        Check if target state has changed since last analysis.
        
        Args:
            target_id: Target identifier
            ports: Current ports (comma-separated or JSON)
            vulnerabilities: Current vulnerabilities (JSON)
            services: Current services (JSON)
        
        Returns:
            bool: True if changes detected, False otherwise
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get current state from database
                cursor.execute("""
                    SELECT ports_hash, vulnerabilities_hash, services_hash
                    FROM target_intelligence
                    WHERE target_id = ?
                """, (target_id,))
                
                row = cursor.fetchone()
                
                if not row:
                    # New target - always needs evaluation
                    return True
                
                # Calculate new hashes
                new_ports_hash = self._calculate_hash(ports) if ports else ""
                new_vulns_hash = self._calculate_hash(vulnerabilities) if vulnerabilities else ""
                new_services_hash = self._calculate_hash(services) if services else ""
                
                # Compare hashes
                ports_changed = row['ports_hash'] != new_ports_hash
                vulns_changed = row['vulnerabilities_hash'] != new_vulns_hash
                services_changed = row['services_hash'] != new_services_hash
                
                return ports_changed or vulns_changed or services_changed
                
        except Exception as e:
            logger.error(f"Error checking target changes: {e}")
            return False
    
    def update_target_state(self, ip: str, mac: str = None, hostname: str = None,
                          ports: str = None, vulnerabilities: str = None, 
                          services: str = None) -> bool:
        """
        Update target state and detect changes.
        
        Args:
            ip: IP address
            mac: MAC address (optional)
            hostname: Hostname (optional)
            ports: Current ports
            vulnerabilities: Current vulnerabilities
            services: Current services
        
        Returns:
            bool: True if changes detected (needs AI evaluation)
        """
        try:
            target_id = self._create_target_id(ip, mac)
            
            # Check for changes
            has_changes = self.check_target_changes(target_id, ports, vulnerabilities, services)
            
            with self.get_connection() as conn:
                cursor = conn.cursor()
                now = datetime.now().isoformat()
                
                # Calculate hashes
                ports_hash = self._calculate_hash(ports) if ports else ""
                vulns_hash = self._calculate_hash(vulnerabilities) if vulnerabilities else ""
                services_hash = self._calculate_hash(services) if services else ""
                
                # Check if target exists
                cursor.execute("SELECT target_id FROM target_intelligence WHERE target_id = ?", (target_id,))
                exists = cursor.fetchone() is not None
                
                if exists:
                    # Update existing target
                    update_fields = []
                    update_values = []
                    
                    if ip is not None:
                        update_fields.append("ip_address = ?")
                        update_values.append(ip)
                    
                    if mac is not None:
                        update_fields.append("mac_address = ?")
                        update_values.append(mac)
                    
                    if hostname is not None:
                        update_fields.append("hostname = ?")
                        update_values.append(hostname)
                    
                    if ports_hash is not None:
                        update_fields.append("ports_hash = ?")
                        update_values.append(ports_hash)
                    
                    if vulns_hash is not None:
                        update_fields.append("vulnerabilities_hash = ?")
                        update_values.append(vulns_hash)
                    
                    if services_hash is not None:
                        update_fields.append("services_hash = ?")
                        update_values.append(services_hash)
                    
                    if ports is not None:
                        update_fields.append("current_ports = ?")
                        update_values.append(ports)
                    
                    if vulnerabilities is not None:
                        update_fields.append("current_vulnerabilities = ?")
                        update_values.append(vulnerabilities)
                    
                    if services is not None:
                        update_fields.append("current_services = ?")
                        update_values.append(services)
                    
                    # Always update last_seen
                    update_fields.append("last_seen = ?")
                    update_values.append(now)
                    
                    # Update state_changed flag
                    update_fields.append("state_changed = ?")
                    update_values.append(1 if has_changes else 0)
                    
                    # Update last_state_change if changes detected
                    if has_changes:
                        update_fields.append("last_state_change = ?")
                        update_values.append(now)
                        update_fields.append("needs_ai_evaluation = ?")
                        update_values.append(1)
                    
                    # Always update timestamp
                    update_fields.append("updated_at = ?")
                    update_values.append(now)
                    
                    # Add target_id for WHERE clause
                    update_values.append(target_id)
                    
                    sql = f"UPDATE target_intelligence SET {', '.join(update_fields)} WHERE target_id = ?"
                    cursor.execute(sql, update_values)
                    
                    if has_changes:
                        logger.info(f"Target {target_id} state changed - needs AI evaluation")
                else:
                    # Insert new target
                    cursor.execute("""
                        INSERT INTO target_intelligence
                        (target_id, ip_address, mac_address, hostname,
                         ports_hash, vulnerabilities_hash, services_hash,
                         current_ports, current_vulnerabilities, current_services,
                         last_seen, state_changed, last_state_change, needs_ai_evaluation)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 1)
                    """, (
                        target_id, ip, mac, hostname,
                        ports_hash, vulns_hash, services_hash,
                        ports, vulnerabilities, services,
                        now, now
                    ))
                    
                    logger.info(f"New target {target_id} added - needs AI evaluation")
                    has_changes = True
                
                # Record change history if changes detected
                if has_changes and exists:
                    self._record_change(cursor, target_id, "state_update", 
                                      "Target state updated with new data")
                
                conn.commit()
                return has_changes
                
        except Exception as e:
            logger.error(f"Error updating target state: {e}")
            return False
    
    def _record_change(self, cursor, target_id: str, change_type: str, 
                      description: str, old_value: str = None, new_value: str = None):
        """Record a change in the change history."""
        try:
            cursor.execute("""
                INSERT INTO target_change_history
                (target_id, change_type, change_description, old_value, new_value)
                VALUES (?, ?, ?, ?, ?)
            """, (target_id, change_type, description, old_value, new_value))
        except Exception as e:
            logger.error(f"Error recording change: {e}")
    
    def get_targets_needing_evaluation(self) -> List[Dict]:
        """
        Get all targets that need AI evaluation.
        
        Returns:
            List of target dictionaries
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM target_intelligence
                    WHERE needs_ai_evaluation = 1
                    AND status = 'active'
                    ORDER BY last_state_change DESC
                """)
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            logger.error(f"Error getting targets needing evaluation: {e}")
            return []
    
    def store_ai_analysis(self, target_id: str, analysis_trigger: str,
                         ai_summary: str = None, ai_risk_assessment: str = None,
                         ai_recommendations: str = None, ai_attack_vectors: str = None,
                         tokens_used: int = 0, analysis_duration_ms: int = 0) -> bool:
        """
        Store AI analysis results for a target.
        
        Args:
            target_id: Target identifier
            analysis_trigger: What triggered the analysis
            ai_summary: AI-generated summary
            ai_risk_assessment: Risk assessment
            ai_recommendations: Recommendations
            ai_attack_vectors: Attack vectors
            tokens_used: API tokens consumed
            analysis_duration_ms: Analysis duration in milliseconds
        
        Returns:
            bool: True if successful
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                now = datetime.now().isoformat()
                
                # Update target intelligence
                cursor.execute("""
                    UPDATE target_intelligence
                    SET ai_summary = ?,
                        ai_risk_assessment = ?,
                        ai_recommendations = ?,
                        ai_attack_vectors = ?,
                        last_ai_analysis = ?,
                        ai_analysis_count = ai_analysis_count + 1,
                        needs_ai_evaluation = 0,
                        state_changed = 0,
                        updated_at = ?
                    WHERE target_id = ?
                """, (
                    ai_summary, ai_risk_assessment, ai_recommendations, ai_attack_vectors,
                    now, now, target_id
                ))
                
                # Store in analysis history
                cursor.execute("""
                    INSERT INTO ai_analysis_history
                    (target_id, analysis_trigger, ai_summary, ai_risk_assessment,
                     ai_recommendations, ai_attack_vectors, tokens_used, analysis_duration_ms)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    target_id, analysis_trigger, ai_summary, ai_risk_assessment,
                    ai_recommendations, ai_attack_vectors, tokens_used, analysis_duration_ms
                ))
                
                # Mark change history as having triggered AI analysis
                cursor.execute("""
                    UPDATE target_change_history
                    SET triggered_ai_analysis = 1
                    WHERE target_id = ?
                    AND triggered_ai_analysis = 0
                """, (target_id,))
                
                conn.commit()
                logger.info(f"AI analysis stored for target {target_id}")
                return True
                
        except Exception as e:
            logger.error(f"Error storing AI analysis: {e}")
            return False
    
    def get_target_intelligence(self, target_id: str) -> Optional[Dict]:
        """Get AI intelligence for a specific target."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM target_intelligence
                    WHERE target_id = ?
                """, (target_id,))
                
                row = cursor.fetchone()
                return dict(row) if row else None
                
        except Exception as e:
            logger.error(f"Error getting target intelligence: {e}")
            return None
    
    def get_all_target_intelligence(self, status: str = 'active') -> List[Dict]:
        """Get AI intelligence for all targets."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                if status:
                    cursor.execute("""
                        SELECT * FROM target_intelligence
                        WHERE status = ?
                        ORDER BY last_ai_analysis DESC
                    """, (status,))
                else:
                    cursor.execute("""
                        SELECT * FROM target_intelligence
                        ORDER BY last_ai_analysis DESC
                    """)
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            logger.error(f"Error getting all target intelligence: {e}")
            return []
    
    def get_target_change_history(self, target_id: str, limit: int = 50) -> List[Dict]:
        """Get change history for a target."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM target_change_history
                    WHERE target_id = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (target_id, limit))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            logger.error(f"Error getting change history: {e}")
            return []
    
    def get_target_analysis_history(self, target_id: str, limit: int = 20) -> List[Dict]:
        """Get AI analysis history for a target."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM ai_analysis_history
                    WHERE target_id = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (target_id, limit))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            logger.error(f"Error getting analysis history: {e}")
            return []
    
    def get_statistics(self) -> Dict:
        """Get statistics about AI intelligence tracking."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                stats = {}
                
                # Total targets
                cursor.execute("SELECT COUNT(*) FROM target_intelligence")
                stats['total_targets'] = cursor.fetchone()[0]
                
                # Targets needing evaluation
                cursor.execute("""
                    SELECT COUNT(*) FROM target_intelligence
                    WHERE needs_ai_evaluation = 1 AND status = 'active'
                """)
                stats['targets_needing_evaluation'] = cursor.fetchone()[0]
                
                # Total AI analyses
                cursor.execute("SELECT COUNT(*) FROM ai_analysis_history")
                stats['total_ai_analyses'] = cursor.fetchone()[0]
                
                # Total changes recorded
                cursor.execute("SELECT COUNT(*) FROM target_change_history")
                stats['total_changes_recorded'] = cursor.fetchone()[0]
                
                # Average tokens per analysis (if any)
                cursor.execute("""
                    SELECT AVG(tokens_used) FROM ai_analysis_history
                    WHERE tokens_used > 0
                """)
                avg_tokens = cursor.fetchone()[0]
                stats['avg_tokens_per_analysis'] = int(avg_tokens) if avg_tokens else 0
                
                return stats
                
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}
    
    def cleanup_old_data(self, days: int = 30):
        """
        Clean up old inactive targets and history.
        
        Args:
            days: Remove data older than this many days
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cutoff_date = datetime.now() - timedelta(days=days)
                
                # Mark old targets as inactive
                cursor.execute("""
                    UPDATE target_intelligence
                    SET status = 'inactive'
                    WHERE last_seen < ?
                    AND status = 'active'
                """, (cutoff_date,))
                marked_inactive = cursor.rowcount
                
                # Clean up old change history
                cursor.execute("""
                    DELETE FROM target_change_history
                    WHERE timestamp < ?
                """, (cutoff_date,))
                history_deleted = cursor.rowcount
                
                conn.commit()
                logger.info(f"Cleanup: {marked_inactive} targets marked inactive, "
                          f"{history_deleted} old changes removed")
                
        except Exception as e:
            logger.error(f"Error cleaning up old data: {e}")


# Singleton instance
_ai_intel_manager = None
_ai_intel_lock = threading.Lock()


def get_ai_intelligence_manager(datadir: str = None) -> AIIntelligenceManager:
    """
    Get singleton AI Intelligence Manager instance.
    Thread-safe lazy initialization.
    """
    global _ai_intel_manager
    
    if _ai_intel_manager is None:
        with _ai_intel_lock:
            if _ai_intel_manager is None:
                _ai_intel_manager = AIIntelligenceManager(datadir=datadir)
    
    return _ai_intel_manager


if __name__ == "__main__":
    # Test the AI intelligence manager
    import logging
    logging.basicConfig(level=logging.DEBUG)
    
    manager = AIIntelligenceManager()
    
    # Test update and change detection
    manager.update_target_state(
        ip="192.168.1.100",
        mac="aa:bb:cc:dd:ee:ff",
        hostname="test-host",
        ports="22,80,443",
        vulnerabilities='{"CVE-2021-1234": "Critical"}',
        services='{"22": "SSH", "80": "HTTP"}'
    )
    
    # Get targets needing evaluation
    targets = manager.get_targets_needing_evaluation()
    print(f"Targets needing evaluation: {len(targets)}")
    
    # Get statistics
    stats = manager.get_statistics()
    print(f"Statistics: {stats}")
    
    print("AI Intelligence Manager tests completed!")
