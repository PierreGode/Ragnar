#!/usr/bin/env python3
"""
AI Target Evaluator for Ragnar
Coordinates dynamic AI evaluation of targets based on detected changes
Integrates AIIntelligenceManager with AIService for token-efficient analysis

Features:
- Dynamic evaluation triggered by target changes (not time-based)
- Per-target AI analysis with change detection
- Token optimization through change-based evaluation
- Automatic re-evaluation when targets are patched
"""

import os
import time
import logging
from datetime import datetime
from typing import Dict, List, Optional

from logger import Logger
from ai_intelligence_manager import get_ai_intelligence_manager

# Import AIService with fallback for environments without openai
try:
    from ai_service import AIService
except ImportError as e:
    # OpenAI not installed - AI evaluation will be disabled
    AIService = None
    import sys
    print(f"Warning: AIService unavailable ({e}), AI evaluation features disabled", file=sys.stderr)

logger = Logger(name="AITargetEvaluator", level=logging.INFO)


class AITargetEvaluator:
    """
    Evaluates targets using AI when changes are detected.
    Coordinates between AI Intelligence Manager and AI Service.
    """
    
    def __init__(self, shared_data):
        """
        Initialize the AI Target Evaluator.
        
        Args:
            shared_data: Shared data object containing configuration
        """
        self.shared_data = shared_data
        self.logger = logger
        
        # Get AI intelligence manager
        datadir = getattr(shared_data, 'datadir', None)
        self.ai_intel_manager = get_ai_intelligence_manager(datadir=datadir)
        
        # Get AI service (may be None if not configured)
        self.ai_service = getattr(shared_data, 'ai_service', None)
        
        # Configuration
        self.enabled = shared_data.config.get('ai_target_evaluation_enabled', True)
        self.batch_size = shared_data.config.get('ai_evaluation_batch_size', 5)
        self.evaluation_interval = shared_data.config.get('ai_evaluation_check_interval', 300)  # 5 minutes
        
        # State tracking
        self.last_evaluation_check = None
        self.evaluation_in_progress = False
        
        logger.info("AI Target Evaluator initialized")
    
    def is_enabled(self) -> bool:
        """Check if AI target evaluation is enabled and ready."""
        if not self.enabled:
            return False
        
        # Check if AI service is available and enabled
        if not self.ai_service:
            self.ai_service = getattr(self.shared_data, 'ai_service', None)
        
        if not self.ai_service or not self.ai_service.is_enabled():
            return False
        
        return True
    
    def check_and_update_target(self, ip: str, mac: str = None, hostname: str = None,
                               ports: str = None, vulnerabilities: str = None,
                               services: str = None) -> bool:
        """
        Check target for changes and update intelligence database.
        
        Args:
            ip: IP address
            mac: MAC address
            hostname: Hostname
            ports: Current ports
            vulnerabilities: Current vulnerabilities
            services: Current services
        
        Returns:
            bool: True if changes detected (target needs AI evaluation)
        """
        try:
            # Update target state and check for changes
            has_changes = self.ai_intel_manager.update_target_state(
                ip=ip,
                mac=mac,
                hostname=hostname,
                ports=ports,
                vulnerabilities=vulnerabilities,
                services=services
            )
            
            if has_changes:
                logger.info(f"Changes detected for target {ip} - marked for AI evaluation")
            
            return has_changes
            
        except Exception as e:
            logger.error(f"Error checking target {ip}: {e}")
            return False
    
    def evaluate_target(self, target_data: Dict) -> bool:
        """
        Perform AI evaluation of a single target.
        
        Args:
            target_data: Target intelligence data from database
        
        Returns:
            bool: True if successful
        """
        if not self.is_enabled():
            logger.warning("AI evaluation disabled or not available")
            return False
        
        try:
            target_id = target_data['target_id']
            ip = target_data['ip_address']
            
            logger.info(f"Starting AI evaluation for target {target_id}")
            start_time = time.time()
            
            # Prepare target context for AI
            context = self._prepare_target_context(target_data)
            
            # Get AI analysis for the target
            ai_summary = self._analyze_target_summary(context)
            ai_risk = self._analyze_target_risk(context)
            ai_recommendations = self._analyze_target_recommendations(context)
            ai_attack_vectors = self._analyze_attack_vectors(context)
            
            # Calculate analysis duration
            duration_ms = int((time.time() - start_time) * 1000)
            
            # Estimate tokens used (rough estimate based on response length)
            tokens_used = self._estimate_tokens(
                ai_summary, ai_risk, ai_recommendations, ai_attack_vectors
            )
            
            # Store AI analysis
            success = self.ai_intel_manager.store_ai_analysis(
                target_id=target_id,
                analysis_trigger="change_detected",
                ai_summary=ai_summary,
                ai_risk_assessment=ai_risk,
                ai_recommendations=ai_recommendations,
                ai_attack_vectors=ai_attack_vectors,
                tokens_used=tokens_used,
                analysis_duration_ms=duration_ms
            )
            
            if success:
                logger.info(f"AI evaluation completed for {target_id} "
                          f"(duration: {duration_ms}ms, tokens: {tokens_used})")
            
            return success
            
        except Exception as e:
            logger.error(f"Error evaluating target: {e}")
            return False
    
    def _prepare_target_context(self, target_data: Dict) -> Dict:
        """Prepare context data for AI analysis."""
        context = {
            'ip': target_data.get('ip_address', 'Unknown'),
            'hostname': target_data.get('hostname', 'Unknown'),
            'mac': target_data.get('mac_address', 'Unknown'),
            'ports': target_data.get('current_ports', ''),
            'vulnerabilities': target_data.get('current_vulnerabilities', ''),
            'services': target_data.get('current_services', ''),
            'first_seen': target_data.get('first_seen', ''),
            'last_seen': target_data.get('last_seen', ''),
            'previous_analysis_count': target_data.get('ai_analysis_count', 0),
        }
        return context
    
    def _analyze_target_summary(self, context: Dict) -> Optional[str]:
        """Generate AI summary for target."""
        if not self.ai_service:
            return None
        
        try:
            system = (
                "You are Ragnar, a tactical cybersecurity analyst. "
                "Provide concise, actionable summaries of network targets."
            )
            
            user = f"""
Analyze this network target:

IP: {context['ip']}
Hostname: {context['hostname']}
MAC: {context['mac']}
Open Ports: {context['ports']}
Vulnerabilities: {context['vulnerabilities']}
Services: {context['services']}

Provide a 2-3 sentence tactical summary of this target's security posture.
"""
            
            return self.ai_service._ask(system, user)
            
        except Exception as e:
            logger.error(f"Error generating target summary: {e}")
            return None
    
    def _analyze_target_risk(self, context: Dict) -> Optional[str]:
        """Generate AI risk assessment for target."""
        if not self.ai_service:
            return None
        
        try:
            system = (
                "You are Ragnar, a cybersecurity risk analyst. "
                "Assess risk levels and severity for network targets."
            )
            
            user = f"""
Assess the risk for this target:

IP: {context['ip']}
Hostname: {context['hostname']}
Open Ports: {context['ports']}
Vulnerabilities: {context['vulnerabilities']}

Provide:
- Overall risk level (Critical/High/Medium/Low)
- Key risk factors
- Exploitation likelihood
"""
            
            return self.ai_service._ask(system, user)
            
        except Exception as e:
            logger.error(f"Error generating risk assessment: {e}")
            return None
    
    def _analyze_target_recommendations(self, context: Dict) -> Optional[str]:
        """Generate AI recommendations for target."""
        if not self.ai_service:
            return None
        
        try:
            system = (
                "You are Ragnar, a cybersecurity remediation expert. "
                "Provide practical, prioritized security recommendations."
            )
            
            user = f"""
Provide remediation recommendations for:

IP: {context['ip']}
Hostname: {context['hostname']}
Open Ports: {context['ports']}
Vulnerabilities: {context['vulnerabilities']}
Services: {context['services']}

List top 3 prioritized actions to secure this target.
"""
            
            return self.ai_service._ask(system, user)
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {e}")
            return None
    
    def _analyze_attack_vectors(self, context: Dict) -> Optional[str]:
        """Generate AI attack vector analysis for target."""
        if not self.ai_service:
            return None
        
        try:
            system = (
                "You are Ragnar, a penetration testing expert. "
                "Identify potential attack vectors and exploitation paths."
            )
            
            user = f"""
Identify attack vectors for:

IP: {context['ip']}
Open Ports: {context['ports']}
Vulnerabilities: {context['vulnerabilities']}
Services: {context['services']}

List 2-3 most viable attack vectors with exploitation methods.
"""
            
            return self.ai_service._ask(system, user)
            
        except Exception as e:
            logger.error(f"Error analyzing attack vectors: {e}")
            return None
    
    def _estimate_tokens(self, *texts) -> int:
        """Estimate tokens used based on text length."""
        total_chars = sum(len(str(t)) for t in texts if t)
        # Rough estimate: ~4 characters per token
        return int(total_chars / 4)
    
    def process_pending_evaluations(self, max_targets: int = None) -> int:
        """
        Process targets that need AI evaluation.
        
        Args:
            max_targets: Maximum number of targets to evaluate (None for batch_size)
        
        Returns:
            int: Number of targets evaluated
        """
        if not self.is_enabled():
            logger.debug("AI evaluation disabled or not available")
            return 0
        
        if self.evaluation_in_progress:
            logger.debug("Evaluation already in progress")
            return 0
        
        try:
            self.evaluation_in_progress = True
            max_targets = max_targets or self.batch_size
            
            # Get targets needing evaluation
            targets = self.ai_intel_manager.get_targets_needing_evaluation()
            
            if not targets:
                logger.debug("No targets need AI evaluation")
                return 0
            
            logger.info(f"Found {len(targets)} targets needing AI evaluation")
            
            # Process up to max_targets
            evaluated_count = 0
            for target in targets[:max_targets]:
                try:
                    if self.evaluate_target(target):
                        evaluated_count += 1
                    else:
                        logger.warning(f"Failed to evaluate target {target['target_id']}")
                except Exception as e:
                    logger.error(f"Error evaluating target {target['target_id']}: {e}")
                    continue
            
            logger.info(f"Evaluated {evaluated_count} targets")
            return evaluated_count
            
        except Exception as e:
            logger.error(f"Error processing pending evaluations: {e}")
            return 0
        finally:
            self.evaluation_in_progress = False
            self.last_evaluation_check = datetime.now()
    
    def get_target_intelligence(self, target_id: str) -> Optional[Dict]:
        """Get AI intelligence for a specific target."""
        return self.ai_intel_manager.get_target_intelligence(target_id)
    
    def get_all_intelligence(self) -> List[Dict]:
        """Get AI intelligence for all active targets."""
        return self.ai_intel_manager.get_all_target_intelligence(status='active')
    
    def get_statistics(self) -> Dict:
        """Get AI evaluation statistics."""
        return self.ai_intel_manager.get_statistics()


# Singleton instance
_ai_target_evaluator = None


def get_ai_target_evaluator(shared_data) -> AITargetEvaluator:
    """
    Get singleton AI Target Evaluator instance.
    
    Args:
        shared_data: Shared data object
    
    Returns:
        AITargetEvaluator instance
    """
    global _ai_target_evaluator
    
    if _ai_target_evaluator is None:
        _ai_target_evaluator = AITargetEvaluator(shared_data)
    
    return _ai_target_evaluator


if __name__ == "__main__":
    # Test the AI target evaluator
    import logging
    logging.basicConfig(level=logging.DEBUG)
    
    # Mock shared_data for testing
    class MockSharedData:
        def __init__(self):
            self.datadir = 'data'
            self.config = {
                'ai_target_evaluation_enabled': True,
                'ai_evaluation_batch_size': 5
            }
            self.ai_service = None
    
    shared_data = MockSharedData()
    evaluator = AITargetEvaluator(shared_data)
    
    # Test check and update
    evaluator.check_and_update_target(
        ip="192.168.1.100",
        mac="aa:bb:cc:dd:ee:ff",
        hostname="test-host",
        ports="22,80,443",
        vulnerabilities='{"CVE-2021-1234": "Critical"}'
    )
    
    # Get statistics
    stats = evaluator.get_statistics()
    print(f"Statistics: {stats}")
    
    print("AI Target Evaluator tests completed!")
