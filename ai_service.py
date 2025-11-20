#!/usr/bin/env python3
"""
AI Service for Ragnar
Provides intelligent network analysis and vulnerability summaries using OpenAI GPT-5 Nano
Similar to PWNAGOTCHI's personality and analysis capabilities
"""

import os
import json
import time
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from logger import Logger

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False


class AIService:
    """AI-powered network analysis and vulnerability assessment service"""
    
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.logger = Logger(name="AIService", level=logging.INFO)
        
        # Configuration
        self.enabled = shared_data.config.get('ai_enabled', False)
        self.api_token = shared_data.config.get('openai_api_token', '')
        self.model = shared_data.config.get('ai_model', 'gpt-5-nano')
        self.max_tokens = shared_data.config.get('ai_max_tokens', 500)
        self.temperature = shared_data.config.get('ai_temperature', 0.7)
        
        # Analysis capabilities
        self.vulnerability_summaries = shared_data.config.get('ai_vulnerability_summaries', True)
        self.network_insights = shared_data.config.get('ai_network_insights', True)
        
        # Cache for AI responses
        self.cache = {}
        self.cache_ttl = 300  # 5 minutes cache
        
        # Initialize OpenAI client if available
        self.client = None
        if self.enabled and OPENAI_AVAILABLE and self.api_token:
            try:
                openai.api_key = self.api_token
                self.client = openai
                self.logger.info("AI Service initialized with OpenAI GPT-5 Nano")
            except Exception as e:
                self.logger.error(f"Failed to initialize OpenAI client: {e}")
                self.enabled = False
        elif self.enabled and not OPENAI_AVAILABLE:
            self.logger.warning("AI enabled but OpenAI library not available. Install with: pip install openai")
            self.enabled = False
        elif self.enabled and not self.api_token:
            self.logger.warning("AI enabled but no API token configured")
            self.enabled = False
    
    def is_enabled(self) -> bool:
        """Check if AI service is enabled and ready"""
        return self.enabled and self.client is not None
    
    def _get_cache_key(self, prompt: str, context: Dict) -> str:
        """Generate cache key for a prompt and context"""
        import hashlib
        content = f"{prompt}_{json.dumps(context, sort_keys=True)}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def _get_cached_response(self, cache_key: str) -> Optional[str]:
        """Get cached AI response if available and not expired"""
        if cache_key in self.cache:
            cached_data = self.cache[cache_key]
            if time.time() - cached_data['timestamp'] < self.cache_ttl:
                self.logger.debug(f"Using cached AI response for key: {cache_key[:8]}...")
                return cached_data['response']
            else:
                # Remove expired cache
                del self.cache[cache_key]
        return None
    
    def _cache_response(self, cache_key: str, response: str):
        """Cache an AI response"""
        self.cache[cache_key] = {
            'response': response,
            'timestamp': time.time()
        }
    
    def _call_openai(self, prompt: str, system_prompt: str = None) -> Optional[str]:
        """Make a call to OpenAI API"""
        if not self.is_enabled():
            return None
        
        try:
            messages = []
            
            if system_prompt:
                messages.append({
                    "role": "system",
                    "content": system_prompt
                })
            
            messages.append({
                "role": "user",
                "content": prompt
            })
            
            # Call OpenAI API
            response = self.client.ChatCompletion.create(
                model=self.model,
                messages=messages,
                max_tokens=self.max_tokens,
                temperature=self.temperature
            )
            
            # Extract response text
            if response and response.choices:
                return response.choices[0].message.content.strip()
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error calling OpenAI API: {e}")
            return None
    
    def analyze_network_summary(self, network_data: Dict) -> Optional[str]:
        """Generate AI-powered network analysis summary
        
        Args:
            network_data: Dictionary containing network statistics and findings
            
        Returns:
            AI-generated summary or None if AI is disabled
        """
        if not self.is_enabled() or not self.network_insights:
            return None
        
        try:
            # Create cache key
            cache_key = self._get_cache_key("network_summary", network_data)
            
            # Check cache
            cached = self._get_cached_response(cache_key)
            if cached:
                return cached
            
            # Prepare network data summary
            targets = network_data.get('target_count', 0)
            ports = network_data.get('port_count', 0)
            vulnerabilities = network_data.get('vulnerability_count', 0)
            credentials = network_data.get('credential_count', 0)
            
            system_prompt = """You are Ragnar, a cybersecurity AI assistant similar to PWNAGOTCHI. 
You are knowledgeable, witty, and provide insightful analysis of network security.
Your responses should be concise, actionable, and occasionally include a touch of personality.
You help identify network weaknesses and provide strategic recommendations."""
            
            prompt = f"""Analyze this network scan data and provide a brief security summary:

Network Statistics:
- Active Targets: {targets}
- Open Ports: {ports}
- Vulnerabilities Found: {vulnerabilities}
- Credentials Discovered: {credentials}

Provide a 2-3 sentence summary of the network's security posture and key findings.
Focus on the most critical insights and actionable recommendations."""
            
            # Get AI response
            response = self._call_openai(prompt, system_prompt)
            
            if response:
                self._cache_response(cache_key, response)
                return response
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error generating network summary: {e}")
            return None
    
    def analyze_vulnerabilities(self, vulnerabilities: List[Dict]) -> Optional[str]:
        """Generate AI-powered vulnerability analysis
        
        Args:
            vulnerabilities: List of vulnerability findings
            
        Returns:
            AI-generated analysis or None if AI is disabled
        """
        if not self.is_enabled() or not self.vulnerability_summaries:
            return None
        
        try:
            # Create cache key
            cache_key = self._get_cache_key("vulnerability_analysis", {'count': len(vulnerabilities)})
            
            # Check cache
            cached = self._get_cached_response(cache_key)
            if cached:
                return cached
            
            # Prepare vulnerability summary
            vuln_summary = []
            for vuln in vulnerabilities[:10]:  # Limit to top 10
                vuln_info = {
                    'host': vuln.get('host', 'unknown'),
                    'service': vuln.get('service', 'unknown'),
                    'severity': vuln.get('severity', 'unknown'),
                    'vulnerability': vuln.get('vulnerability', 'unknown')
                }
                vuln_summary.append(vuln_info)
            
            system_prompt = """You are Ragnar, a cybersecurity AI assistant with expertise in vulnerability assessment.
You help prioritize security findings and provide clear, actionable remediation advice.
Keep your analysis concise and focused on the most critical issues."""
            
            prompt = f"""Analyze these vulnerabilities and provide key insights:

Total Vulnerabilities: {len(vulnerabilities)}

Top Findings:
{json.dumps(vuln_summary, indent=2)}

Provide a brief analysis focusing on:
1. Most critical vulnerabilities
2. Recommended priority for remediation
3. Overall risk assessment

Keep it to 3-4 sentences."""
            
            # Get AI response
            response = self._call_openai(prompt, system_prompt)
            
            if response:
                self._cache_response(cache_key, response)
                return response
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error analyzing vulnerabilities: {e}")
            return None
    
    def identify_network_weaknesses(self, network_data: Dict, findings: List[Dict]) -> Optional[str]:
        """Identify network weaknesses and attack vectors
        
        Args:
            network_data: Network statistics and topology data
            findings: Security findings (vulnerabilities, open ports, etc.)
            
        Returns:
            AI-generated weakness analysis or None if AI is disabled
        """
        if not self.is_enabled():
            return None
        
        try:
            # Create cache key
            cache_key = self._get_cache_key("network_weaknesses", {
                'targets': network_data.get('target_count', 0),
                'findings_count': len(findings)
            })
            
            # Check cache
            cached = self._get_cached_response(cache_key)
            if cached:
                return cached
            
            targets = network_data.get('target_count', 0)
            ports = network_data.get('port_count', 0)
            
            # Summarize findings
            findings_summary = []
            for finding in findings[:5]:  # Limit to top 5
                findings_summary.append({
                    'type': finding.get('type', 'unknown'),
                    'host': finding.get('host', 'unknown'),
                    'severity': finding.get('severity', 'unknown')
                })
            
            system_prompt = """You are Ragnar, an expert in network penetration testing and security assessment.
You identify attack vectors, weaknesses, and potential exploitation paths.
Provide tactical insights that would help both attackers and defenders."""
            
            prompt = f"""Analyze this network for potential weaknesses and attack vectors:

Network Overview:
- Devices: {targets}
- Open Ports: {ports}

Key Findings:
{json.dumps(findings_summary, indent=2)}

Identify the top 2-3 network weaknesses and potential attack vectors.
Keep it concise and actionable."""
            
            # Get AI response
            response = self._call_openai(prompt, system_prompt)
            
            if response:
                self._cache_response(cache_key, response)
                return response
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error identifying network weaknesses: {e}")
            return None
    
    def generate_insights(self) -> Dict[str, Any]:
        """Generate comprehensive AI insights for the current network state
        
        Returns:
            Dictionary containing various AI-generated insights
        """
        insights = {
            'enabled': self.is_enabled(),
            'timestamp': datetime.now().isoformat(),
            'network_summary': None,
            'vulnerability_analysis': None,
            'weakness_analysis': None
        }
        
        if not self.is_enabled():
            insights['message'] = "AI service is not enabled or configured"
            return insights
        
        try:
            # Get network data
            network_data = {
                'target_count': self.shared_data.targetnbr,
                'port_count': self.shared_data.portnbr,
                'vulnerability_count': self.shared_data.vulnnbr,
                'credential_count': self.shared_data.crednbr
            }
            
            # Generate network summary
            if self.network_insights:
                insights['network_summary'] = self.analyze_network_summary(network_data)
            
            # Get vulnerabilities from network intelligence
            if (hasattr(self.shared_data, 'network_intelligence') and 
                self.shared_data.network_intelligence and
                self.vulnerability_summaries):
                
                findings = self.shared_data.network_intelligence.get_active_findings_for_dashboard()
                vulnerabilities = list(findings.get('vulnerabilities', {}).values())
                
                if vulnerabilities:
                    insights['vulnerability_analysis'] = self.analyze_vulnerabilities(vulnerabilities)
                    
                    # Also generate weakness analysis
                    all_findings = vulnerabilities + list(findings.get('credentials', {}).values())
                    insights['weakness_analysis'] = self.identify_network_weaknesses(network_data, all_findings)
            
            return insights
            
        except Exception as e:
            self.logger.error(f"Error generating insights: {e}")
            insights['error'] = str(e)
            return insights
    
    def clear_cache(self):
        """Clear the AI response cache"""
        self.cache = {}
        self.logger.info("AI response cache cleared")
