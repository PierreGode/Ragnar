#!/usr/bin/env python3
"""
AI Service for Ragnar
GPT-5-nano version using OpenAI SDK 2.x
Provides intelligent network analysis, summaries, and insights
"""

import os
import json
import time
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any

from logger import Logger
from env_manager import EnvManager

# OpenAI SDK (modern 2.x)
try:
    from openai import OpenAI
    OPENAI_SDK_OK = True
except Exception:
    OPENAI_SDK_OK = False
    OpenAI = None


class AIService:
    """AI-powered network analysis and vulnerability assessment service"""

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.logger = Logger(name="AIService", level=logging.INFO)
        self.env_manager = EnvManager()

        # Configuration (kept exactly as original for compatibility)
        cfg = shared_data.config
        self.enabled = cfg.get('ai_enabled', False)
        self.model = cfg.get('ai_model', 'gpt-5-nano')
        self.max_tokens = cfg.get('ai_max_tokens', 500)
        self.temperature = cfg.get('ai_temperature', 0.7)
        self.vulnerability_summaries = cfg.get('ai_vulnerability_summaries', True)
        self.network_insights = cfg.get('ai_network_insights', True)

        # Token from environment manager
        self.api_token = self.env_manager.get_token()

        # Cache
        self.cache = {}
        self.cache_ttl = 300  # seconds

        # Initialization status
        self.client = None
        self.initialization_error = None

        self._initialize_client()

    # -----------------------------------------------------------
    # Initialization
    # -----------------------------------------------------------

    def _initialize_client(self):
        """Initialize OpenAI client if possible"""
        if not self.enabled:
            return

        if not OPENAI_SDK_OK:
            self.initialization_error = (
                "OpenAI library missing: install using pip3 install openai --break-system-packages"
            )
            return

        if not self.api_token:
            self.initialization_error = "No API token found in environment or .env"
            return

        try:
            self.client = OpenAI(api_key=self.api_token)
            self.logger.info(f"AI Service initialized using model: {self.model}")
        except Exception as e:
            self.initialization_error = f"Failed to initialize OpenAI client: {e}"
            self.logger.error(self.initialization_error)

    # -----------------------------------------------------------
    # Utility
    # -----------------------------------------------------------

    def is_enabled(self):
        return self.enabled and self.client is not None and self.initialization_error is None

    def _cache_key(self, name: str, content: Any):
        import hashlib
        raw = f"{name}:{json.dumps(content, sort_keys=True)}"
        return hashlib.md5(raw.encode()).hexdigest()

    def _cache_get(self, key: str):
        item = self.cache.get(key)
        if not item:
            return None
        if time.time() - item['timestamp'] > self.cache_ttl:
            del self.cache[key]
            return None
        return item['value']

    def _cache_set(self, key: str, value: Any):
        self.cache[key] = {"timestamp": time.time(), "value": value}

    # -----------------------------------------------------------
    # Core OpenAI Call (GPT-5-nano)
    # Includes Token Logging
    # -----------------------------------------------------------

    def _ask(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        if not self.is_enabled():
            return None

        try:
            result = self.client.responses.create(
                model=self.model,
                input=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                max_output_tokens=self.max_tokens,
                temperature=self.temperature
            )

            output = result.output_text

            # Token logging (you enabled this)
            if hasattr(result, "usage"):
                u = result.usage
                self.logger.info(
                    f"AI Tokens → input:{u.input_tokens} output:{u.output_tokens} total:{u.total_tokens}"
                )

            return output.strip()

        except Exception as e:
            self.logger.error(f"OpenAI request failed: {e}")
            return None

    # -----------------------------------------------------------
    # Network Summary
    # -----------------------------------------------------------

    def analyze_network_summary(self, network_data):
        if not self.is_enabled() or not self.network_insights:
            return None

        key = self._cache_key("summary", network_data)
        cached = self._cache_get(key)
        if cached:
            return cached

        system_prompt = (
            "You are Ragnar, a witty cybersecurity Viking AI. "
            "Provide concise, sharp insights with a hint of personality."
        )

        user_prompt = f"""
Analyze this network scan:

Targets: {network_data.get('target_count', 0)}
Open Ports: {network_data.get('port_count', 0)}
Vulnerabilities Found: {network_data.get('vulnerability_count', 0)}
Credentials Found: {network_data.get('credential_count', 0)}

Give a 2–3 sentence summary in Ragnar's tone.
"""

        resp = self._ask(system_prompt, user_prompt)
        if resp:
            self._cache_set(key, resp)
        return resp

    # -----------------------------------------------------------
    # Vulnerability Analysis
    # -----------------------------------------------------------

    def analyze_vulnerabilities(self, vulnerabilities: List[Dict]):
        if not self.is_enabled() or not self.vulnerability_summaries:
            return None

        key = self._cache_key("vuln_analysis", {"count": len(vulnerabilities)})
        cached = self._cache_get(key)
        if cached:
            return cached

        top = vulnerabilities[:10]
        user_data = json.dumps(top, indent=2)

        system_prompt = (
            "You are Ragnar, an elite vulnerability analyst. "
            "Provide critical, actionable advice with high clarity."
        )

        user_prompt = f"""
Analyze these vulnerabilities:

Total: {len(vulnerabilities)}

Top Findings:
{user_data}

Provide:
1. The most critical weaknesses
2. What should be fixed *first*
3. Overall attack risk

Keep it short, sharp, and Viking-like.
"""

        resp = self._ask(system_prompt, user_prompt)
        if resp:
            self._cache_set(key, resp)
        return resp

    # -----------------------------------------------------------
    # Weakness Identification
    # -----------------------------------------------------------

    def identify_network_weaknesses(self, network_data: Dict, findings: List[Dict]):
        if not self.is_enabled():
            return None

        key = self._cache_key("weakness", {"targets": network_data.get("target_count", 0),
                                           "findings": len(findings)})
        cached = self._cache_get(key)
        if cached:
            return cached

        sample = findings[:5]
        fjson = json.dumps(sample, indent=2)

        system_prompt = (
            "You are Ragnar, a penetration strategist. "
            "Identify attack paths with tactical precision."
        )

        user_prompt = f"""
Devices: {network_data.get('target_count', 0)}
Ports: {network_data.get('port_count', 0)}

Key Findings:
{fjson}

Identify 2–3 attack vectors Ragnar would exploit.
"""

        resp = self._ask(system_prompt, user_prompt)
        if resp:
            self._cache_set(key, resp)
        return resp

    # -----------------------------------------------------------
    # Parallel Future Support (requested)
    # -----------------------------------------------------------

    def analyze_batch(self, tasks: List[Dict]) -> List[Optional[str]]:
        """
        Prepares Ragnar for future parallel insight pipelines.
        Currently runs sequentially but structure supports parallelization.
        """
        results = []
        for t in tasks:
            results.append(self._ask(t["system"], t["user"]))
        return results

    # -----------------------------------------------------------
    # Generate Combined Insights
    # -----------------------------------------------------------

    def generate_insights(self):
        output = {
            "enabled": self.is_enabled(),
            "timestamp": datetime.now().isoformat(),
            "network_summary": None,
            "vulnerability_analysis": None,
            "weakness_analysis": None
        }

        if not self.is_enabled():
            output["message"] = self.initialization_error or "AI is disabled"
            return output

        # Basic network data
        net = {
            'target_count': self.shared_data.targetnbr,
            'port_count': self.shared_data.portnbr,
            'vulnerability_count': self.shared_data.vulnnbr,
            'credential_count': self.shared_data.crednbr
        }

        # Summary
        output['network_summary'] = self.analyze_network_summary(net)

        # Vulnerabilities + weaknesses
        if hasattr(self.shared_data, "network_intelligence") and self.shared_data.network_intelligence:
            findings = self.shared_data.network_intelligence.get_active_findings_for_dashboard()
            vulns = list(findings.get('vulnerabilities', {}).values())

            if vulns:
                output['vulnerability_analysis'] = self.analyze_vulnerabilities(vulns)

                creds = list(findings.get('credentials', {}).values())
                combined = vulns + creds
                output['weakness_analysis'] = self.identify_network_weaknesses(net, combined)

        return output

    # -----------------------------------------------------------
    # Cache Clear
    # -----------------------------------------------------------

    def clear_cache(self):
        self.cache.clear()
        self.logger.info("AI cache cleared")
