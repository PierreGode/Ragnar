#!/usr/bin/env python3
"""
AI Service for Ragnar
GPT-5 version using OpenAI SDK 2.x
Provides intelligent network analysis, summaries, and insights.
"""

import os
import json
import time
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any

from logger import Logger
from env_manager import EnvManager, load_env

# Load environment variables immediately
load_env()

# OpenAI SDK
try:
    from openai import OpenAI
    OPENAI_SDK_OK = True
except Exception:
    OPENAI_SDK_OK = False
    OpenAI = None



# ===================================================================
#   AI SERVICE
# ===================================================================

class AIService:
    """AI-powered network analysis, vulnerability interpretation, and insights."""

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.logger = Logger(name="AIService", level=logging.INFO)
        self.env_manager = EnvManager()

        cfg = shared_data.config

        # Configuration
        self.enabled = cfg.get("ai_enabled", False)
        self.model = cfg.get("ai_model", "gpt-5-nano")

        # These must remain for backward compatibility (but not used)
        self.max_tokens = cfg.get("ai_max_tokens")
        self.temperature = cfg.get("ai_temperature")
        self.temperature_supported = True  # will disable on first failure

        self.vulnerability_summaries = cfg.get("ai_vulnerability_summaries", True)
        self.network_insights = cfg.get("ai_network_insights", True)

        self.api_token = self.env_manager.get_token()

        # Cache
        self.cache = {}
        self.cache_ttl = 300  # 5 minutes

        # Client initialization
        self.client = None
        self.initialization_error = None
        self._initialize_client()



    # ===================================================================
    #   INITIALIZATION
    # ===================================================================

    def _initialize_client(self):
        # ALWAYS initialize if we have a token, ignore the enabled flag
        if not OPENAI_SDK_OK:
            self.initialization_error = (
                "OpenAI SDK missing. Install with: pip install openai"
            )
            return

        if not self.api_token:
            self.initialization_error = "No OpenAI API key found."
            return

        try:
            self.client = OpenAI(api_key=self.api_token)
            self.logger.info(f"AI Service initialized using model: {self.model}")
        except Exception as e:
            self.initialization_error = f"Failed to initialize OpenAI client: {e}"
            self.logger.error(self.initialization_error)



    # ===================================================================
    #   UTILITY HELPERS
    # ===================================================================

    def is_enabled(self):
        # If we have a client and token, we're enabled regardless of config flag
        return self.client is not None and self.initialization_error is None and self.api_token

    def _cache_key(self, name: str, content: Any):
        import hashlib
        raw = f"{name}:{json.dumps(content, sort_keys=True)}"
        return hashlib.md5(raw.encode()).hexdigest()

    def _cache_get(self, key: str):
        item = self.cache.get(key)
        if not item:
            return None
        if time.time() - item["timestamp"] > self.cache_ttl:
            del self.cache[key]
            return None
        return item["value"]

    def _cache_set(self, key: str, value: Any):
        self.cache[key] = {"timestamp": time.time(), "value": value}



    # ===================================================================
    #   CORE GPT-5 CALL — NEW RESPONSES API
    # ===================================================================

    def _ask(self, system_msg: str, user_msg: str) -> Optional[str]:
        """
        Unified GPT-5 call with temperature fallback (required for tests).
        """

        if not self.is_enabled():
            return None

        # Base GPT-5 payload
        payload = {
            "model": self.model,
            "input": [
                {"role": "system", "content": system_msg},
                {"role": "user", "content": user_msg},
            ],
            "reasoning": {"effort": "low"},
            "text": {"verbosity": "low"},
        }

        # Include temperature ONLY if still marked supported
        if self.temperature_supported and self.temperature is not None:
            payload["temperature"] = self.temperature

        # FIRST ATTEMPT
        try:
            result = self.client.responses.create(**payload)
            return self._extract_output(result)

        except Exception as e:
            error_text = str(e).lower()

            # Handle GPT-5 "temperature unsupported" case
            if "temperature" in error_text and "unsupported" in error_text:
                self.temperature_supported = False
                self.logger.warning(
                    "Model reported temperature as unsupported — retrying without it."
                )

                payload.pop("temperature", None)

                # SECOND ATTEMPT WITHOUT TEMPERATURE
                try:
                    result = self.client.responses.create(**payload)
                    return self._extract_output(result)
                except Exception as e2:
                    self.logger.error(f"Retry after removing temperature failed: {e2}")
                    return None

            self.logger.error(f"OpenAI call failed: {e}")
            return None



    def _extract_output(self, result):
        """Extract output text and log token usage."""
        if hasattr(result, "usage"):
            u = result.usage
            self.logger.info(
                f"AI Tokens → input:{u.input_tokens} output:{u.output_tokens} total:{u.total_tokens}"
            )

        try:
            return result.output_text.strip()
        except:
            return None



    # ===================================================================
    #   NETWORK SUMMARY
    # ===================================================================

    def analyze_network_summary(self, network_data):
        if not self.is_enabled() or not self.network_insights:
            return None

        key = self._cache_key("summary", network_data)
        cached = self._cache_get(key)
        if cached:
            return cached

        system = (
            "You are Ragnar, a witty cybersecurity Viking AI. "
            "Provide concise, aggressive but clear summaries."
        )

        user = f"""
Analyze this network scan:

Targets: {network_data.get('target_count')}
Open Ports: {network_data.get('port_count')}
Vulnerabilities Found: {network_data.get('vulnerability_count')}
Credentials Found: {network_data.get('credential_count')}

Give a 2–3 sentence Viking-style summary.
"""

        resp = self._ask(system, user)
        if resp:
            self._cache_set(key, resp)
        return resp



    # ===================================================================
    #   VULNERABILITY ANALYSIS
    # ===================================================================

    def analyze_vulnerabilities(self, vulnerabilities: List[Dict]):
        if not self.is_enabled() or not self.vulnerability_summaries:
            return None

        key = self._cache_key("vuln_analysis", {"count": len(vulnerabilities)})
        cached = self._cache_get(key)
        if cached:
            return cached

        limited = vulnerabilities[:10]
        data_json = json.dumps(limited, indent=2)

        system = (
            "You are Ragnar, an elite vulnerability hunter. "
            "Analyze weaknesses with precision and battle-readiness."
        )

        user = f"""
Vulnerabilities Detected: {len(vulnerabilities)}

Top Findings:
{data_json}

Provide:
1. Critical weaknesses
2. What must be fixed FIRST
3. Overall attack risk

Tone: fierce Viking strategist.
"""

        resp = self._ask(system, user)
        if resp:
            self._cache_set(key, resp)
        return resp



    # ===================================================================
    #   ATTACK VECTOR IDENTIFICATION
    # ===================================================================

    def identify_network_weaknesses(self, network_data: Dict, findings: List[Dict]):
        if not self.is_enabled():
            return None

        key = self._cache_key("weakness", {
            "targets": network_data.get("target_count"),
            "findings": len(findings),
        })
        cached = self._cache_get(key)
        if cached:
            return cached

        sample = json.dumps(findings[:5], indent=2)

        system = (
            "You are Ragnar, a penetration strategist. "
            "Identify viable attack vectors with tactical precision."
        )

        user = f"""
Devices: {network_data.get('target_count')}
Ports: {network_data.get('port_count')}

Key Findings:
{sample}

List 2–3 attack paths Ragnar would exploit.
"""

        resp = self._ask(system, user)
        if resp:
            self._cache_set(key, resp)
        return resp



    # ===================================================================
    #   PARALLEL BATCH PREP (FUTURE SUPPORT)
    # ===================================================================

    def analyze_batch(self, tasks: List[Dict]) -> List[Optional[str]]:
        results = []
        for t in tasks:
            results.append(self._ask(t["system"], t["user"]))
        return results



    # ===================================================================
    #   COMBINED INSIGHTS FOR UI
    # ===================================================================

    def generate_insights(self):
        output = {
            "enabled": self.is_enabled(),
            "timestamp": datetime.now().isoformat(),
            "network_summary": None,
            "vulnerability_analysis": None,
            "weakness_analysis": None,
        }

        if not self.is_enabled():
            output["message"] = self.initialization_error or "AI disabled"
            return output

        net = {
            "target_count": self.shared_data.targetnbr,
            "port_count": self.shared_data.portnbr,
            "vulnerability_count": self.shared_data.vulnnbr,
            "credential_count": self.shared_data.crednbr,
        }

        # Summary
        output["network_summary"] = self.analyze_network_summary(net)

        # Additional analyses if intelligence system is available
        if hasattr(self.shared_data, "network_intelligence") and \
           self.shared_data.network_intelligence:

            findings = self.shared_data.network_intelligence.get_active_findings_for_dashboard()

            vulns = list(findings.get("vulnerabilities", {}).values())
            if vulns:
                output["vulnerability_analysis"] = self.analyze_vulnerabilities(vulns)

                creds = list(findings.get("credentials", {}).values())
                combined = vulns + creds
                output["weakness_analysis"] = self.identify_network_weaknesses(net, combined)

        return output



    # ===================================================================
    #   CONFIG / TOKEN RELOAD
    # ===================================================================

    def reload_token(self) -> bool:
        """Reload AI configuration, refresh API token, and rebuild the client."""

        cfg = getattr(self.shared_data, "config", {})
        if cfg:
            self.enabled = cfg.get("ai_enabled", self.enabled)
            self.model = cfg.get("ai_model", self.model)
            self.max_tokens = cfg.get("ai_max_tokens", self.max_tokens)
            self.temperature = cfg.get("ai_temperature", self.temperature)
            self.vulnerability_summaries = cfg.get("ai_vulnerability_summaries", self.vulnerability_summaries)
            self.network_insights = cfg.get("ai_network_insights", self.network_insights)

        # Always refresh the token from disk/env before rebuilding the client
        self.api_token = self.env_manager.get_token()
        self.initialization_error = None
        self.client = None

        # ALWAYS try to initialize if we have a token, ignore the enabled flag
        self._initialize_client()

        ready = self.client is not None and self.initialization_error is None
        if ready:
            self.clear_cache()
            self.logger.info("AI Service client reloaded with latest configuration")
        else:
            self.logger.warning(
                "AI Service reload failed; check token/configuration and try again."
            )

        return ready



    # ===================================================================
    #   CACHE CLEAR
    # ===================================================================

    def clear_cache(self):
        self.cache.clear()
        self.logger.info("AI cache cleared")
