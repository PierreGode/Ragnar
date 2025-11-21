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

# OpenAI SDK (modern client optional)
try:
    from openai import OpenAI as OpenAIClient
except Exception:
    OpenAIClient = None



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
        self.model = cfg.get("ai_model", "gpt-5.1")

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
        self.legacy_openai = None
        self.using_legacy_sdk = False
        self.initialization_error = None
        self._initialize_client()



    # ===================================================================
    #   INITIALIZATION
    # ===================================================================

    def _initialize_client(self):
        if not self.enabled:
            return

        if not self.api_token:
            self.initialization_error = "No OpenAI API key found."
            self.logger.warning(self.initialization_error)
            return

        # Reset state
        self.client = None
        self.legacy_openai = None
        self.using_legacy_sdk = False

        # Attempt modern SDK first if available
        if OpenAIClient is not None:
            try:
                self.client = OpenAIClient(api_key=self.api_token)
                self.logger.info(f"AI Service initialized using model: {self.model}")
                self.initialization_error = None
                return
            except Exception as modern_error:
                self.logger.warning(
                    f"Modern OpenAI client initialization failed ({modern_error}). Falling back to legacy SDK..."
                )

        # Fallback to legacy openai module
        try:
            import importlib

            legacy_module = importlib.import_module("openai")
            setattr(legacy_module, "api_key", self.api_token)
            self.legacy_openai = legacy_module
            self.using_legacy_sdk = True

            if self.model.startswith("gpt-5"):
                self.logger.info(
                    f"Legacy OpenAI SDK detected; overriding model '{self.model}' → 'gpt-3.5-turbo' for compatibility"
                )
                self.model = "gpt-3.5-turbo"

            self.initialization_error = None
            self.logger.info(f"AI Service initialized using legacy OpenAI SDK (model: {self.model})")
        except Exception as legacy_error:
            self.initialization_error = (
                "OpenAI SDK not accessible. Ensure the 'openai' package is installed and up to date."
            )
            self.logger.error(f"Legacy OpenAI initialization failed: {legacy_error}")


    def reload_token(self) -> bool:
        """Refresh the API token from disk and reinitialize the OpenAI client."""

        # Keep enabled flag synced with latest config intent
        if hasattr(self.shared_data, "config"):
            self.enabled = self.shared_data.config.get("ai_enabled", self.enabled)

        self.api_token = self.env_manager.get_token()
        self.client = None
        self.legacy_openai = None
        self.using_legacy_sdk = False
        self.initialization_error = None

        if not self.enabled:
            self.logger.info("AI service disabled in config; skipping token reload.")
            return False

        if not self.api_token:
            self.logger.warning("AI token reload requested but no token present in environment.")
            self.initialization_error = "No OpenAI API key found."
            return False

        self._initialize_client()
        has_client = (self.client is not None) or (self.legacy_openai is not None)
        success = has_client and self.initialization_error is None

        if success:
            self.logger.info("AI service reloaded with updated token.")
        else:
            if self.initialization_error:
                self.logger.error(
                    f"AI service failed to reinitialize after token reload: {self.initialization_error}"
                )
            else:
                self.logger.error("AI service failed to reinitialize after token reload.")

        return success



    # ===================================================================
    #   UTILITY HELPERS
    # ===================================================================

    def is_enabled(self):
        active_client = self.client if not self.using_legacy_sdk else self.legacy_openai
        return self.enabled and active_client is not None and self.initialization_error is None

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

        if self.using_legacy_sdk:
            return self._ask_legacy(system_msg, user_msg)

        if self.client is None:
            self.logger.error("AI client unavailable despite service being enabled.")
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


    def _ask_legacy(self, system_msg: str, user_msg: str, allow_retry: bool = True) -> Optional[str]:
        """Fallback path using legacy openai.ChatCompletion API."""

        if not self.legacy_openai:
            self.logger.error("Legacy OpenAI client unavailable despite fallback mode.")
            return None

        temperature = self.temperature if self.temperature_supported and self.temperature is not None else None

        try:
            completion = self.legacy_openai.ChatCompletion.create(  # type: ignore[attr-defined]
                model=self.model,
                messages=[
                    {"role": "system", "content": system_msg},
                    {"role": "user", "content": user_msg},
                ],
                temperature=temperature,
                max_tokens=self.max_tokens or 512,
            )

            usage = completion.get("usage", {}) if isinstance(completion, dict) else {}
            if usage:
                self.logger.info(
                    f"AI Tokens → input:{usage.get('prompt_tokens')} output:{usage.get('completion_tokens')} total:{usage.get('total_tokens')}"
                )

            choices = completion.get("choices") if isinstance(completion, dict) else None
            if not choices:
                return None

            return choices[0]["message"]["content"].strip()

        except Exception as legacy_error:
            error_text = str(legacy_error).lower()
            if (
                allow_retry
                and temperature is not None
                and "temperature" in error_text
                and "unsupported" in error_text
            ):
                self.temperature_supported = False
                self.logger.warning("Legacy model does not support temperature — retrying without it.")
                return self._ask_legacy(system_msg, user_msg, allow_retry=False)

            self.logger.error(f"Legacy OpenAI call failed: {legacy_error}")
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
    #   CACHE CLEAR
    # ===================================================================

    def clear_cache(self):
        self.cache.clear()
        self.logger.info("AI cache cleared")
