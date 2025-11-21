#!/usr/bin/env python3
"""
Updated Test Script for AI Service
Supports GPT-5 Responses API (OpenAI().responses.create)
"""

import os
import sys
import json
from typing import Any, cast

# Add Ragnar project directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ai_service import AIService
from env_manager import EnvManager


# ============================================================
# MOCK SHARED DATA (UPDATED FOR GPT-5)
# ============================================================

class MockSharedData:
    """Mock shared data object for AIService testing."""
    def __init__(self, config_override=None):

        base_config = {
            'ai_enabled': True,
            'ai_model': 'gpt-5.1',  # ✔ VALID GPT-5 MODEL

            # GPT-5 no longer uses these:
            'ai_max_tokens': None,
            'ai_temperature': None,

            'ai_vulnerability_summaries': True,
            'ai_network_insights': True
        }

        if config_override:
            base_config.update(config_override)

        self.config = base_config

        # Mocked numerical values used by tests
        self.targetnbr = 5
        self.portnbr = 23
        self.vulnnbr = 8
        self.crednbr = 3

        self.network_intelligence = None



# ============================================================
# FAKE GPT-5 CLIENT FOR TEMPERATURE FALLBACK TEST
# ============================================================

class FakeUsage:
    def __init__(self):
        self.input_tokens = 10
        self.output_tokens = 15
        self.total_tokens = 25


class FakeResponse:
    """Simulates OpenAI GPT-5 response object."""
    def __init__(self, text):
        self.output_text = text
        self.usage = FakeUsage()


class FakeOpenAIClient:
    """
    Simulates OpenAI().responses.create()
    Used for testing temperature fallback logic.
    """
    def __init__(self):
        self.responses = self  # mimic OpenAI().responses namespace
        self.call_count = 0
        self.last_payload = None

    def create(self, **kwargs):
        self.call_count += 1

        # First request: simulate "temperature unsupported" GPT-5 error
        if self.call_count == 1:
            raise Exception("Unsupported parameter: 'temperature' is not supported with this model.")

        # Retry (correct payload)
        self.last_payload = kwargs
        return FakeResponse("Fallback success")



# ============================================================
# TEST 1 — ENV MANAGER
# ============================================================

def test_env_manager():
    print("\n" + "="*60)
    print("TEST 1: Environment Manager")
    print("="*60)

    env_manager = EnvManager()
    api_key = env_manager.get_token()

    if api_key:
        print("✓ API key loaded successfully")
        print(f"  Preview: {api_key[:5]}...{api_key[-4:]}")
        return True

    print("✗ No API key found in .env file")
    return False



# ============================================================
# TEST 2 — AI SERVICE INIT
# ============================================================

def test_ai_service_init():
    print("\n" + "="*60)
    print("TEST 2: AI Service Initialization")
    print("="*60)

    shared_data = MockSharedData()
    ai_service = AIService(shared_data)

    print(f"AI Enabled: {ai_service.enabled}")
    print(f"Model: {ai_service.model}")
    print(f"Client initialized: {ai_service.client is not None}")
    print(f"Initialization error: {ai_service.initialization_error}")

    if ai_service.is_enabled():
        print("✓ AI Service initialized successfully")
        return True

    print("✗ AI Service initialization failed")
    return False



# ============================================================
# TEST 3 — NETWORK SUMMARY
# ============================================================

def test_network_summary():
    print("\n" + "="*60)
    print("TEST 3: Network Summary Analysis")
    print("="*60)

    shared_data = MockSharedData()
    ai_service = AIService(shared_data)

    if not ai_service.is_enabled():
        print("⊘ Skipped - AI disabled")
        return None

    network_data = {
        'target_count': 5,
        'port_count': 23,
        'vulnerability_count': 8,
        'credential_count': 3
    }

    print("Analyzing network data...")
    summary = ai_service.analyze_network_summary(network_data)

    if summary:
        print("\n✓ Network Summary Generated:")
        print("-" * 60)
        print(summary)
        print("-" * 60)
        return True

    print("✗ Failed to generate network summary")
    return False



# ============================================================
# TEST 4 — VULNERABILITY ANALYSIS
# ============================================================

def test_vulnerability_analysis():
    print("\n" + "="*60)
    print("TEST 4: Vulnerability Analysis")
    print("="*60)

    shared_data = MockSharedData()
    ai_service = AIService(shared_data)

    vulnerabilities = [
        {"host": "192.168.1.10", "port": 22, "service": "ssh", "vulnerability": "Weak authentication", "severity": "high"},
        {"host": "192.168.1.15", "port": 445, "service": "smb", "vulnerability": "SMBv1 enabled", "severity": "critical"},
        {"host": "192.168.1.20", "port": 3389, "service": "rdp", "vulnerability": "Default credentials", "severity": "critical"},
    ]

    print("Running vulnerability analysis...")
    analysis = ai_service.analyze_vulnerabilities(vulnerabilities)

    if analysis:
        print("\n✓ Vulnerability Analysis Generated:")
        print("-" * 60)
        print(analysis)
        print("-" * 60)
        return True

    print("✗ Failed to generate vulnerability analysis")
    return False



# ============================================================
# TEST 5 — WEAKNESS IDENTIFICATION
# ============================================================

def test_weakness_identification():
    print("\n" + "="*60)
    print("TEST 5: Network Weakness Identification")
    print("="*60)

    shared_data = MockSharedData()
    ai_service = AIService(shared_data)

    network_data = {'target_count': 5, 'port_count': 23}
    findings = [
        {"type": "credential", "host": "192.168.1.10", "service": "ssh", "username": "admin", "password": "admin123"},
        {"type": "vulnerability", "host": "192.168.1.15", "port": 445, "issue": "SMBv1 exposed"},
    ]

    print("Identifying weaknesses...")
    weaknesses = ai_service.identify_network_weaknesses(network_data, findings)

    if weaknesses:
        print("\n✓ Weaknesses Identified:")
        print("-" * 60)
        print(weaknesses)
        print("-" * 60)
        return True

    print("✗ Weakness identification failed")
    return False



# ============================================================
# TEST 6 — TEMPERATURE FALLBACK
# ============================================================

def test_temperature_fallback():
    print("\n" + "="*60)
    print("TEST 6: Temperature Fallback")
    print("="*60)

    shared_data = MockSharedData()
    ai_service = AIService(shared_data)

    fake_client: Any = FakeOpenAIClient()
    ai_service.client = cast(Any, fake_client)
    ai_service.temperature_supported = True

    print("Simulating unsupported 'temperature'...")
    result = ai_service._ask("System check", "Fallback test")

    if (
        result == "Fallback success"
        and ai_service.temperature_supported is False
        and 'temperature' not in (fake_client.last_payload or {})
    ):
        print("✓ Temperature fallback works")
        return True

    print("✗ Temperature fallback failed")
    return False



# ============================================================
# TEST 7 — COMBINED INSIGHTS
# ============================================================

def test_generate_insights():
    print("\n" + "="*60)
    print("TEST 7: Generate Combined Insights")
    print("="*60)

    shared_data = MockSharedData()
    ai_service = AIService(shared_data)

    insights = ai_service.generate_insights()

    print(json.dumps(insights, indent=2))

    if insights.get("enabled", False):
        print("✓ Insights generated successfully")
        return True

    print("✗ Failed to generate insights")
    return False



# ============================================================
# TEST 8 — CACHE
# ============================================================

def test_cache():
    print("\n" + "="*60)
    print("TEST 8: Cache Functionality")
    print("="*60)

    shared_data = MockSharedData()
    ai_service = AIService(shared_data)

    network_data = {
        'target_count': 3,
        'port_count': 10,
        'vulnerability_count': 2,
        'credential_count': 1
    }

    import time

    print("Running first call...")
    t1 = time.time()
    r1 = ai_service.analyze_network_summary(network_data)
    t1 = time.time() - t1

    print("Running second call...")
    t2 = time.time()
    r2 = ai_service.analyze_network_summary(network_data)
    t2 = time.time() - t2

    print(f"First call:  {t1:.2f}s")
    print(f"Second call: {t2:.2f}s")

    if r1 == r2:
        print("✓ Cache working (results match)")
        return True

    print("✗ Cache failure")
    return False



# ============================================================
# MAIN
# ============================================================

def main():
    print("\n" + "="*60)
    print("RAGNAR AI SERVICE TEST SUITE")
    print("="*60)

    results = {
        'env_manager': test_env_manager(),
        'ai_init': test_ai_service_init(),
        'network_summary': test_network_summary(),
        'vulnerability_analysis': test_vulnerability_analysis(),
        'weakness_identification': test_weakness_identification(),
        'temperature_fallback': test_temperature_fallback(),
        'insights': test_generate_insights(),
        'cache': test_cache()
    }

    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)

    for name, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL" if result is False else "⊘ SKIP"
        print(f"{status:10} {name}")

    print("="*60)
    return 0 if all(r is True for r in results.values()) else 1



if __name__ == "__main__":
    sys.exit(main())
