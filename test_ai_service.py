#!/usr/bin/env python3
"""
Test script for AI Service
Tests OpenAI integration, token loading, and AI analysis functions
"""

import os
import sys

# Add the Ragnar project directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ai_service import AIService
from env_manager import EnvManager
import json
from typing import Any, cast


class MockSharedData:
    """Mock shared data object for testing"""
    def __init__(self, config_override=None):
        base_config = {
            'ai_enabled': True,
            'ai_model': 'gpt-5-nano',
            'ai_max_tokens': 500,
            'ai_temperature': 0.7,
            'ai_vulnerability_summaries': True,
            'ai_network_insights': True
        }
        if config_override:
            base_config.update(config_override)
        self.config = base_config
        self.targetnbr = 5
        self.portnbr = 23
        self.vulnnbr = 8
        self.crednbr = 3
        self.network_intelligence = None


class FakeUsage:
    def __init__(self):
        self.input_tokens = 10
        self.output_tokens = 15
        self.total_tokens = 25


class FakeResponse:
    def __init__(self, text):
        self.output_text = text
        self.usage = FakeUsage()


class FakeOpenAIClient:
    """Simulates OpenAI client to test temperature fallback logic."""
    def __init__(self):
        self.responses = self
        self.call_count = 0
        self.last_payload = None

    def create(self, **kwargs):
        self.call_count += 1
        if self.call_count == 1:
            raise Exception("Unsupported parameter: 'temperature' is not supported with this model.")
        self.last_payload = kwargs
        return FakeResponse("Fallback success")


def test_env_manager():
    """Test 1: EnvManager token retrieval"""
    print("\n" + "="*60)
    print("TEST 1: Environment Manager")
    print("="*60)
    
    env_manager = EnvManager()
    api_key = env_manager.get_token()
    
    if api_key:
        print(f"✓ API key loaded successfully")
        print(f"  Preview: {api_key[:5]}...{api_key[-4:]}")
        return True
    else:
        print("✗ No API key found in .env file")
        return False


def test_ai_service_init():
    """Test 2: AI Service initialization"""
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
    else:
        print(f"✗ AI Service initialization failed: {ai_service.initialization_error}")
        return False


def test_network_summary():
    """Test 3: Network summary analysis"""
    print("\n" + "="*60)
    print("TEST 3: Network Summary Analysis")
    print("="*60)
    
    shared_data = MockSharedData()
    ai_service = AIService(shared_data)
    
    if not ai_service.is_enabled():
        print("⊘ Skipped - AI service not enabled")
        return None
    
    network_data = {
        'target_count': 5,
        'port_count': 23,
        'vulnerability_count': 8,
        'credential_count': 3
    }
    
    print("Analyzing network data...")
    print(f"  Targets: {network_data['target_count']}")
    print(f"  Open Ports: {network_data['port_count']}")
    print(f"  Vulnerabilities: {network_data['vulnerability_count']}")
    print(f"  Credentials: {network_data['credential_count']}")
    
    summary = ai_service.analyze_network_summary(network_data)
    
    if summary:
        print("\n✓ Network Summary Generated:")
        print("-" * 60)
        print(summary)
        print("-" * 60)
        return True
    else:
        print("✗ Failed to generate network summary")
        return False


def test_vulnerability_analysis():
    """Test 4: Vulnerability analysis"""
    print("\n" + "="*60)
    print("TEST 4: Vulnerability Analysis")
    print("="*60)
    
    shared_data = MockSharedData()
    ai_service = AIService(shared_data)
    
    if not ai_service.is_enabled():
        print("⊘ Skipped - AI service not enabled")
        return None
    
    vulnerabilities = [
        {
            "host": "192.168.1.10",
            "port": 22,
            "service": "ssh",
            "vulnerability": "Weak authentication",
            "severity": "high"
        },
        {
            "host": "192.168.1.15",
            "port": 445,
            "service": "smb",
            "vulnerability": "SMBv1 enabled",
            "severity": "critical"
        },
        {
            "host": "192.168.1.20",
            "port": 3389,
            "service": "rdp",
            "vulnerability": "Default credentials",
            "severity": "critical"
        }
    ]
    
    print(f"Analyzing {len(vulnerabilities)} vulnerabilities...")
    
    analysis = ai_service.analyze_vulnerabilities(vulnerabilities)
    
    if analysis:
        print("\n✓ Vulnerability Analysis Generated:")
        print("-" * 60)
        print(analysis)
        print("-" * 60)
        return True
    else:
        print("✗ Failed to generate vulnerability analysis")
        return False


def test_weakness_identification():
    """Test 5: Network weakness identification"""
    print("\n" + "="*60)
    print("TEST 5: Network Weakness Identification")
    print("="*60)
    
    shared_data = MockSharedData()
    ai_service = AIService(shared_data)
    
    if not ai_service.is_enabled():
        print("⊘ Skipped - AI service not enabled")
        return None
    
    network_data = {
        'target_count': 5,
        'port_count': 23
    }
    
    findings = [
        {
            "type": "credential",
            "host": "192.168.1.10",
            "service": "ssh",
            "username": "admin",
            "password": "admin123"
        },
        {
            "type": "vulnerability",
            "host": "192.168.1.15",
            "port": 445,
            "issue": "SMBv1 exposed"
        }
    ]
    
    print("Identifying attack vectors...")
    
    weaknesses = ai_service.identify_network_weaknesses(network_data, findings)
    
    if weaknesses:
        print("\n✓ Weakness Analysis Generated:")
        print("-" * 60)
        print(weaknesses)
        print("-" * 60)
        return True
    else:
        print("✗ Failed to identify weaknesses")
        return False


def test_temperature_fallback():
    """Test 6: Temperature unsupported fallback behavior"""
    print("\n" + "="*60)
    print("TEST 6: Temperature Fallback")
    print("="*60)

    shared_data = MockSharedData()
    ai_service = AIService(shared_data)

    # Override client with fake implementation to avoid real API calls
    fake_client: Any = FakeOpenAIClient()
    ai_service.client = cast(Any, fake_client)
    ai_service.temperature_supported = True
    ai_service.enabled = True
    ai_service.initialization_error = None

    print("Simulating model rejection of temperature parameter...")
    result = ai_service._ask("System check", "Fallback test input")

    if (
        result == "Fallback success"
        and ai_service.temperature_supported is False
        and 'temperature' not in (fake_client.last_payload or {})
    ):
        print("✓ Temperature parameter automatically disabled after error")
        return True

    print("✗ Temperature fallback did not behave as expected")
    return False


def test_generate_insights():
    """Test 7: Generate combined insights"""
    print("\n" + "="*60)
    print("TEST 7: Generate Combined Insights")
    print("="*60)
    
    shared_data = MockSharedData()
    ai_service = AIService(shared_data)
    
    print("Generating full AI insights...")
    
    insights = ai_service.generate_insights()
    
    print("\n" + "="*60)
    print("INSIGHTS OUTPUT:")
    print("="*60)
    print(json.dumps(insights, indent=2))
    
    if insights.get('enabled'):
        print("\n✓ Insights generated successfully")
        return True
    else:
        print(f"\n⊘ AI disabled or failed: {insights.get('message', 'Unknown')}")
        return False


def test_cache():
    """Test 8: Caching functionality"""
    print("\n" + "="*60)
    print("TEST 8: Cache Functionality")
    print("="*60)
    
    shared_data = MockSharedData()
    ai_service = AIService(shared_data)
    
    if not ai_service.is_enabled():
        print("⊘ Skipped - AI service not enabled")
        return None
    
    network_data = {
        'target_count': 3,
        'port_count': 10,
        'vulnerability_count': 2,
        'credential_count': 1
    }
    
    print("First call (should query AI)...")
    import time
    start = time.time()
    result1 = ai_service.analyze_network_summary(network_data)
    time1 = time.time() - start
    
    print("Second call (should use cache)...")
    start = time.time()
    result2 = ai_service.analyze_network_summary(network_data)
    time2 = time.time() - start
    
    print(f"\nFirst call time: {time1:.2f}s")
    print(f"Second call time: {time2:.2f}s")
    
    if result1 == result2 and time2 < time1:
        print("✓ Cache working correctly")
        return True
    elif result1 == result2:
        print("✓ Results match (cache may be working)")
        return True
    else:
        print("✗ Cache issue detected")
        return False


def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("RAGNAR AI SERVICE TEST SUITE")
    print("="*60)
    
    results = {}
    
    # Run tests
    results['env_manager'] = test_env_manager()
    results['ai_init'] = test_ai_service_init()
    results['network_summary'] = test_network_summary()
    results['vulnerability_analysis'] = test_vulnerability_analysis()
    results['weakness_identification'] = test_weakness_identification()
    results['temperature_fallback'] = test_temperature_fallback()
    results['insights'] = test_generate_insights()
    results['cache'] = test_cache()
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for v in results.values() if v is True)
    failed = sum(1 for v in results.values() if v is False)
    skipped = sum(1 for v in results.values() if v is None)
    
    for test_name, result in results.items():
        status = "✓ PASS" if result is True else "✗ FAIL" if result is False else "⊘ SKIP"
        print(f"{status:10} {test_name}")
    
    print("-" * 60)
    print(f"Passed:  {passed}")
    print(f"Failed:  {failed}")
    print(f"Skipped: {skipped}")
    print("="*60)
    
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
