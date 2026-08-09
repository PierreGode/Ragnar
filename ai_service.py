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

from openai import OpenAI

from logger import Logger
from env_manager import EnvManager, load_env

# Load environment variables immediately
load_env()


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
        self.model = cfg.get("ai_model", "gpt-5.4-nano")

        # These must remain for backward compatibility (but not used)
        self.max_tokens = cfg.get("ai_max_tokens")
        self.temperature = cfg.get("ai_temperature")
        self.temperature_supported = True  # will disable on first failure

        self.vulnerability_summaries = cfg.get("ai_vulnerability_summaries", True)
        self.network_insights = cfg.get("ai_network_insights", True)

        self.api_token = self.env_manager.get_token()

        # Cache
        self.cache = {}
        self.cache_ttl = 3600  # 1 hour (3600 seconds) - reduce token consumption

        # Client initialization
        self.client = None
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

        try:
            self.client = OpenAI(api_key=self.api_token)
            self.initialization_error = None
            self.logger.info(f"AI Service initialized using model: {self.model}")
        except Exception as exc:
            self.client = None
            self.initialization_error = f"OpenAI client initialization failed: {exc}"
            self.logger.error(self.initialization_error)


    def reload_token(self) -> bool:
        """Refresh the API token from disk and reinitialize the OpenAI client."""

        # Keep enabled flag synced with latest config intent
        if hasattr(self.shared_data, "config"):
            self.enabled = self.shared_data.config.get("ai_enabled", self.enabled)

        self.api_token = self.env_manager.get_token()
        self.client = None
        self.initialization_error = None

        if not self.enabled:
            self.logger.info("AI service disabled in config; skipping token reload.")
            return False

        if not self.api_token:
            self.logger.warning("AI token reload requested but no token present in environment.")
            self.initialization_error = "No OpenAI API key found."
            return False

        self._initialize_client()
        success = self.client is not None and self.initialization_error is None

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
        """Return True when the service is enabled and the client is ready."""
        return self.ensure_ready()

    def ensure_ready(self):
        """Lazily initialize the OpenAI client if configuration says AI is enabled."""
        # Sync enabled state with config in case it changed
        if hasattr(self.shared_data, "config"):
            self.enabled = self.shared_data.config.get("ai_enabled", self.enabled)
        
        if not self.enabled:
            return False

        # Already initialized and healthy
        if self.client is not None and self.initialization_error is None:
            return True

        # Don't keep retrying when we've already recorded a permanent failure
        # But allow retry if token was added after initial failure
        if self.initialization_error and self.api_token:
            # Clear error and retry if we have a token now
            self.initialization_error = None

        # Refresh token from disk if we don't have one yet
        if not self.api_token:
            self.api_token = self.env_manager.get_token()

        if not self.api_token:
            self.initialization_error = "No OpenAI API key found."
            self.logger.warning(self.initialization_error)
            return False

        self._initialize_client()
        return self.client is not None and self.initialization_error is None

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
            "Structure your analysis clearly with sections and bullet points. "
            "Use markdown-style formatting for readability."
        )

        user = f"""
Vulnerabilities Detected: {len(vulnerabilities)}

Top Findings:
{data_json}

Provide a structured analysis:

First, give a brief Viking-style tactical summary (max 50 words) of the overall vulnerability situation.

Then provide detailed analysis:

**Critical Weaknesses:**
- List the most severe vulnerabilities (CVE numbers if available)
- Include affected hosts/ports
- Note severity ratings

**Immediate Actions Required:**
- Prioritized remediation steps
- What to patch/fix first
- Quick wins for risk reduction

**Overall Risk Assessment:**
- Current attack surface severity (Critical/High/Medium)
- Potential impact if exploited
- Recommended timeline for fixes

Tone: Direct, tactical Viking strategist. Use bullet points and clear sections.
"""

        resp = self._ask(system, user)
        if resp:
            self._cache_set(key, resp)
        return resp



    # ===================================================================
    #   PCAP ANALYSIS (general network fault diagnosis)
    # ===================================================================

    def analyze_pcap(self, data: Dict):
        """Interpret a PCAP-analysis summary (from network_diagnostics) and tell
        the user what is WRONG with the network. Covers the whole stack — L2
        (ARP/broadcast storms, duplicate IPs), TCP health (retransmits, resets,
        zero-windows, dup-ACKs), DNS/DHCP, TLS handshakes — and treats Wi-Fi/AP
        client-drops as a special case when it's an 802.11 capture. `data` is the
        dict returned by do_pcap_analyze (summary/protocols/talkers/expert/wifi).
        Returns a plain-language root-cause read, or None if AI is unavailable."""
        if not self.is_enabled():
            return None

        wifi = (data or {}).get('wifi') or {}
        summary = (data or {}).get('summary') or {}
        expert = (data or {}).get('expert') or {}
        protos = (data or {}).get('protocols') or []
        # Key the cache on what actually drives the verdict, not just packet count
        # + Wi-Fi fields — otherwise two unrelated non-Wi-Fi captures with the same
        # packet count collide and get served each other's analysis. The expert
        # findings + protocol mix uniquely fingerprint what the AI will say.
        key = self._cache_key("pcap_analysis", {
            "pkts": summary.get('packets'),
            "bytes": summary.get('data_size'),
            "dur": summary.get('duration_s'),
            "exp": (expert.get('errors'), expert.get('warnings'), expert.get('notes')),
            "items": [(i.get('protocol'), i.get('summary'), i.get('count'))
                      for i in (expert.get('items') or [])[:10]],
            "protos": [(p.get('proto'), p.get('bytes')) for p in protos[:10]],
            "wifi": {
                "deauth": (wifi.get('deauth') or {}).get('total'),
                "disassoc": (wifi.get('disassoc') or {}).get('total'),
                "retry": wifi.get('retry_pct'),
            } if wifi else None,
        })
        cached = self._cache_get(key)
        if cached:
            return cached

        # Keep the prompt compact: send the summary, expert findings, and (if
        # present) the Wi-Fi event breakdown that actually explains drops.
        payload = {
            'summary': summary,
            'expert': (data or {}).get('expert'),
            'top_protocols': ((data or {}).get('protocols') or [])[:15],
            'top_talkers': ((data or {}).get('talkers') or [])[:8],
            'wifi': wifi or None,
        }
        data_json = json.dumps(payload, indent=2, default=str)[:6000]

        is_wifi = bool(wifi.get('is_wifi'))
        system = (
            "You are a senior network engineer triaging a packet capture. Decide whether the "
            "network is HEALTHY or has a real problem, and if so diagnose the ROOT CAUSE from "
            "the evidence in plain language a field tech can act on. Reason across the whole "
            "stack: L2 (ARP/broadcast/multicast storms, duplicate IPs, spanning-tree churn), "
            "TCP health (retransmissions, resets, zero-windows, dup-ACKs, out-of-order, "
            "high RTT), DNS and DHCP failures/latency, TLS/handshake errors, and — for "
            "802.11 captures — deauth/disassoc reason codes and retry rates that drive "
            "client drops. "
            "CALIBRATE SEVERITY AGAINST VOLUME: a small number of RSTs, duplicate ACKs, "
            "retransmissions, and normal FIN-based connection closes is EXPECTED, especially "
            "for ordinary web/TLS browsing — judge by RATES relative to total packets/bytes "
            "and to the number of conversations, not by raw counts. Normal connection teardown "
            "(FIN / 'connection closing') is NOT a fault, and a few RSTs are how clients "
            "routinely close sessions. Do not describe the network as 'unstable' or 'degraded' "
            "unless the error rate is clearly disproportionate to the traffic. If the capture "
            "looks healthy, SAY SO plainly (make that the Verdict) rather than manufacturing a "
            "problem. "
            "Be specific and quote the counts/codes. Do not invent data not present in the "
            "summary. When you cite a Wireshark/tshark display filter or CLI command, use only "
            "valid, real syntax (e.g. tcp.analysis.retransmission, tcp.flags.reset==1, "
            "tcp.analysis.duplicate_ack) and parenthesize mixed AND/OR filters correctly; if "
            "unsure of the exact filter, describe what to match in words rather than inventing "
            "a field name. Use short markdown sections and bullet points."
        )
        focus = (
            "This is a Wi-Fi / access-point capture: pay special attention to WHY CLIENTS "
            "ARE DROPPING / DISCONNECTING (deauth/disassoc reason codes, retry %, AP "
            "behavior), but still flag any other network problems you see." if is_wifi else
            "Diagnose the most impactful problems in this capture across every layer — "
            "not just one — and rank them by how much they hurt the network. If nothing "
            "rises above normal background noise, say the capture looks healthy."
        )
        user = f"""{focus}

Packet-capture summary (JSON):
{data_json}

Provide:

**Verdict** - is the network healthy, or the single most likely root cause if not (1-2 sentences).

**Evidence** - the specific counts / reason codes / status codes / expert
findings that point to it, quoted from the summary.

**Other factors** - secondary issues worth noting (only if supported by the data).

**Fix it** - concrete, prioritized remediation steps a technician can take.

Keep it tight and practical. If the data is inconclusive, say so and name the
one capture/filter that would confirm it."""

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
            "Structure attack vector analysis clearly with numbered attack paths. "
            "Use markdown formatting for readability."
        )

        user = f"""
Network Profile:
- Devices: {network_data.get('target_count')}
- Open Ports: {network_data.get('port_count')}

Key Findings:
{sample}

Provide structured attack vector analysis:

First, give a brief, witty Viking-style summary (max 50 words) describing the network's exploitability and main attack surface.

Then provide detailed attack paths:

**Primary Attack Paths:**

1. **[Attack Name]**
   - Target: [specific host/service]
   - Method: [exploitation technique]
   - Risk Level: [Critical/High/Medium]
   - Ease of Exploitation: [Easy/Moderate/Difficult]

2. **[Attack Name]**
   - Target: [specific host/service]
   - Method: [exploitation technique]
   - Risk Level: [Critical/High/Medium]
   - Ease of Exploitation: [Easy/Moderate/Difficult]

3. **[Attack Name]** (if applicable)
   - Target: [specific host/service]
   - Method: [exploitation technique]
   - Risk Level: [Critical/High/Medium]
   - Ease of Exploitation: [Easy/Moderate/Difficult]

**Defense Recommendations:**
- Immediate hardening steps
- Network segmentation suggestions

Limit to 2-3 most viable attack paths. Be specific and tactical.
"""

        resp = self._ask(system, user)
        if resp:
            self._cache_set(key, resp)
        return resp



    # ===================================================================
    #   WI-FI CONNECTION ANALYSIS  (professional tone, no persona)
    # ===================================================================

    def analyze_wifi_connection(self, context: Dict):
        """Assess the user's current Wi-Fi connection and RF environment from a
        spectrum scan + association info, and return prioritized, professional
        recommendations. `context` is built by the /api/ai/wifi-analyze route."""
        if not self.is_enabled():
            return None

        connected = (context or {}).get("connected")
        bt = (context or {}).get("bt")
        zb = (context or {}).get("zigbee")
        key = self._cache_key("wifi_conn", {
            "bssid": (connected or {}).get("bssid"),
            "signal": (connected or {}).get("signal_dbm"),
            "cochannel": (context or {}).get("co_channel_count"),
            "aps": (context or {}).get("ap_total"),
            # Include the non-Wi-Fi 2.4 GHz overlays so enabling/refreshing them
            # busts the cache instead of serving a Wi-Fi-only verdict.
            "bt": (bt or {}).get("device_count") if bt else None,
            "zb": (zb or {}).get("device_count") if zb else None,
        })
        cached = self._cache_get(key)
        if cached:
            return cached

        # Which non-Wi-Fi 2.4 GHz sources are present shapes what we ask for.
        overlays = []
        if bt:
            overlays.append("Bluetooth/BLE")
        if zb:
            overlays.append("Zigbee / 802.15.4")
        overlay_line = (
            (" The data also includes non-Wi-Fi 2.4 GHz emitters discovered "
             "alongside the Wi-Fi scan (" + " and ".join(overlays) + "), under "
             "the 'bt' and/or 'zigbee' keys, with an estimated per-Wi-Fi-channel "
             "pressure for channels 1/6/11/13. Treat these as coexistence load on "
             "the 2.4 GHz band: factor them into 2.4 GHz channel advice and, when "
             "they are significant, recommend moving affected clients to 5/6 GHz. "
             "The pressure figures are heuristic activity estimates, not measured "
             "energy — say so and do not overstate them.") if overlays else ""
        )

        data_json = json.dumps(context, indent=2, default=str)[:6000]
        system = (
            "You are a professional wireless network engineer. Analyze the user's "
            "current Wi-Fi connection and the surrounding RF environment from the "
            "scan data provided, and give clear, actionable recommendations to fix "
            "or improve it. Use a neutral, professional tone — no personas, no "
            "slang, no jokes. Base every statement strictly on the data provided; "
            "do not invent SSIDs, channels or values that are not present. If the "
            "user is not associated to a network, say so and analyze the "
            "environment instead. Use short markdown sections and bullet points."
            + overlay_line
        )
        user = f"""Analyze this Wi-Fi connection and RF environment.

Data (JSON):
{data_json}

Provide:

**Connection summary** — the network the user is on: band, channel, channel
width, security, Wi-Fi generation, signal strength and negotiated rate, in one
short paragraph.

**Issues found** — concrete problems supported by the data, e.g. co-channel or
adjacent-channel congestion, 2.4 GHz use where 5 GHz is available, weak signal,
legacy/weak security (Open/WEP/WPA/TKIP), a narrow channel width, a crowded
channel, or — when the bt/zigbee overlays are present — non-Wi-Fi 2.4 GHz
coexistence pressure from Bluetooth/BLE or Zigbee on channels 1/6/11. Only list
issues the data supports.

**Recommendations** — prioritized, specific actions (e.g. "move to 5 GHz",
"change to channel 44", "widen to 80 MHz", "upgrade to WPA2/WPA3-CCMP",
"relocate the AP / add an AP"). Say why each helps.

If the environment is healthy, say so plainly. Keep it tight and practical."""

        resp = self._ask(system, user)
        if resp:
            self._cache_set(key, resp)
        return resp

    # ===================================================================
    #   SECURITY POSTURE  (Watchtower + Wi-Fi Defense passive monitoring)
    # ===================================================================

    def analyze_security_posture(self, posture: Dict):
        """Summarize the passive-monitoring posture from Watchtower's aggregated
        alert feed (which includes the Wi-Fi Defense family: wifiwatch,
        legacywatch, wpswatch, ndpwatch, …). Professional tone."""
        if not self.is_enabled():
            return None

        key = self._cache_key("posture", {
            "total": (posture or {}).get("total_alerts"),
            "worst": (posture or {}).get("worst"),
            "by_sev": (posture or {}).get("by_severity"),
        })
        cached = self._cache_get(key)
        if cached:
            return cached

        data_json = json.dumps(posture, indent=2, default=str)[:5000]
        system = (
            "You are a professional security operations analyst. Summarize the "
            "current passive-monitoring posture from the alert data. Watchtower "
            "aggregates Ragnar's passive watchers, including the Wi-Fi Defense "
            "family (wifiwatch, legacywatch, wpswatch) and wired monitors "
            "(ndpwatch, arp_guard, …). Use a neutral, professional tone. Base "
            "every statement on the data; do not invent alerts. Be concise."
        )
        user = f"""Summarize this passive security-monitoring posture.

Data (JSON):
{data_json}

Provide:

**Posture** — one or two sentences on the overall state (quiet, elevated, or
active incidents), grounded in the alert counts.

**Top concerns** — the most important active findings (by severity and source),
naming the finding codes/summaries present.

**Recommended actions** — concrete next steps for the highest-severity items.

If there are no alerts, state that the monitored surface is currently clean and
note which watchers are reporting. Keep it short."""

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

    def generate_insights(self, posture: Optional[Dict] = None):
        output = {
            "enabled": self.is_enabled(),
            "timestamp": datetime.now().isoformat(),
            "network_summary": None,
            "vulnerability_analysis": None,
            "weakness_analysis": None,
            "posture_analysis": None,
        }

        if not self.is_enabled():
            output["message"] = self.initialization_error or "AI disabled"
            return output

        # Passive-monitoring posture (Watchtower + Wi-Fi Defense), if supplied by
        # the caller — the route gathers it since the aggregator lives there.
        if posture is not None:
            output["posture_analysis"] = self.analyze_security_posture(posture)

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
