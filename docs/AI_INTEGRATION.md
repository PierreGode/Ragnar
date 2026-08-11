# AI Integration for Ragnar

This document describes the AI integration feature added to Ragnar, which provides intelligent network analysis and vulnerability summaries using OpenAI's GPT-5.4 Nano.

## Overview

The AI integration brings PWNAGOTCHI-style intelligence to Ragnar, providing:
- Network security summaries
- Vulnerability analysis and prioritization
- Network weakness identification
- Attack vector analysis

## Features

### 1. Network Security Summaries
AI analyzes your network scan data and provides concise summaries of the overall security posture, highlighting key findings and actionable recommendations.

### 2. Vulnerability Assessment
Intelligent analysis of discovered vulnerabilities with:
- Priority recommendations for remediation
- Risk assessment
- Critical vulnerability highlights

### 3. Network Weakness Identification
Identifies potential attack vectors and security gaps in your network:
- Weak configurations
- Exposed services
- Potential exploitation paths

## Configuration

### 1. Enable AI in Config Tab

1. Navigate to the **Config** tab in the web interface
2. Scroll to the **AI Integration (GPT-5.4 Nano)** section
3. Configure the following settings:

- **ai_enabled**: Set to `true` to enable AI features
- **openai_api_token**: Your OpenAI API token (required for OpenAI's cloud; optional for a self-hosted endpoint)
- **ai_model**: Model to use (default: "gpt-5.4-nano"; for a local server use its model tag, e.g. `qwen2.5:7b`)
- **ai_base_url**: Optional OpenAI-compatible endpoint (see below). Blank = OpenAI cloud
- **ai_api_style**: `auto` (default), `responses`, or `chat` — overrides which API dialect Ragnar speaks
- **ai_analysis_enabled**: Enable/disable AI analysis
- **ai_vulnerability_summaries**: Enable vulnerability summaries
- **ai_network_insights**: Enable network insights
- **ai_max_tokens**: Maximum tokens per response (default: 500)
- **ai_temperature**: Creativity setting (default: 0.7)

### Self-hosted / local AI endpoints (issue #462)

Ragnar can talk to any **OpenAI-compatible** server instead of OpenAI's cloud —
[Ollama](https://ollama.com/), [LocalAI](https://localai.io/), vLLM, or LM Studio.
Set **ai_base_url** (in Settings → AI → *Self-Hosted / Custom Endpoint*) to the
server's `/v1` URL, e.g. `http://192.168.1.50:11434/v1`, and set **ai_model** to
that server's model tag. When a base URL is present:

- Ragnar uses the **Chat Completions** API (`/v1/chat/completions`) — local
  servers implement this, not OpenAI's proprietary Responses API. `ai_api_style`
  lets you force `responses` or `chat` if auto-detection guesses wrong.
- The API token becomes **optional** (most local servers accept any key).

Click **Connect** next to the endpoint field to list the models the server
offers and pick one from the dropdown (backed by `POST /api/ai/models`, which
the Pi proxies so it works even though the browser can't reach the remote server
directly). Then click **Save Endpoint**. URLs are tidied automatically — a
missing `http://` or `/v1` is added, so `192.168.1.50:11434` becomes
`http://192.168.1.50:11434/v1`.

**Cloud fallback:** if a self-hosted endpoint becomes unreachable (connection
lost / timeout) mid-run and an OpenAI token is configured, Ragnar automatically
falls back to OpenAI's cloud so insights keep flowing. The dashboard header
shows `… → OpenAI fallback` while this is active, and reverts once the local
endpoint answers again. Set **ai_fallback_model** to choose the cloud model used
(blank = `gpt-5.4-nano`). The dashboard AI card's title and footer always show
the model actually in use.

**The model runs on whatever host you point at — not on the Pi.** The Pi stays a
thin HTTP client, exactly as it is with OpenAI. This pairs naturally with a
fleet: a small board (e.g. a Pi Zero 2W) can offload inference to a capable box
running Ollama on the LAN or mesh.

> **Running a model on the Pi itself:** a Pi 5 (16 GB) *can* self-host a small
> quantized model (e.g. a 3B–8B Q4 via Ollama) — point `ai_base_url` at
> `http://localhost:11434/v1` — but expect **triage-grade** quality and only a
> few tokens/sec on CPU. A Pi Zero 2W (512 MB) cannot run a useful model; use it
> as a client to a remote endpoint instead.

### 2. Get an OpenAI API Token

1. Visit [OpenAI Platform](https://platform.openai.com/)
2. Sign up or log in to your account
3. Navigate to API Keys section
4. Create a new API key
5. Copy the API key and paste it into the `openai_api_token` field in Ragnar

### 3. Save Configuration

Click "Save Configuration" to apply the settings. The AI service will initialize automatically.

## Usage

### Dashboard View

Once configured, AI insights appear automatically on the Dashboard tab:

1. **Network Security Summary** - Overall security posture analysis
2. **Vulnerability Assessment** - Prioritized vulnerability analysis
3. **Network Weaknesses** - Identified attack vectors and security gaps

### Refresh Insights

Click the "Refresh" button in the AI Insights section to:
- Clear the cache
- Generate new analysis with latest data
- Get updated recommendations

## API Endpoints

The following API endpoints are available for programmatic access:

### POST /api/ai/models
Lists the models offered by an OpenAI-compatible endpoint (self-hosted support).
Body: `{ "base_url": "http://host:11434/v1", "api_key": "optional" }` — both
fall back to the saved config. Returns `{ "success": true, "models": [...] }`.

### GET /api/ai/status
Returns AI service status and configuration
```json
{
  "enabled": true,
  "available": true,
  "model": "gpt-5.4-nano",
  "capabilities": {
    "network_insights": true,
    "vulnerability_summaries": true
  },
  "configured": true
}
```

### GET /api/ai/insights
Returns comprehensive AI insights. The four analyses (network summary,
vulnerability, weakness, posture) are generated in a **background thread** and
the endpoint **answers immediately** — so a slow board (e.g. a Pi Zero) never
blocks the dashboard on the multi-second generation, which is what timed out and
showed "could not reach". While the first run is in flight the response carries
`status:"computing"` (plus any previous result), and the page **polls** every
~6s until it lands; completed results are cached (1h server-side; client-side 1h
on full success, 2min if any analysis failed). Pass `?refresh=1` (the Refresh
button) to force a recompute. Inside the background run the analyses go 2-at-a-
time so units sharing one API key don't trip OpenAI's per-key rate limits, each
with a 25s per-request timeout; `attempted`/`failed` tell the UI which analyses
ran and which came back empty (per-section "Temporarily unavailable + Retry").
```json
{
  "enabled": true,
  "timestamp": "2025-11-20T20:39:19.888Z",
  "network_summary": "Your network shows 10 active targets...",
  "vulnerability_analysis": "Critical vulnerabilities detected...",
  "weakness_analysis": "Potential attack vectors identified..."
}
```

### GET /api/ai/network-summary
Returns network security summary only

### GET /api/ai/vulnerabilities
Returns vulnerability analysis only

### GET /api/ai/weaknesses
Returns weakness analysis only

### POST /api/ai/wifi-analyze
Professional assessment of the **current Wi-Fi connection and RF environment**,
used by the **WiFi Spectrum Analyzer → "Analyze with AI"** button. Body:
`{"scan": <result of /api/net/wifi/scan>, "bt": <bt overlay?>, "zb": <zigbee overlay?>}`.
The server determines the connected network itself (`iw dev … link`), enriches
it from the scan (channel, width, security, Wi-Fi generation), computes the
co-/adjacent-channel picture, and returns prioritized, plain-language
recommendations (band/channel/width/security changes, AP placement). Neutral
professional tone — no persona.

When the **Bluetooth** and/or **Zigbee** 2.4 GHz overlays are active, the panel
also passes those payloads. The AI folds their **per-Wi-Fi-channel coexistence
pressure** into its 2.4 GHz channel advice (e.g. recommending a move to 5/6 GHz
when BT/Zigbee load on ch 1/6/11 is significant), and the response's `overlays`
field lists which were included. The pressure figures are heuristic activity
estimates, not measured energy, and the prompt says so.

### POST /api/ai/wifidef-analyze
One professional read across the **three WiFi Defense modules** for the capture
the panel currently holds, used by the **WiFi Defense → "Analyze with AI"**
button. Body: `{"wids": <do_scan>, "airtime": <do_airtime?>, "isolation": <do_isolation?>}`.
The server compacts each module (WIDS threat/detections/airspace, airtime
findings + per-AP retry/airtime, client-isolation verdicts) and asks the model
to **correlate across all three** — e.g. tying a deauth burst to a retry spike,
or flagging a "rogue" that's really a legit AP with a randomized-MAC client.
Returns the analysis plus the `modules` that were included. Severity is
calibrated against capture length so a short hopping capture reads as weak
evidence, not an incident. Neutral SOC-analyst tone.

### POST /api/ai/clear-cache
Clears the AI response cache

### Dashboard posture analysis
`GET /api/ai/insights` now also returns a `posture_analysis` field (and the
`posture_data` it was built from): a professional summary of the **passive-
monitoring posture** drawn from **Watchtower**, which aggregates the Wi-Fi
Defense family (wifiwatch, legacywatch, wpswatch) and the wired watchers
(ndpwatch, arp_guard, …). It surfaces on the dashboard as the "Passive
Monitoring & Wi-Fi Defense" card.

## Technical Details

### Architecture

The AI integration consists of:

1. **ai_service.py** - Core AI service module
   - OpenAI API integration
   - Response caching (5-minute TTL)
   - Network analysis logic
   
2. **API Endpoints** (webapp_modern.py)
   - RESTful endpoints for AI functionality
   - Integration with network intelligence
   
3. **Web UI** (index_modern.html, ragnar_modern.js)
   - Dashboard display components
   - Auto-loading and refresh functionality

### Caching Strategy

AI responses are cached for 5 minutes to:
- Reduce API costs
- Improve response times
- Prevent redundant analysis

Cache is automatically cleared on:
- Manual refresh
- Configuration changes
- Network changes

### Integration with Network Intelligence

The AI service integrates seamlessly with Ragnar's Network Intelligence system:
- Uses active findings for current network
- Analyzes vulnerabilities and credentials
- Respects network context and history

## Personality

The AI assistant ("Ragnar") is designed to be:
- **Knowledgeable**: Expert in cybersecurity and penetration testing
- **Witty**: Occasionally includes personality in responses
- **Concise**: Provides actionable insights without verbosity
- **Tactical**: Focuses on practical recommendations

Similar to PWNAGOTCHI, Ragnar provides intelligent analysis that helps both attackers (in authorized pentests) and defenders understand network security.

## Cost Considerations

### API Usage

The OpenAI API is pay-per-use. To minimize costs:

1. **Caching**: Responses cached for 5 minutes
2. **Token Limits**: Configurable max_tokens (default: 500)
3. **Manual Refresh**: Insights only regenerated on demand
4. **Smart Analysis**: Only analyzes when data changes

### Estimated Costs

With default settings (500 tokens max):
- Network summary: ~0.5-1 cent per request
- Vulnerability analysis: ~0.5-1 cent per request
- Total per refresh: ~1.5-3 cents

Costs vary based on:
- Chosen model
- Token limits
- Refresh frequency
- Network size

## Troubleshooting

### AI Insights Not Appearing

1. Check that `ai_enabled` is set to `true`
2. Verify `openai_api_token` is configured
3. Check browser console for errors
4. Verify internet connectivity

### "AI service not enabled" Message

1. Ensure OpenAI package is installed: `pip install openai`
2. Check API token is valid
3. Verify configuration was saved

### Empty or Generic Responses

1. Run network scans to gather data
2. Wait for vulnerability scans to complete
3. Ensure network intelligence is enabled
4. Check that data is flowing to the AI service

### API Errors

1. Verify API token is valid
2. Check OpenAI account has credits
3. Ensure model name is correct
4. Review API rate limits

## Security Considerations

### API Token Security

⚠️ **IMPORTANT**: Protect your OpenAI API token

- Store in configuration file (not in code)
- Use environment variables in production
- Rotate tokens periodically
- Monitor API usage for anomalies

### Data Privacy

AI analysis sends the following data to OpenAI:
- Network statistics (counts)
- Vulnerability summaries (anonymized)
- Service information
- Host identifiers (IPs)

**Never send**:
- Actual credentials
- Sensitive file contents
- Personal data
- Proprietary information

### Compliance

Consider regulatory requirements when using AI:
- GDPR (if processing EU data)
- HIPAA (if analyzing healthcare networks)
- PCI-DSS (if scanning payment networks)

Ensure AI usage complies with your organization's policies.

## Future Enhancements

Planned improvements:
- [ ] Credential analysis with security recommendations
- [ ] Attack path recommendations
- [ ] Automated remediation suggestions
- [ ] Integration with threat intelligence feeds
- [ ] Custom AI prompts and personalities
- [ ] Local LLM support (privacy-focused option)
- [ ] Multi-model support

## Support

For issues or questions:
1. Check the [GitHub Issues](https://github.com/PierreGode/Ragnar/issues)
2. Review the main [README](../README.md)
3. Submit a bug report with:
   - AI configuration (redact API token)
   - Error messages
   - Browser console logs
   - Steps to reproduce

## License

This AI integration is part of Ragnar and follows the same license as the main project.
