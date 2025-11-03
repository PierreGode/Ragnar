# Threat Intelligence API Endpoint Fix

## Problem
The logs showed a 405 Method Not Allowed error for POST requests to `/api/threat-intelligence/enrich-target`:

```
Nov 03 22:07:28 ragnar python3[60678]: 10.8.0.6 - - [03/Nov/2025 22:07:28] "POST /api/threat-intelligence/enrich-target HTTP/1.1" 405 -
```

## Root Cause
The JavaScript client in `web/scripts/ragnar_modern.js` was calling the endpoint `/api/threat-intelligence/enrich-target`, but the Flask webapp only had `/api/threat-intelligence/enrich-finding` endpoint implemented.

## Solution Applied

### 1. Added Missing Imports
Added required imports to `webapp_modern.py`:
```python
import hashlib
import ipaddress
```

### 2. Added IP Address Helper Function
Added utility function to validate IP addresses:
```python
def _is_ip_address(value):
    """Check if a value is a valid IP address"""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
```

### 3. Added Missing API Endpoint
Added the `/api/threat-intelligence/enrich-target` endpoint to handle the client's POST requests:

```python
@app.route('/api/threat-intelligence/enrich-target', methods=['POST'])
def enrich_target_endpoint():
    """Enrich a target (IP, domain, or hash) with threat intelligence"""
    # Implementation handles:
    # - IP addresses
    # - Domain names  
    # - File hashes
    # - CVE IDs
    # - Returns risk scores on 0-100 scale for frontend compatibility
```

## Key Features of New Endpoint

1. **Target Type Detection**: Automatically identifies if the target is an IP, domain, or hash
2. **Risk Score Conversion**: Converts internal 0-10 scale to 0-100 scale for frontend display
3. **Comprehensive Response**: Returns threat contexts, attribution data, and recommendations
4. **Error Handling**: Proper error responses for invalid data or system issues
5. **Integration**: Uses existing threat intelligence fusion engine

## Testing
- Created test script: `test_threat_intelligence_endpoint.py`
- Verified webapp imports successfully
- Endpoint now responds to POST requests instead of returning 405 errors

## Files Modified
1. `webapp_modern.py` - Added missing endpoint and helper functions
2. Created `test_threat_intelligence_endpoint.py` - Test script for validation

The 405 error should now be resolved and the threat intelligence enrichment feature should work correctly through the web interface.