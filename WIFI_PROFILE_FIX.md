# CRITICAL WiFi Profile Bug Fix

## ⚠️ CRITICAL ISSUE FIXED

**Problem:** Ragnar was **DELETING existing NetworkManager WiFi profiles** when connecting to networks, which could lock users out of their own networks!

**Root Cause:** The `connect_to_network()` method in `wifi_manager.py` was executing:
```python
# DELETE EXISTING CONNECTION (DANGEROUS!)
subprocess.run(['nmcli', 'con', 'delete', ssid], ...)
```

This deleted ALL existing NetworkManager profiles for that SSID, including:
- User-created profiles
- System administrator profiles  
- Profiles with specific security settings
- Profiles needed for system access

## 🔧 FIXES APPLIED

### 1. `connect_to_network()` Method (Lines 1065-1130)

**BEFORE (Dangerous):**
```python
# First, try to delete any existing connection to ensure fresh connection
delete_result = subprocess.run(['nmcli', 'con', 'delete', ssid], ...)
if delete_result.returncode == 0:
    self.logger.info(f"Deleted existing connection for {ssid}")

# Always create a new connection
cmd = ['nmcli', 'dev', 'wifi', 'connect', ssid]
```

**AFTER (Safe):**
```python
# Check if a connection profile already exists (DO NOT DELETE!)
check_result = subprocess.run(['nmcli', 'con', 'show', ssid], ...)
profile_exists = check_result.returncode == 0

if profile_exists:
    # Use existing profile - update password if provided
    if password:
        subprocess.run(['nmcli', 'con', 'modify', ssid, 'wifi-sec.psk', password], ...)
    # Activate existing connection
    cmd = ['nmcli', 'con', 'up', ssid]
else:
    # Create new profile only if none exists
    cmd = ['nmcli', 'dev', 'wifi', 'connect', ssid]
    if password:
        cmd.extend(['password', password])
```

### 2. `remove_known_network()` Method (Lines 1177-1200)

**BEFORE (Dangerous):**
```python
# Also remove from NetworkManager
try:
    subprocess.run(['nmcli', 'con', 'delete', ssid], ...)
except:
    pass
```

**AFTER (Safe):**
```python
# Only remove from Ragnar's internal list
self.save_wifi_config()
self.logger.info(f"Removed {ssid} from Ragnar's known networks list")
self.logger.info(f"NOTE: System NetworkManager profile for {ssid} was NOT deleted")
```

## 🛡️ PROTECTION MECHANISMS

1. **Profile Preservation:** Existing NetworkManager profiles are NEVER deleted
2. **Profile Reuse:** If a profile exists, Ragnar reuses it instead of creating duplicates
3. **Password Updates:** If a password is provided for an existing profile, it's updated (not replaced)
4. **Separation of Concerns:** Ragnar's known networks list is separate from system profiles
5. **Clear Logging:** All profile operations are logged with explanations

## 📋 BEHAVIORAL CHANGES

### Connecting to WiFi:
- ✅ **If profile exists:** Activate it (optionally update password)
- ✅ **If profile doesn't exist:** Create new profile
- ✅ **Never delete** existing profiles

### Removing from Known Networks:
- ✅ **Ragnar's list:** Network removed from Ragnar's internal tracking
- ✅ **System profile:** Remains intact and available
- ✅ **User control:** User keeps full control of their NetworkManager profiles

### Password Updates:
- ✅ **Known network with stored password fails:** Shows password field for retry
- ✅ **New password provided:** Updates existing profile's password
- ✅ **No password changes:** Uses existing stored credentials

## 🔍 TESTING RECOMMENDATIONS

1. **Test existing profile connection:**
   - Create a WiFi profile manually with NetworkManager
   - Use Ragnar to connect to it
   - Verify the original profile is still intact after connection

2. **Test password update:**
   - Connect to a network through Ragnar
   - Change the WiFi password on the router
   - Try connecting again - should show password field
   - Enter new password - should update profile, not delete/recreate

3. **Test new network:**
   - Connect to a completely new network
   - Verify profile is created correctly
   - Verify it doesn't interfere with other profiles

4. **Test profile removal:**
   - Remove a network from Ragnar's known networks
   - Verify the NetworkManager profile still exists
   - Verify you can still connect to it manually

## ⚡ SMART PASSWORD LOGIC

The captive portal and modern dashboard now implement smart password behavior:

- **Known network selected:** Password field hidden, uses stored credentials
- **Stored password fails:** Password field appears automatically with error message
- **Unknown network selected:** Password field shown immediately
- **No password needed:** Can connect to open networks

This provides a seamless user experience while maintaining security and profile integrity.

## 🚨 IMPORTANT NOTES

- **No System Impact:** These fixes ensure Ragnar plays nicely with system WiFi management
- **User Safety:** Users can never be locked out of their own networks
- **Clean Separation:** Ragnar tracks its own known networks without interfering with system profiles
- **Backwards Compatible:** Existing Ragnar installations will benefit from these protections immediately

## 📝 FILES MODIFIED

1. `wifi_manager.py` - Lines 1065-1130 (`connect_to_network` method)
2. `wifi_manager.py` - Lines 1177-1200 (`remove_known_network` method)
3. `web/captive_portal.html` - Smart password field logic
4. `web/scripts/ragnar_modern.js` - Smart password field logic

---

**Status:** ✅ CRITICAL BUG FIXED - Safe to deploy
**Priority:** 🔴 CRITICAL - Deploy immediately to prevent user lockouts
**Risk Level:** ⚠️ HIGH - Previous code could lock users out of their own WiFi
