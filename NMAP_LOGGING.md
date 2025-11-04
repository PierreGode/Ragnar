# Nmap Logging in Ragnar

## Overview

Ragnar now includes comprehensive logging for all nmap operations. All nmap commands executed by Ragnar and their results are automatically logged to provide audit trails, debugging information, and security compliance.

## Log File Location

- **Linux/Unix**: `/var/log/nmap.log`
- **Windows**: `<ragnar_directory>/var/log/nmap.log`

The logging system automatically creates the log directory if it doesn't exist and falls back to the local directory structure if system-wide logging isn't available.

## What Gets Logged

### 1. Direct Nmap Commands
All nmap commands executed via subprocess are logged with:
- Full command line arguments
- Execution context (what operation triggered the command)
- Standard output (stdout)
- Standard error (stderr)  
- Return code

### 2. Python-nmap Operations
Operations using the python-nmap library are logged with:
- Scan operation details
- Network/host discovery results
- Found hosts and their details

### 3. Vulnerability Scans
Specific logging for vulnerability scanning includes:
- Target IP addresses and ports
- Scan parameters (aggressiveness level, scripts used)
- Vulnerability findings
- Error conditions

## Log Format

```
YYYY-MM-DD HH:MM:SS - NMAP - LEVEL - MESSAGE
```

Example log entries:
```
2025-11-04 07:26:48 - NMAP - INFO - COMMAND (Vulnerability scan for 192.168.1.100): nmap -T4 -sV --script vulners.nse -p 22,80,443 192.168.1.100
2025-11-04 07:26:50 - NMAP - INFO - RESULT (Vulnerability scan for 192.168.1.100): Return code: 0
2025-11-04 07:26:50 - NMAP - INFO - STDOUT (Vulnerability scan for 192.168.1.100):
2025-11-04 07:26:50 - NMAP - INFO -   Starting Nmap 7.94 ( https://nmap.org )
2025-11-04 07:26:50 - NMAP - INFO -   Nmap scan report for 192.168.1.100
2025-11-04 07:26:50 - NMAP - INFO - OPERATION: Host discovery scan - Network: 192.168.1.0/24, Arguments: -sn
2025-11-04 07:26:51 - NMAP - INFO - OPERATION: Host discovery completed - Found 5 hosts: 192.168.1.1, 192.168.1.100, 192.168.1.101, 192.168.1.102, 192.168.1.103
```

## Implementation Details

### Files Modified

1. **`nmap_logger.py`** (new file)
   - Centralized logging utility for all nmap operations
   - Thread-safe logging with automatic directory creation
   - Fallback mechanism for different operating systems

2. **`actions/nmap_vuln_scanner.py`**
   - Modified to use `nmap_logger.run_nmap_command()` instead of direct subprocess calls
   - All vulnerability scans are now logged with full context

3. **`actions/scanning.py`**  
   - Added logging for python-nmap host discovery operations
   - Logs scan operations and discovered hosts

### Key Functions

- `nmap_logger.run_nmap_command()`: Execute and log nmap commands
- `nmap_logger.log_scan_operation()`: Log general nmap operations
- `nmap_logger.log_command()`: Log command before execution
- `nmap_logger.log_result()`: Log command results

## Benefits

1. **Audit Trail**: Complete record of all network scanning activities
2. **Debugging**: Detailed output for troubleshooting scan issues
3. **Compliance**: Helps meet security audit requirements
4. **Monitoring**: Track what networks and hosts are being scanned
5. **Analysis**: Historical data for security assessments

## Usage

The logging is automatic and requires no configuration. Simply run Ragnar as usual and all nmap operations will be logged.

To view recent nmap activities:
```bash
# Linux/Unix
tail -f /var/log/nmap.log

# Windows (PowerShell)
Get-Content "var\log\nmap.log" -Tail 10 -Wait
```

## Testing

A test script is provided to verify the logging functionality:
```bash
python test_nmap_logging.py
```

This will create test log entries and verify the logging system is working correctly.