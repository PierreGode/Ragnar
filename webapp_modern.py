#webapp_modern.py
"""
Modern Flask-based web application for Ragnar
Features:
- Fast Flask backend with proper routing
- RESTful API endpoints
- WebSocket support for real-time updates
- Static file caching
- Better performance than SimpleHTTPRequestHandler
"""

import os
import sys
import json
import csv
import signal
import logging
import threading
import time
from datetime import datetime
from flask import Flask, render_template, jsonify, request, send_from_directory, Response
from flask_socketio import SocketIO, emit
import re
import time
import os
import json
try:
    from flask_cors import CORS
    flask_cors_available = True
except ImportError:
    flask_cors_available = False
from init_shared import shared_data
from utils import WebUtils
from logger import Logger

# Initialize logger
logger = Logger(name="webapp_modern.py", level=logging.DEBUG)

# Initialize Flask app
app = Flask(__name__,
            static_folder='web',
            template_folder='web')
app.config['SECRET_KEY'] = 'ragnar-cyberviking-secret-key'
app.config['JSON_SORT_KEYS'] = False

# Enable CORS
# Set up CORS if available
if flask_cors_available:
    CORS(app)

# Initialize SocketIO for real-time updates
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Initialize web utilities
web_utils = WebUtils(shared_data, logger)

# Global state
clients_connected = 0


def safe_int(value, default=0):
    """Safely convert value to int, handling numpy types"""
    try:
        if hasattr(value, 'item'):  # numpy types have .item() method
            return int(value.item())
        return int(value) if value is not None else default
    except (ValueError, TypeError, AttributeError):
        return default

def safe_str(value, default=""):
    """Safely convert value to string"""
    try:
        return str(value) if value is not None else default
    except (ValueError, TypeError):
        return default

def safe_bool(value, default=False):
    """Safely convert value to boolean"""
    try:
        return bool(value) if value is not None else default
    except (ValueError, TypeError):
        return default


def is_ap_client_request():
    """Check if the request is coming from an AP client (192.168.4.x)"""
    try:
        client_ip = request.environ.get('REMOTE_ADDR', '')
        # Check if request is from AP network (192.168.4.x)
        return client_ip.startswith('192.168.4.') and client_ip != '192.168.4.1'
    except:
        return False


# ============================================================================
# STATIC FILE ROUTES
# ============================================================================

@app.route('/')
def index():
    """Serve the main dashboard page or captive portal for AP clients"""
    if is_ap_client_request():
        # Serve captive portal for AP clients
        return send_from_directory('web', 'captive_portal.html')
    else:
        # Serve main dashboard for regular users
        return send_from_directory('web', 'index_modern.html')


# Add explicit captive portal route
@app.route('/portal')
def captive_portal():
    """Explicit captive portal route"""
    return send_from_directory('web', 'captive_portal.html')


# Captive portal detection routes for mobile devices
@app.route('/generate_204')
@app.route('/gen_204')
@app.route('/connecttest.txt')
@app.route('/success.txt')
@app.route('/ncsi.txt')
def captive_portal_detection():
    """Handle captive portal detection requests from mobile devices"""
    if is_ap_client_request():
        # Redirect to captive portal for AP clients
        return '''<html><head><meta http-equiv="refresh" content="0; url=/portal"></head><body><a href="/portal">Click here for WiFi setup</a></body></html>''', 302
    else:
        # Return success for non-AP clients
        return "Success", 204


@app.route('/<path:filename>')
def serve_static(filename):
    """Serve static files from web directory"""
    return send_from_directory('web', filename)


# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route('/api/status')
def get_status():
    """Get current Ragnar status"""
    try:
        status_data = {
            'ragnar_status': safe_str(shared_data.ragnarstatustext),
            'ragnar_status2': safe_str(shared_data.ragnarstatustext2),
            'ragnar_says': safe_str(shared_data.ragnarsays),
            'orchestrator_status': safe_str(shared_data.ragnarorch_status),
            'target_count': safe_int(shared_data.targetnbr),
            'port_count': safe_int(shared_data.portnbr),
            'vulnerability_count': safe_int(shared_data.vulnnbr),
            'credential_count': safe_int(shared_data.crednbr),
            'data_count': safe_int(shared_data.datanbr),
            'wifi_connected': safe_bool(shared_data.wifi_connected),
            'bluetooth_active': safe_bool(shared_data.bluetooth_active),
            'pan_connected': safe_bool(shared_data.pan_connected),
            'usb_active': safe_bool(shared_data.usb_active),
            'manual_mode': safe_bool(shared_data.config.get('manual_mode', False)),
            'timestamp': datetime.now().isoformat()
        }
        return jsonify(status_data)
    except Exception as e:
        logger.error(f"Error getting status: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/config', methods=['GET'])
def get_config():
    """Get current configuration"""
    try:
        return jsonify(shared_data.config)
    except Exception as e:
        logger.error(f"Error getting config: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/config', methods=['POST'])
def update_config():
    """Update configuration"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Update configuration
        for key, value in data.items():
            if key in shared_data.config:
                shared_data.config[key] = value
        
        # Save configuration
        shared_data.save_config()
        
        # Emit update to all connected clients
        socketio.emit('config_updated', shared_data.config)
        
        return jsonify({'success': True, 'message': 'Configuration updated'})
    except Exception as e:
        logger.error(f"Error updating config: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/network')
def get_network():
    """Get network scan data"""
    try:
        data = shared_data.read_data()
        return jsonify(data)
    except Exception as e:
        logger.error(f"Error getting network data: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/credentials')
def get_credentials():
    """Get discovered credentials"""
    try:
        credentials = web_utils.get_all_credentials()
        return jsonify(credentials)
    except Exception as e:
        logger.error(f"Error getting credentials: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/loot')
def get_loot():
    """Get stolen data/loot"""
    try:
        loot = web_utils.get_loot_data()
        return jsonify(loot)
    except Exception as e:
        logger.error(f"Error getting loot: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/logs')
def get_logs():
    """Get recent logs"""
    try:
        # Read last 100 lines of temp log
        log_file = shared_data.webconsolelog
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                lines = f.readlines()
                return jsonify({'logs': lines[-100:]})
        return jsonify({'logs': []})
    except Exception as e:
        logger.error(f"Error getting logs: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# SYSTEM MANAGEMENT ENDPOINTS
# ============================================================================

@app.route('/api/system/check-updates')
def check_updates():
    """Check for system updates using git"""
    try:
        import subprocess
        import os
        
        # Get current working directory (should be the repo root)
        # Use the directory where the webapp is running from, not the file location
        repo_path = os.getcwd()
        
        logger.info(f"Checking for updates in repository: {repo_path}")
        
        # Fetch latest changes from remote
        try:
            fetch_result = subprocess.run(['git', 'fetch', 'origin'], cwd=repo_path, check=True, capture_output=True, text=True)
            logger.info(f"Git fetch completed: {fetch_result.stdout}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Git fetch failed: {e.stderr}")
            # Try to fix git safe directory issue and retry
            try:
                subprocess.run(['git', 'config', '--global', '--add', 'safe.directory', repo_path], 
                             cwd=repo_path, check=True, capture_output=True)
                logger.info(f"Added {repo_path} to git safe directories")
                # Retry fetch
                fetch_result = subprocess.run(['git', 'fetch', 'origin'], cwd=repo_path, check=True, capture_output=True, text=True)
                logger.info(f"Git fetch completed after fixing safe directory: {fetch_result.stdout}")
            except subprocess.CalledProcessError as e2:
                logger.error(f"Git fetch still failed after fixing safe directory: {e2.stderr}")
                return jsonify({
                    'error': 'Failed to fetch from remote repository. Git safe directory issue detected.',
                    'fix_command': f'git config --global --add safe.directory {repo_path}',
                    'detailed_error': str(e2.stderr)
                }), 500
        
        # Check if local branch is behind remote
        try:
            result = subprocess.run(
                ['git', 'rev-list', '--count', 'HEAD..origin/main'], 
                cwd=repo_path, 
                capture_output=True, 
                text=True, 
                check=True
            )
            commits_behind = int(result.stdout.strip())
            logger.info(f"Commits behind: {commits_behind}")
        except (subprocess.CalledProcessError, ValueError) as e:
            logger.error(f"Error checking commits behind main: {e}")
            # Fallback: try master branch or assume up to date
            try:
                result = subprocess.run(
                    ['git', 'rev-list', '--count', 'HEAD..origin/master'], 
                    cwd=repo_path, 
                    capture_output=True, 
                    text=True, 
                    check=True
                )
                commits_behind = int(result.stdout.strip())
                logger.info(f"Commits behind (master): {commits_behind}")
            except:
                logger.error("Could not determine commits behind, assuming up to date")
                commits_behind = 0
        
        # Get current HEAD commit
        try:
            current_result = subprocess.run(
                ['git', 'log', 'HEAD', '--oneline', '-1'], 
                cwd=repo_path, 
                capture_output=True, 
                text=True, 
                check=True
            )
            current_commit = current_result.stdout.strip()
        except:
            current_commit = "Unable to fetch current commit"
        
        # Get latest commit info
        try:
            result = subprocess.run(
                ['git', 'log', 'origin/main', '--oneline', '-1'], 
                cwd=repo_path, 
                capture_output=True, 
                text=True, 
                check=True
            )
            latest_commit = result.stdout.strip()
        except:
            try:
                result = subprocess.run(
                    ['git', 'log', 'origin/master', '--oneline', '-1'], 
                    cwd=repo_path, 
                    capture_output=True, 
                    text=True, 
                    check=True
                )
                latest_commit = result.stdout.strip()
            except:
                latest_commit = "Unable to fetch latest commit"
        
        logger.info(f"Update check result - Behind: {commits_behind}, Current: {current_commit}, Latest: {latest_commit}")
        
        return jsonify({
            'updates_available': commits_behind > 0,
            'commits_behind': commits_behind,
            'current_commit': current_commit,
            'latest_commit': latest_commit,
            'repo_path': repo_path
        })
        
    except Exception as e:
        logger.error(f"Error checking for updates: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/update', methods=['POST'])
def perform_update():
    """Perform system update using git pull"""
    try:
        import subprocess
        import os
        
        repo_path = os.getcwd()
        logger.info(f"Performing update in repository: {repo_path}")
        
        # Perform git pull
        try:
            result = subprocess.run(
                ['git', 'pull', 'origin', 'main'], 
                cwd=repo_path, 
                capture_output=True, 
                text=True, 
                check=True
            )
            output = result.stdout
            logger.info(f"Git pull completed: {output}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Git pull main failed: {e.stderr}")
            # Try master branch as fallback
            try:
                result = subprocess.run(
                    ['git', 'pull', 'origin', 'master'], 
                    cwd=repo_path, 
                    capture_output=True, 
                    text=True, 
                    check=True
                )
                output = result.stdout
                logger.info(f"Git pull master completed: {output}")
            except subprocess.CalledProcessError as e2:
                logger.error(f"Git pull master also failed: {e2.stderr}")
                return jsonify({'success': False, 'error': f'Git pull failed: {e2.stderr}'}), 500
        
        # Schedule service restart after a short delay
        def restart_service_delayed():
            import time
            time.sleep(2)  # Give time for response to be sent
            try:
                subprocess.run(['sudo', 'systemctl', 'restart', 'ragnar'], check=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to restart service: {e}")
        
        # Start restart in background thread
        import threading
        threading.Thread(target=restart_service_delayed, daemon=True).start()
        
        return jsonify({
            'success': True,
            'message': 'Update completed successfully',
            'output': output
        })
        
    except Exception as e:
        logger.error(f"Error performing update: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/system/fix-git', methods=['POST'])
def fix_git_safe_directory():
    """Fix git safe directory issue"""
    try:
        import subprocess
        import os
        
        repo_path = os.getcwd()
        
        # Add repo to git safe directories
        result = subprocess.run(
            ['git', 'config', '--global', '--add', 'safe.directory', repo_path], 
            cwd=repo_path, 
            capture_output=True, 
            text=True, 
            check=True
        )
        
        logger.info(f"Added {repo_path} to git safe directories")
        
        return jsonify({
            'success': True,
            'message': f'Successfully added {repo_path} to git safe directories'
        })
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to fix git safe directory: {e.stderr}")
        return jsonify({
            'success': False, 
            'error': f'Failed to fix git configuration: {e.stderr}'
        }), 500
    except Exception as e:
        logger.error(f"Error fixing git safe directory: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/system/restart-service', methods=['POST'])
def restart_service():
    """Restart the Ragnar service"""
    try:
        import subprocess
        
        # Schedule service restart after a short delay to allow response to be sent
        def restart_service_delayed():
            import time
            time.sleep(2)  # Give time for response to be sent
            try:
                subprocess.run(['sudo', 'systemctl', 'restart', 'ragnar'], check=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to restart service: {e}")
        
        # Start restart in background thread
        import threading
        threading.Thread(target=restart_service_delayed, daemon=True).start()
        
        return jsonify({
            'success': True,
            'message': 'Service restart initiated'
        })
        
    except Exception as e:
        logger.error(f"Error restarting service: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/system/reboot', methods=['POST'])
def reboot_system():
    """Reboot the entire system"""
    try:
        import subprocess
        
        # Schedule reboot after a short delay to allow response to be sent
        def reboot_delayed():
            import time
            time.sleep(3)  # Give time for response to be sent
            try:
                subprocess.run(['sudo', 'reboot'], check=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to reboot system: {e}")
        
        # Start reboot in background thread
        import threading
        threading.Thread(target=reboot_delayed, daemon=True).start()
        
        return jsonify({
            'success': True,
            'message': 'System reboot initiated'
        })
        
    except Exception as e:
        logger.error(f"Error rebooting system: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# WI-FI MANAGEMENT ENDPOINTS
# ============================================================================

@app.route('/api/wifi/status')
def get_wifi_status():
    """Get Wi-Fi manager status"""
    try:
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if wifi_manager and hasattr(wifi_manager, 'wifi_manager'):
            status = wifi_manager.wifi_manager.get_status()
            return jsonify(status)
        else:
            return jsonify({
                'wifi_connected': shared_data.wifi_connected,
                'ap_mode_active': False,
                'current_ssid': None,
                'error': 'Wi-Fi manager not available'
            })
    except Exception as e:
        logger.error(f"Error getting Wi-Fi status: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/wifi/scan', methods=['POST'])
def scan_wifi_networks():
    """Scan for available Wi-Fi networks"""
    try:
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if wifi_manager and hasattr(wifi_manager, 'wifi_manager'):
            networks = wifi_manager.wifi_manager.scan_networks()
            return jsonify({'networks': networks})
        else:
            return jsonify({'error': 'Wi-Fi manager not available'}), 503
    except Exception as e:
        logger.error(f"Error scanning Wi-Fi networks: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/wifi/networks')
def get_wifi_networks():
    """Get available and known Wi-Fi networks"""
    try:
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if wifi_manager and hasattr(wifi_manager, 'wifi_manager'):
            available = wifi_manager.wifi_manager.get_available_networks()
            known = wifi_manager.wifi_manager.get_known_networks()
            
            # For captive portal, return networks in a simple format
            if is_ap_client_request():
                return jsonify({
                    'success': True,
                    'networks': available if available else []
                })
            else:
                # For main interface, return detailed format
                return jsonify({
                    'success': True,
                    'available': available,
                    'known': known
                })
        else:
            return jsonify({
                'success': False,
                'networks': [],
                'available': [], 
                'known': []
            })
    except Exception as e:
        logger.error(f"Error getting Wi-Fi networks: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/wifi/connect', methods=['POST'])
def connect_wifi():
    """Connect to a Wi-Fi network"""
    try:
        data = request.get_json()
        if not data or 'ssid' not in data:
            return jsonify({'success': False, 'error': 'SSID is required'}), 400
        
        ssid = data['ssid']
        password = data.get('password')
        priority = data.get('priority', 1)
        save_network = data.get('save', True)
        
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if not wifi_manager or not hasattr(wifi_manager, 'wifi_manager'):
            return jsonify({'success': False, 'error': 'Wi-Fi manager not available'}), 503
        
        # Try to connect
        success = wifi_manager.wifi_manager.connect_to_network(ssid, password)
        
        if success and save_network:
            # Add to known networks if connection successful
            wifi_manager.wifi_manager.add_known_network(ssid, password, priority)
        
        message = 'Connected successfully' if success else 'Connection failed'
        if success and is_ap_client_request():
            message = 'Connected successfully! Ragnar will now use this network. You can disconnect from this AP.'
        
        return jsonify({
            'success': success,
            'message': message
        })
        
    except Exception as e:
        logger.error(f"Error connecting to Wi-Fi: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/wifi/disconnect', methods=['POST'])
def disconnect_wifi():
    """Disconnect from current Wi-Fi network"""
    try:
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if not wifi_manager or not hasattr(wifi_manager, 'wifi_manager'):
            return jsonify({'error': 'Wi-Fi manager not available'}), 503
        
        # Stop any active connection and start AP mode
        result = wifi_manager.wifi_manager.start_ap_mode()
        
        return jsonify({
            'success': result,
            'message': 'Disconnected and started AP mode' if result else 'Failed to start AP mode'
        })
        
    except Exception as e:
        logger.error(f"Error disconnecting Wi-Fi: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/wifi/forget', methods=['POST'])
def forget_wifi_network():
    """Remove a network from known networks"""
    try:
        data = request.get_json()
        if not data or 'ssid' not in data:
            return jsonify({'error': 'SSID is required'}), 400
        
        ssid = data['ssid']
        
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if not wifi_manager or not hasattr(wifi_manager, 'wifi_manager'):
            return jsonify({'error': 'Wi-Fi manager not available'}), 503
        
        success = wifi_manager.wifi_manager.remove_known_network(ssid)
        
        return jsonify({
            'success': success,
            'message': 'Network forgotten' if success else 'Network not found'
        })
        
    except Exception as e:
        logger.error(f"Error forgetting Wi-Fi network: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/wifi/ap/enable', methods=['POST'])
def enable_wifi_ap_mode():
    """Enable Wi-Fi Access Point mode with smart cycling"""
    try:
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if not wifi_manager or not hasattr(wifi_manager, 'wifi_manager'):
            return jsonify({'error': 'Wi-Fi manager not available'}), 503
        
        # Use the smart AP mode with cycling
        success = wifi_manager.wifi_manager.enable_ap_mode_from_web()
        
        ap_config = {
            'ssid': wifi_manager.wifi_manager.ap_ssid,
            'timeout': wifi_manager.wifi_manager.ap_timeout,
            'cycling': wifi_manager.wifi_manager.ap_cycle_enabled
        }
        
        return jsonify({
            'success': success,
            'message': 'Smart AP mode enabled with 3-minute cycling' if success else 'Failed to enable AP mode',
            'ap_config': ap_config
        })
        
    except Exception as e:
        logger.error(f"Error enabling Wi-Fi AP mode: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/wifi/ap/start', methods=['POST'])
def start_wifi_ap():
    """Start Wi-Fi Access Point mode"""
    try:
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if not wifi_manager or not hasattr(wifi_manager, 'wifi_manager'):
            return jsonify({'error': 'Wi-Fi manager not available'}), 503
        
        success = wifi_manager.wifi_manager.start_ap_mode()
        
        return jsonify({
            'success': success,
            'message': 'AP mode started' if success else 'Failed to start AP mode'
        })
        
    except Exception as e:
        logger.error(f"Error starting Wi-Fi AP: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/wifi/ap/stop', methods=['POST'])
def stop_wifi_ap():
    """Stop Wi-Fi Access Point mode"""
    try:
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if not wifi_manager or not hasattr(wifi_manager, 'wifi_manager'):
            return jsonify({'error': 'Wi-Fi manager not available'}), 503
        
        success = wifi_manager.wifi_manager.stop_ap_mode()
        
        return jsonify({
            'success': success,
            'message': 'AP mode stopped' if success else 'Failed to stop AP mode'
        })
        
    except Exception as e:
        logger.error(f"Error stopping Wi-Fi AP: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/wifi/reconnect', methods=['POST'])
def reconnect_wifi():
    """Force Wi-Fi reconnection attempt"""
    try:
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if not wifi_manager or not hasattr(wifi_manager, 'wifi_manager'):
            return jsonify({'error': 'Wi-Fi manager not available'}), 503
        
        success = wifi_manager.wifi_manager.force_reconnect()
        
        return jsonify({
            'success': success,
            'message': 'Reconnection attempt initiated' if success else 'Reconnection failed'
        })
        
    except Exception as e:
        logger.error(f"Error reconnecting Wi-Fi: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/epaper-display')
def get_epaper_display():
    """Get current e-paper display image as base64"""
    try:
        from PIL import Image
        import base64
        import io
        
        # Look for the current display image saved by display.py
        display_image_path = os.path.join(shared_data.webdir, "screen.png")
        
        if os.path.exists(display_image_path):
            # Read and encode the image
            with Image.open(display_image_path) as img:
                # Convert to RGB if needed
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                
                # Save to bytes
                img_byte_arr = io.BytesIO()
                img.save(img_byte_arr, format='PNG')
                img_byte_arr = img_byte_arr.getvalue()
                
                # Encode to base64
                img_base64 = base64.b64encode(img_byte_arr).decode('utf-8')
                
                return jsonify({
                    'image': f"data:image/png;base64,{img_base64}",
                    'timestamp': int(os.path.getctime(display_image_path)),
                    'width': img.width,
                    'height': img.height,
                    'status_text': safe_str(shared_data.ragnarstatustext),
                    'status_text2': safe_str(shared_data.ragnarstatustext2)
                })
        
        # If no image found, return status only
        return jsonify({
            'image': None,
            'message': 'No e-paper display image available',
            'timestamp': int(time.time()),
            'status_text': safe_str(shared_data.ragnarstatustext),
            'status_text2': safe_str(shared_data.ragnarstatustext2)
        })
        
    except Exception as e:
        logger.error(f"Error getting e-paper display: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/display')
def get_display():
    """Get current EPD display image"""
    try:
        # Return the current display status image
        image_path = os.path.join(shared_data.picdir, 'current_display.png')
        if os.path.exists(image_path):
            return send_from_directory(shared_data.picdir, 'current_display.png')
        return jsonify({'error': 'Display image not found'}), 404
    except Exception as e:
        logger.error(f"Error getting display: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/actions', methods=['GET'])
def get_actions():
    """Get available actions"""
    try:
        with open(shared_data.actions_file, 'r') as f:
            actions = json.load(f)
        return jsonify(actions)
    except Exception as e:
        logger.error(f"Error getting actions: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/vulnerabilities')
def get_vulnerabilities():
    """Get vulnerability scan results"""
    try:
        vuln_data = web_utils.get_vulnerability_data()
        return jsonify(vuln_data)
    except Exception as e:
        logger.error(f"Error getting vulnerabilities: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/stats')
def get_stats():
    """Get aggregated statistics"""
    try:
        stats = {
            'total_targets': safe_int(shared_data.targetnbr),
            'total_ports': safe_int(shared_data.portnbr),
            'total_vulnerabilities': safe_int(shared_data.vulnnbr),
            'total_credentials': safe_int(shared_data.crednbr),
            'total_data_stolen': safe_int(shared_data.datanbr),
            'scan_results_count': 0,
            'services_discovered': {}
        }
        
        # Add scan results count
        if os.path.exists(shared_data.netkbfile):
            import pandas as pd
            df = pd.read_csv(shared_data.netkbfile)
            stats['scan_results_count'] = safe_int(len(df[df['Alive'] == 1]) if 'Alive' in df.columns else len(df))
        
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# LEGACY ENDPOINTS (for compatibility)
# ============================================================================

@app.route('/network_data')
def legacy_network_data():
    """Legacy endpoint for network data"""
    return get_network()

@app.route('/list_credentials')
def legacy_credentials():
    """Legacy endpoint for credentials"""
    return get_credentials()

@app.route('/get_logs')
def legacy_logs():
    """Legacy endpoint for logs"""
    return get_logs()

@app.route('/netkb_data_json')
def legacy_netkb_json():
    """Legacy endpoint for network knowledge base JSON"""
    try:
        netkb_file = shared_data.netkbfile
        if not os.path.exists(netkb_file):
            return jsonify({'ips': [], 'ports': {}, 'actions': []})
            
        import pandas as pd
        df = pd.read_csv(netkb_file)
        data = df[df['Alive'] == 1] if 'Alive' in df.columns else df
        
        # Get available actions from actions file
        actions = []
        try:
            with open(shared_data.actions_file, 'r') as f:
                actions_config = json.load(f)
                actions = list(actions_config.keys())
        except Exception:
            pass
        
        response_data = {
            'ips': data['IPs'].tolist() if 'IPs' in data.columns else [],
            'ports': {row['IPs']: row['Ports'].split(';') for _, row in data.iterrows() if 'Ports' in row},
            'actions': actions
        }
        
        return jsonify(response_data)
    except Exception as e:
        logger.error(f"Error getting netkb JSON: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# WEBSOCKET EVENTS
# ============================================================================

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    global clients_connected
    clients_connected += 1
    logger.info(f"Client connected. Total clients: {clients_connected}")
    emit('connected', {'message': 'Connected to Bjorn'})
    
    # Send initial data to new client
    try:
        status_data = get_current_status()
        emit('status_update', status_data)
        
        # Send recent logs
        logs = get_recent_logs()
        emit('log_update', logs)
    except Exception as e:
        logger.error(f"Error sending initial data: {e}")


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    global clients_connected
    clients_connected = max(0, clients_connected - 1)
    logger.info(f"Client disconnected. Total clients: {clients_connected}")


@socketio.on('request_status')
def handle_status_request():
    """Handle status update request"""
    try:
        status_data = get_current_status()
        emit('status_update', status_data)
    except Exception as e:
        logger.error(f"Error handling status request: {e}")


@socketio.on('request_logs')
def handle_log_request():
    """Handle request for recent logs"""
    try:
        logs = get_recent_logs()
        emit('log_update', logs)
    except Exception as e:
        logger.error(f"Error sending logs: {e}")


@socketio.on('request_network')
def handle_network_request():
    """Handle request for network data"""
    try:
        data = shared_data.read_data()
        emit('network_update', data)
    except Exception as e:
        logger.error(f"Error sending network data: {e}")


@socketio.on('request_credentials')
def handle_credentials_request():
    """Handle request for credentials data"""
    try:
        credentials = web_utils.get_all_credentials()
        emit('credentials_update', credentials)
    except Exception as e:
        logger.error(f"Error sending credentials: {e}")


@socketio.on('request_loot')
def handle_loot_request():
    """Handle request for loot data"""
    try:
        loot = web_utils.get_loot_data()
        emit('loot_update', loot)
    except Exception as e:
        logger.error(f"Error sending loot data: {e}")


# ============================================================================
# BACKGROUND TASKS
# ============================================================================

def get_current_status():
    """Get current status data"""
    return {
        'bjorn_status': safe_str(shared_data.ragnarstatustext),
        'bjorn_status2': safe_str(shared_data.ragnarstatustext2),
        'bjorn_says': safe_str(shared_data.ragnarsays),
        'orchestrator_status': safe_str(shared_data.ragnarorch_status),
        'target_count': safe_int(shared_data.targetnbr),
        'port_count': safe_int(shared_data.portnbr),
        'vulnerability_count': safe_int(shared_data.vulnnbr),
        'credential_count': safe_int(shared_data.crednbr),
        'data_count': safe_int(shared_data.datanbr),
        'wifi_connected': safe_bool(shared_data.wifi_connected),
        'bluetooth_active': safe_bool(shared_data.bluetooth_active),
        'pan_connected': safe_bool(shared_data.pan_connected),
        'usb_active': safe_bool(shared_data.usb_active),
        'manual_mode': safe_bool(shared_data.config.get('manual_mode', False)),
        'timestamp': datetime.now().isoformat()
    }

def get_recent_logs():
    """Get recent log entries"""
    logs = []
    try:
        log_file = shared_data.webconsolelog
        if os.path.exists(log_file):
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                # Return last 50 lines
                logs = [line.strip() for line in lines[-50:] if line.strip()]
    except Exception as e:
        logger.error(f"Error reading logs: {e}")
    return logs

def broadcast_status_updates():
    """Broadcast status updates to all connected clients"""
    log_counter = 0
    while not shared_data.webapp_should_exit:
        try:
            if clients_connected > 0:
                # Send status update
                status_data = get_current_status()
                socketio.emit('status_update', status_data)
                
                # Send logs every 5 cycles (10 seconds)
                log_counter += 1
                if log_counter % 5 == 0:
                    logs = get_recent_logs()
                    socketio.emit('log_update', logs)
            
            socketio.sleep(2)  # Update every 2 seconds
        except Exception as e:
            logger.error(f"Error broadcasting status: {e}")
            socketio.sleep(5)


# ============================================================================
# MANUAL MODE ENDPOINTS
# ============================================================================

@app.route('/api/manual/status')
def get_manual_mode_status():
    """Get current manual mode status"""
    try:
        return jsonify({
            'manual_mode': shared_data.config.get('manual_mode', False),
            'orchestrator_status': shared_data.ragnarorch_status
        })
    except Exception as e:
        logger.error(f"Error getting manual mode status: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/manual/targets')
def get_manual_targets():
    """Get available targets for manual attacks"""
    try:
        targets = []
        target_ips = set()  # Track unique IPs to avoid duplicates
        
        # Read from the live status file first
        if os.path.exists(shared_data.livestatusfile):
            with open(shared_data.livestatusfile, 'r') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    if row.get('Alive') == '1':  # Only alive targets
                        ip = row.get('IP', '')
                        hostname = row.get('Hostname', ip)
                        
                        # Get open ports
                        ports = []
                        for key, value in row.items():
                            if key.isdigit() and value:  # Port columns with values
                                ports.append(key)
                        
                        if ip and ip not in target_ips:
                            targets.append({
                                'ip': ip,
                                'hostname': hostname,
                                'ports': ports,
                                'source': 'Network Scan'
                            })
                            target_ips.add(ip)
        
        # Also include hosts from NetKB data
        try:
            # Get NetKB data
            netkb_entries = []
            
            # Process scan results for host/service information
            scan_results_dir = getattr(shared_data, 'scan_results_dir', os.path.join('data', 'output', 'scan_results'))
            if os.path.exists(scan_results_dir):
                for filename in os.listdir(scan_results_dir):
                    if filename.endswith('.txt'):
                        filepath = os.path.join(scan_results_dir, filename)
                        try:
                            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                if content.strip():
                                    # Extract IP from filename or content
                                    ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', filename)
                                    host_ip = ip_match.group() if ip_match else None
                                    
                                    if host_ip and host_ip not in target_ips:
                                        # Parse port/service info from content
                                        ports = []
                                        for line in content.split('\n'):
                                            if '/tcp' in line or '/udp' in line:
                                                parts = line.split()
                                                if len(parts) >= 1:
                                                    port = parts[0].split('/')[0]  # Extract port number only
                                                    if port.isdigit() and port not in ports:
                                                        ports.append(port)
                                        
                                        targets.append({
                                            'ip': host_ip,
                                            'hostname': host_ip,  # Use IP as hostname if no other info
                                            'ports': ports,
                                            'source': 'NetKB'
                                        })
                                        target_ips.add(host_ip)
                        except Exception as e:
                            continue
            
            # Add example targets if no real data exists
            if not targets:
                targets = [
                    {
                        'ip': '192.168.1.1',
                        'hostname': '192.168.1.1',
                        'ports': ['22', '80', '443'],
                        'source': 'Example'
                    },
                    {
                        'ip': '192.168.1.100',
                        'hostname': '192.168.1.100',
                        'ports': ['80', '443'],
                        'source': 'Example'
                    }
                ]
        except Exception as e:
            logger.error(f"Error processing NetKB data for targets: {e}")
        
        return jsonify({'targets': targets})
        
    except Exception as e:
        logger.error(f"Error getting manual targets: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/manual/execute-attack', methods=['POST'])
def execute_manual_attack():
    """Execute a manual attack on a specific target"""
    try:
        data = request.get_json()
        target_ip = data.get('ip')
        target_port = data.get('port') 
        attack_type = data.get('action')
        
        if not target_ip or not attack_type:
            return jsonify({'success': False, 'error': 'Missing IP or attack type'}), 400
        
        # Map attack types to module imports and execution
        attack_modules = {
            'ssh': 'actions.ssh_connector',
            'ftp': 'actions.ftp_connector', 
            'telnet': 'actions.telnet_connector',
            'smb': 'actions.smb_connector',
            'rdp': 'actions.rdp_connector',
            'sql': 'actions.sql_connector'
        }
        
        if attack_type not in attack_modules:
            return jsonify({'success': False, 'error': 'Invalid attack type'}), 400
        
        # Execute attack in background
        def execute_attack():
            try:
                # Import the attack module dynamically
                import importlib
                module = importlib.import_module(attack_modules[attack_type])
                
                # Create attack instance
                attack_class_name = attack_type.upper() + 'Bruteforce' if attack_type != 'sql' else 'SQLBruteforce'
                attack_class = getattr(module, attack_class_name, None)
                
                if attack_class:
                    attack_instance = attack_class(shared_data)
                    # Execute with appropriate parameters
                    if hasattr(attack_instance, 'execute'):
                        row = {'ip': target_ip, 'hostname': target_ip, 'mac': '00:00:00:00:00:00'}
                        attack_instance.execute(target_ip, target_port, row, f"manual_{attack_type}")
                    
            except Exception as e:
                logger.error(f"Error executing manual attack: {e}")
        
        # Start attack in background thread
        import threading
        threading.Thread(target=execute_attack, daemon=True).start()
        
        logger.info(f"Manual attack initiated: {attack_type} on {target_ip}:{target_port}")
        
        return jsonify({
            'success': True,
            'message': f'Manual {attack_type} attack initiated on {target_ip}' + (f':{target_port}' if target_port else '')
        })
        
    except Exception as e:
        logger.error(f"Error executing manual attack: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/manual/orchestrator/start', methods=['POST'])
def start_orchestrator_manual():
    """Start the orchestrator in manual mode"""
    try:
        # Update shared data to indicate manual mode
        shared_data.config['manual_mode'] = True
        shared_data.save_config()  # Save the configuration
        
        logger.info("Manual mode enabled")
        
        return jsonify({
            'success': True,
            'message': 'Manual mode enabled - use individual triggers for actions'
        })
        
    except Exception as e:
        logger.error(f"Error enabling manual mode: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/manual/orchestrator/stop', methods=['POST'])
def stop_orchestrator_manual():
    """Disable manual mode"""
    try:
        # Update shared data to disable manual mode
        shared_data.config['manual_mode'] = False
        shared_data.save_config()  # Save the configuration
        
        logger.info("Manual mode disabled")
        
        return jsonify({
            'success': True,
            'message': 'Manual mode disabled'
        })
        
    except Exception as e:
        logger.error(f"Error disabling manual mode: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/manual/scan/network', methods=['POST'])
def trigger_network_scan():
    """Trigger a manual network scan"""
    try:
        data = request.get_json()
        target_range = data.get('range', '192.168.1.0/24')  # Default range
        
        # Execute scan in background
        def execute_scan():
            try:
                # Import and create scanner
                from actions.scanning import NetworkScanner
                scanner = NetworkScanner(shared_data)
                
                # Run the scan
                scanner.scan()
                
            except Exception as e:
                logger.error(f"Error executing network scan: {e}")
        
        # Start scan in background thread
        import threading
        threading.Thread(target=execute_scan, daemon=True).start()
        
        logger.info(f"Manual network scan initiated for range: {target_range}")
        
        return jsonify({
            'success': True,
            'message': f'Network scan initiated for {target_range}'
        })
        
    except Exception as e:
        logger.error(f"Error triggering network scan: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/manual/scan/vulnerability', methods=['POST'])
def trigger_vulnerability_scan():
    """Trigger a manual vulnerability scan"""
    try:
        data = request.get_json()
        target_ip = data.get('ip')
        
        if not target_ip:
            return jsonify({'success': False, 'error': 'Target IP required'}), 400
        
        # Execute vulnerability scan in background
        def execute_vuln_scan():
            try:
                # Import and create vulnerability scanner
                from actions.nmap_vuln_scanner import NmapVulnScanner
                vuln_scanner = NmapVulnScanner(shared_data)
                
                # Create a row for the scanner
                row = {'ip': target_ip, 'hostname': target_ip, 'mac': '00:00:00:00:00:00'}
                
                # Execute vulnerability scan
                vuln_scanner.execute(target_ip, row, "manual_vuln_scan")
                
            except Exception as e:
                logger.error(f"Error executing vulnerability scan: {e}")
        
        # Start scan in background thread
        import threading
        threading.Thread(target=execute_vuln_scan, daemon=True).start()
        
        logger.info(f"Manual vulnerability scan initiated for: {target_ip}")
        
        return jsonify({
            'success': True,
            'message': f'Vulnerability scan initiated for {target_ip}'
        })
        
    except Exception as e:
        logger.error(f"Error triggering vulnerability scan: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# FILE MANAGEMENT ENDPOINTS
# ============================================================================

@app.route('/api/files/list')
def list_files_api():
    """List files in a directory for file management"""
    try:
        path = request.args.get('path', '/')
        
        # Map root paths to actual directories
        if path == '/' or path == '':
            # List main directories
            return jsonify([
                {'name': 'data_stolen', 'is_directory': True, 'path': '/data_stolen'},
                {'name': 'scan_results', 'is_directory': True, 'path': '/scan_results'},
                {'name': 'crackedpwd', 'is_directory': True, 'path': '/crackedpwd'},
                {'name': 'vulnerabilities', 'is_directory': True, 'path': '/vulnerabilities'},
                {'name': 'logs', 'is_directory': True, 'path': '/logs'},
                {'name': 'backups', 'is_directory': True, 'path': '/backups'},
                {'name': 'uploads', 'is_directory': True, 'path': '/uploads'}
            ])
        
        # Map paths to actual directories
        actual_path = ""
        if path.startswith('/data_stolen'):
            actual_path = shared_data.datastolendir
            if len(path) > 12:  # More than just '/data_stolen'
                actual_path = os.path.join(actual_path, path[13:])
        elif path.startswith('/scan_results'):
            actual_path = shared_data.scan_results_dir
            if len(path) > 13:  # More than just '/scan_results'
                actual_path = os.path.join(actual_path, path[14:])
        elif path.startswith('/crackedpwd'):
            actual_path = shared_data.crackedpwddir
            if len(path) > 11:  # More than just '/crackedpwd'
                actual_path = os.path.join(actual_path, path[12:])
        elif path.startswith('/vulnerabilities'):
            actual_path = shared_data.vulnerabilities_dir
            if len(path) > 16:  # More than just '/vulnerabilities'
                actual_path = os.path.join(actual_path, path[17:])
        elif path.startswith('/logs'):
            actual_path = shared_data.datadir + '/logs'
            if len(path) > 5:  # More than just '/logs'
                actual_path = os.path.join(actual_path, path[6:])
        elif path.startswith('/backups'):
            actual_path = shared_data.backupdir
            if len(path) > 8:  # More than just '/backups'
                actual_path = os.path.join(actual_path, path[9:])
        elif path.startswith('/uploads'):
            actual_path = shared_data.upload_dir
            if len(path) > 8:  # More than just '/uploads'
                actual_path = os.path.join(actual_path, path[9:])
        else:
            return jsonify({'error': 'Invalid path'}), 400
        
        # Check if directory exists
        if not os.path.exists(actual_path):
            return jsonify([])
        
        # List files in directory
        files = []
        for entry in os.scandir(actual_path):
            files.append({
                'name': entry.name,
                'is_directory': entry.is_dir(),
                'path': os.path.join(path, entry.name),
                'size': entry.stat().st_size if entry.is_file() else 0,
                'modified': entry.stat().st_mtime
            })
        
        # Sort files - directories first, then by name
        files.sort(key=lambda x: (not x['is_directory'], x['name'].lower()))
        
        return jsonify(files)
        
    except Exception as e:
        logger.error(f"Error listing files: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/files/download')
def download_file_api():
    """Download a file"""
    try:
        file_path = request.args.get('path')
        if not file_path:
            return jsonify({'error': 'File path required'}), 400
        
        # Map virtual path to actual path
        actual_path = ""
        if file_path.startswith('/data_stolen'):
            actual_path = shared_data.datastolendir + file_path[12:]
        elif file_path.startswith('/scan_results'):
            actual_path = shared_data.scan_results_dir + file_path[13:]
        elif file_path.startswith('/crackedpwd'):
            actual_path = shared_data.crackedpwddir + file_path[11:]
        elif file_path.startswith('/vulnerabilities'):
            actual_path = shared_data.vulnerabilities_dir + file_path[16:]
        elif file_path.startswith('/logs'):
            actual_path = shared_data.datadir + '/logs' + file_path[5:]
        elif file_path.startswith('/backups'):
            actual_path = shared_data.backupdir + file_path[8:]
        elif file_path.startswith('/uploads'):
            actual_path = shared_data.upload_dir + file_path[8:]
        else:
            return jsonify({'error': 'Invalid file path'}), 400
        
        if not os.path.isfile(actual_path):
            return jsonify({'error': 'File not found'}), 404
        
        return send_from_directory(
            os.path.dirname(actual_path),
            os.path.basename(actual_path),
            as_attachment=True
        )
        
    except Exception as e:
        logger.error(f"Error downloading file: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/files/delete', methods=['POST'])
def delete_file_api():
    """Delete a file or directory"""
    try:
        data = request.get_json()
        file_path = data.get('path')
        
        if not file_path:
            return jsonify({'error': 'File path required'}), 400
        
        # Map virtual path to actual path
        actual_path = ""
        if file_path.startswith('/data_stolen'):
            actual_path = shared_data.datastolendir + file_path[12:]
        elif file_path.startswith('/scan_results'):
            actual_path = shared_data.scan_results_dir + file_path[13:]
        elif file_path.startswith('/crackedpwd'):
            actual_path = shared_data.crackedpwddir + file_path[11:]
        elif file_path.startswith('/vulnerabilities'):
            actual_path = shared_data.vulnerabilities_dir + file_path[16:]
        elif file_path.startswith('/logs'):
            actual_path = shared_data.datadir + '/logs' + file_path[5:]
        elif file_path.startswith('/backups'):
            actual_path = shared_data.backupdir + file_path[8:]
        elif file_path.startswith('/uploads'):
            actual_path = shared_data.upload_dir + file_path[8:]
        else:
            return jsonify({'error': 'Invalid file path'}), 400
        
        if not os.path.exists(actual_path):
            return jsonify({'error': 'File not found'}), 404
        
        # Delete file or directory
        if os.path.isdir(actual_path):
            import shutil
            shutil.rmtree(actual_path)
            logger.info(f"Deleted directory: {actual_path}")
        else:
            os.remove(actual_path)
            logger.info(f"Deleted file: {actual_path}")
        
        return jsonify({'success': True, 'message': 'File deleted successfully'})
        
    except Exception as e:
        logger.error(f"Error deleting file: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/files/upload', methods=['POST'])
def upload_file_api():
    """Upload a file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        target_path = request.form.get('path', '/uploads')
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Map virtual path to actual path
        actual_dir = ""
        if target_path.startswith('/uploads'):
            actual_dir = shared_data.upload_dir
        elif target_path.startswith('/backups'):
            actual_dir = shared_data.backupdir
        else:
            return jsonify({'error': 'Invalid upload path'}), 400
        
        # Create directory if it doesn't exist
        os.makedirs(actual_dir, exist_ok=True)
        
        # Save file
        filename = file.filename
        if not filename:
            return jsonify({'error': 'Invalid filename'}), 400
            
        actual_path = os.path.join(actual_dir, filename)
        file.save(actual_path)
        
        logger.info(f"File uploaded: {actual_path}")
        
        return jsonify({
            'success': True,
            'message': 'File uploaded successfully',
            'filename': filename
        })
        
    except Exception as e:
        logger.error(f"Error uploading file: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/files/clear', methods=['POST'])
def clear_files_api():
    """Clear files from specified directories"""
    try:
        data = request.get_json()
        clear_type = data.get('type', 'light')  # 'light' or 'full'
        
        if clear_type == 'light':
            # Clear only logs and temporary files (like clear_files_light)
            command = f"""
            rm -rf {shared_data.datadir}/*.log && 
            rm -rf {shared_data.datastolendir}/* && 
            rm -rf {shared_data.crackedpwddir}/* && 
            rm -rf {shared_data.scan_results_dir}/* && 
            rm -rf {shared_data.datadir}/logs/* && 
            rm -rf {shared_data.vulnerabilities_dir}/*
            """
        else:
            # Full clear (like clear_files)
            command = f"""
            rm -rf {shared_data.configdir}/*.json && 
            rm -rf {shared_data.datadir}/*.csv && 
            rm -rf {shared_data.datadir}/*.log && 
            rm -rf {shared_data.backupdir}/* && 
            rm -rf {shared_data.upload_dir}/* && 
            rm -rf {shared_data.datastolendir}/* && 
            rm -rf {shared_data.crackedpwddir}/* && 
            rm -rf {shared_data.scan_results_dir}/* && 
            rm -rf {shared_data.datadir}/logs/* && 
            rm -rf {shared_data.vulnerabilities_dir}/*
            """
        
        import subprocess
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info(f"Files cleared successfully ({clear_type} clear)")
            return jsonify({
                'success': True,
                'message': f'Files cleared successfully ({clear_type} clear)'
            })
        else:
            logger.error(f"Error clearing files: {result.stderr}")
            return jsonify({'error': result.stderr}), 500
        
    except Exception as e:
        logger.error(f"Error clearing files: {e}")
        return jsonify({'error': str(e)}), 500

# Legacy endpoint compatibility
@app.route('/list_files')
def legacy_list_files():
    """Legacy endpoint for file listing"""
    try:
        path = request.args.get('path', '/')
        
        # Use the same logic as list_files_api but return legacy format
        if path == '/' or path == '':
            return jsonify([
                {'name': 'data_stolen', 'is_directory': True, 'children': []},
                {'name': 'scan_results', 'is_directory': True, 'children': []},
                {'name': 'crackedpwd', 'is_directory': True, 'children': []},
                {'name': 'vulnerabilities', 'is_directory': True, 'children': []},
                {'name': 'logs', 'is_directory': True, 'children': []},
                {'name': 'backups', 'is_directory': True, 'children': []},
                {'name': 'uploads', 'is_directory': True, 'children': []}
            ])
        
        # For other paths, use the web_utils function
        actual_path = ""
        if path.startswith('/data_stolen'):
            actual_path = shared_data.datastolendir
        elif path.startswith('/scan_results'):
            actual_path = shared_data.scan_results_dir
        elif path.startswith('/crackedpwd'):
            actual_path = shared_data.crackedpwddir
        elif path.startswith('/vulnerabilities'):
            actual_path = shared_data.vulnerabilities_dir
        elif path.startswith('/logs'):
            actual_path = shared_data.datadir + '/logs'
        elif path.startswith('/backups'):
            actual_path = shared_data.backupdir
        elif path.startswith('/uploads'):
            actual_path = shared_data.upload_dir
        
        if actual_path and os.path.exists(actual_path):
            return jsonify(web_utils.list_files(actual_path))
        else:
            return jsonify([])
        
    except Exception as e:
        logger.error(f"Error in legacy file listing: {e}")
        return jsonify([])

@app.route('/download_file')
def legacy_download_file():
    """Legacy endpoint for file download"""
    try:
        file_path = request.args.get('path')
        if not file_path:
            return "File path required", 400
            
        # Check if file exists in data_stolen directory
        actual_path = os.path.join(shared_data.datastolendir, file_path)
        if os.path.isfile(actual_path):
            return send_from_directory(
                os.path.dirname(actual_path),
                os.path.basename(actual_path),
                as_attachment=True
            )
        else:
            return "File not found", 404
    except Exception as e:
        logger.error(f"Error in legacy file download: {e}")
        return str(e), 500

# ============================================================================
# IMAGE GALLERY ENDPOINTS
# ============================================================================

@app.route('/api/images/list')
def list_images_api():
    """Get list of all images and screenshots"""
    try:
        images = []
        
        # Define image directories to scan
        image_dirs = [
            ('screenshots', shared_data.webdir),  # Screenshots in web directory
            ('status_images', shared_data.statuspicdir),  # Status images
            ('static_images', shared_data.staticpicdir),  # Static images  
            ('captured_images', shared_data.datastolendir)  # Captured images in data stolen
        ]
        
        for category, directory in image_dirs:
            if os.path.exists(directory):
                for root, dirs, files in os.walk(directory):
                    for file in files:
                        if file.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp')):
                            filepath = os.path.join(root, file)
                            try:
                                stat = os.stat(filepath)
                                rel_path = os.path.relpath(filepath, shared_data.currentdir)
                                
                                images.append({
                                    'filename': file,
                                    'path': rel_path.replace('\\', '/'),
                                    'full_path': filepath,
                                    'category': category,
                                    'size': stat.st_size,
                                    'modified': stat.st_mtime,
                                    'url': f'/api/images/serve?path={rel_path.replace(chr(92), "/")}'
                                })
                            except Exception as e:
                                logger.error(f"Error processing image {file}: {e}")
        
        # Sort by modification time (newest first)
        images.sort(key=lambda x: x['modified'], reverse=True)
        
        return jsonify(images)
        
    except Exception as e:
        logger.error(f"Error listing images: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/images/serve')
def serve_image_api():
    """Serve an image file"""
    try:
        image_path = request.args.get('path')
        if not image_path:
            return jsonify({'error': 'Image path required'}), 400
        
        # Security check - ensure path is within project directory
        full_path = os.path.join(shared_data.currentdir, image_path)
        full_path = os.path.normpath(full_path)
        
        if not full_path.startswith(shared_data.currentdir):
            return jsonify({'error': 'Invalid path'}), 403
        
        if not os.path.isfile(full_path):
            return jsonify({'error': 'Image not found'}), 404
        
        return send_from_directory(
            os.path.dirname(full_path),
            os.path.basename(full_path)
        )
        
    except Exception as e:
        logger.error(f"Error serving image: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/images/delete', methods=['POST'])
def delete_image_api():
    """Delete an image file"""
    try:
        data = request.get_json()
        image_path = data.get('path')
        
        if not image_path:
            return jsonify({'error': 'Image path required'}), 400
        
        # Security check - ensure path is within project directory
        full_path = os.path.join(shared_data.currentdir, image_path)
        full_path = os.path.normpath(full_path)
        
        if not full_path.startswith(shared_data.currentdir):
            return jsonify({'error': 'Invalid path'}), 403
        
        if not os.path.isfile(full_path):
            return jsonify({'error': 'Image not found'}), 404
        
        os.remove(full_path)
        logger.info(f"Deleted image: {full_path}")
        
        return jsonify({'success': True, 'message': 'Image deleted successfully'})
        
    except Exception as e:
        logger.error(f"Error deleting image: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/images/capture', methods=['POST'])
def capture_screenshot_api():
    """Capture a new screenshot"""
    try:
        # Import display module for screenshot capture
        import display
        
        # Generate timestamp filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"screenshot_{timestamp}.png"
        filepath = os.path.join(shared_data.webdir, filename)
        
        # Capture screenshot using the display module
        display_manager = display.DisplayManager(shared_data)
        if hasattr(display_manager, 'capture_screenshot'):
            success = display_manager.capture_screenshot(filepath)
        else:
            # Fallback to creating a placeholder
            from PIL import Image, ImageDraw, ImageFont
            img = Image.new('RGB', (400, 300), color='black')
            draw = ImageDraw.Draw(img)
            draw.text((50, 150), f"Screenshot captured\n{timestamp}", fill='white')
            img.save(filepath)
            success = True
        
        if success:
            return jsonify({
                'success': True, 
                'message': 'Screenshot captured successfully',
                'filename': filename,
                'path': f'web/{filename}'
            })
        else:
            return jsonify({'error': 'Failed to capture screenshot'}), 500
        
    except Exception as e:
        logger.error(f"Error capturing screenshot: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/images/info')
def get_image_info_api():
    """Get detailed information about an image"""
    try:
        image_path = request.args.get('path')
        if not image_path:
            return jsonify({'error': 'Image path required'}), 400
        
        # Security check
        full_path = os.path.join(shared_data.currentdir, image_path)
        full_path = os.path.normpath(full_path)
        
        if not full_path.startswith(shared_data.currentdir):
            return jsonify({'error': 'Invalid path'}), 403
        
        if not os.path.isfile(full_path):
            return jsonify({'error': 'Image not found'}), 404
        
        # Get file stats
        stat = os.stat(full_path)
        
        # Try to get image dimensions
        try:
            from PIL import Image
            with Image.open(full_path) as img:
                width, height = img.size
                format_type = img.format
        except Exception:
            width = height = format_type = None
        
        info = {
            'filename': os.path.basename(full_path),
            'path': image_path,
            'size': stat.st_size,
            'size_formatted': format_bytes(stat.st_size),
            'modified': stat.st_mtime,
            'modified_formatted': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            'width': width,
            'height': height,
            'format': format_type
        }
        
        return jsonify(info)
        
    except Exception as e:
        logger.error(f"Error getting image info: {e}")
        return jsonify({'error': str(e)}), 500

def format_bytes(bytes_value):
    """Format bytes to human readable format"""
    if bytes_value == 0:
        return '0 B'
    
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} TB"

# ============================================================================
# SYSTEM MONITORING ENDPOINTS
# ============================================================================

@app.route('/api/system/status')
def get_system_status_api():
    """Get comprehensive system status"""
    try:
        import psutil
        import subprocess
        
        # CPU Information
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count()
        cpu_freq = psutil.cpu_freq()
        
        # Memory Information
        memory = psutil.virtual_memory()
        
        # Disk Information
        disk = psutil.disk_usage('/')
        
        # Network Interfaces
        net_if = psutil.net_if_addrs()
        net_stats = psutil.net_if_stats()
        
        # System Information
        boot_time = psutil.boot_time()
        uptime = time.time() - boot_time
        
        # Process Information
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                pinfo = proc.info
                processes.append({
                    'pid': pinfo['pid'],
                    'name': pinfo['name'],
                    'cpu_percent': pinfo['cpu_percent'],
                    'memory_percent': pinfo['memory_percent']
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Sort processes by CPU usage
        processes.sort(key=lambda x: x['cpu_percent'] or 0, reverse=True)
        processes = processes[:10]  # Top 10 processes
        
        # Temperature (if available)
        try:
            temps = psutil.sensors_temperatures()
            temperature_data = {}
            for name, entries in temps.items():
                for entry in entries:
                    temperature_data[f"{name}_{entry.label}"] = entry.current
        except:
            temperature_data = {}
        
        # Network interface details
        network_interfaces = []
        for interface, addrs in net_if.items():
            if interface in net_stats:
                stats = net_stats[interface]
                interface_info = {
                    'name': interface,
                    'is_up': stats.isup,
                    'speed': stats.speed,
                    'addresses': []
                }
                
                for addr in addrs:
                    interface_info['addresses'].append({
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    })
                
                network_interfaces.append(interface_info)
        
        system_status = {
            'cpu': {
                'percent': round(cpu_percent, 1),
                'count': cpu_count,
                'frequency': {
                    'current': round(cpu_freq.current, 2) if cpu_freq else None,
                    'min': round(cpu_freq.min, 2) if cpu_freq else None,
                    'max': round(cpu_freq.max, 2) if cpu_freq else None
                }
            },
            'memory': {
                'total': memory.total,
                'available': memory.available,
                'used': memory.used,
                'percent': round(memory.percent, 1),
                'total_formatted': format_bytes(memory.total),
                'available_formatted': format_bytes(memory.available),
                'used_formatted': format_bytes(memory.used)
            },
            'disk': {
                'total': disk.total,
                'used': disk.used,
                'free': disk.free,
                'percent': round((disk.used / disk.total) * 100, 1),
                'total_formatted': format_bytes(disk.total),
                'used_formatted': format_bytes(disk.used),
                'free_formatted': format_bytes(disk.free)
            },
            'uptime': {
                'seconds': round(uptime),
                'formatted': format_uptime(uptime)
            },
            'processes': processes,
            'network_interfaces': network_interfaces,
            'temperatures': temperature_data
        }
        
        return jsonify(system_status)
        
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/processes')
def get_processes_api():
    """Get detailed process information"""
    try:
        import psutil
        
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'create_time']):
            try:
                pinfo = proc.info
                processes.append({
                    'pid': pinfo['pid'],
                    'name': pinfo['name'],
                    'cpu_percent': round(pinfo['cpu_percent'] or 0, 2),
                    'memory_percent': round(pinfo['memory_percent'] or 0, 2),
                    'status': pinfo['status'],
                    'create_time': pinfo['create_time']
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Sort by CPU usage
        sort_by = request.args.get('sort', 'cpu')
        if sort_by == 'memory':
            processes.sort(key=lambda x: x['memory_percent'], reverse=True)
        else:
            processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
        
        return jsonify(processes)
        
    except Exception as e:
        logger.error(f"Error getting processes: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/network-stats')
def get_network_stats_api():
    """Get network interface statistics"""
    try:
        import psutil
        
        net_io = psutil.net_io_counters(pernic=True)
        net_connections = psutil.net_connections()
        
        # Count connections by status
        connection_stats = {}
        for conn in net_connections:
            status = conn.status
            connection_stats[status] = connection_stats.get(status, 0) + 1
        
        network_stats = {
            'interfaces': {},
            'connections': connection_stats,
            'total_connections': len(net_connections)
        }
        
        for interface, stats in net_io.items():
            network_stats['interfaces'][interface] = {
                'bytes_sent': stats.bytes_sent,
                'bytes_recv': stats.bytes_recv,
                'packets_sent': stats.packets_sent,
                'packets_recv': stats.packets_recv,
                'errin': stats.errin,
                'errout': stats.errout,
                'dropin': stats.dropin,
                'dropout': stats.dropout,
                'bytes_sent_formatted': format_bytes(stats.bytes_sent),
                'bytes_recv_formatted': format_bytes(stats.bytes_recv)
            }
        
        return jsonify(network_stats)
        
    except Exception as e:
        logger.error(f"Error getting network stats: {e}")
        return jsonify({'error': str(e)}), 500

def format_uptime(seconds):
    """Format uptime in human readable format"""
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)
    
    if days > 0:
        return f"{days}d {hours}h {minutes}m"
    elif hours > 0:
        return f"{hours}h {minutes}m"
    else:
        return f"{minutes}m"

# ============================================================================
# DASHBOARD API ENDPOINTS
# ============================================================================

@app.route('/api/dashboard/stats')
def get_dashboard_stats():
    """Get dashboard statistics including counts from various sources"""
    try:
        stats = {
            'target_count': 0,
            'port_count': 0,
            'vulnerability_count': 0,
            'credential_count': 0
        }
        
        # Get network scan results for target and port counts
        scan_results_dir = getattr(shared_data, 'scan_results_dir', os.path.join('data', 'output', 'scan_results'))
        if os.path.exists(scan_results_dir):
            unique_hosts = set()
            port_count = 0
            
            for filename in os.listdir(scan_results_dir):
                if filename.endswith('.txt'):
                    filepath = os.path.join(scan_results_dir, filename)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            if content.strip():
                                # Extract IP from filename
                                ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', filename)
                                if ip_match:
                                    unique_hosts.add(ip_match.group())
                                
                                # Count ports
                                for line in content.split('\n'):
                                    if '/tcp' in line or '/udp' in line:
                                        port_count += 1
                    except Exception as e:
                        continue
            
            stats['target_count'] = len(unique_hosts)
            stats['port_count'] = port_count
        
        # Add example data if no real scan data exists
        if stats['target_count'] == 0 and stats['port_count'] == 0:
            stats['target_count'] = 2  # Match NetKB example hosts
            stats['port_count'] = 2   # Match NetKB example ports
        
        # Get vulnerability count
        vuln_results_dir = getattr(shared_data, 'vulnerabilities_dir', os.path.join('data', 'output', 'vulnerabilities'))
        if os.path.exists(vuln_results_dir):
            vuln_count = 0
            for filename in os.listdir(vuln_results_dir):
                if filename.endswith('.txt'):
                    filepath = os.path.join(vuln_results_dir, filename)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            if content.strip():
                                # Count CVEs or files with vulnerability content
                                cve_matches = re.findall(r'CVE-\d{4}-\d+', content)
                                if cve_matches:
                                    vuln_count += len(cve_matches)
                                elif len(content.strip()) > 50:  # File has significant content
                                    vuln_count += 1
                    except Exception as e:
                        continue
            
            # If no real vulnerabilities found, add example count for consistency with NetKB
            if vuln_count == 0:
                # Check if we have example NetKB data by seeing if there are any real scan files
                real_data_exists = False
                scan_results_dir = getattr(shared_data, 'scan_results_dir', os.path.join('data', 'output', 'scan_results'))
                if os.path.exists(scan_results_dir):
                    for filename in os.listdir(scan_results_dir):
                        if filename.endswith('.txt'):
                            filepath = os.path.join(scan_results_dir, filename)
                            try:
                                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                    if f.read().strip():
                                        real_data_exists = True
                                        break
                            except:
                                continue
                
                # If no real data exists, add example vulnerability count to match NetKB
                if not real_data_exists:
                    vuln_count = 1  # Match the example vulnerability in NetKB
            
            stats['vulnerability_count'] = vuln_count
        
        # Get credential count
        cred_results_dir = getattr(shared_data, 'crackedpwd_dir', os.path.join('data', 'output', 'crackedpwd'))
        if os.path.exists(cred_results_dir):
            cred_count = 0
            for filename in os.listdir(cred_results_dir):
                if filename.endswith('.txt'):
                    filepath = os.path.join(cred_results_dir, filename)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            # Count lines with credential format (user:pass)
                            for line in content.split('\n'):
                                if ':' in line and line.strip():
                                    cred_count += 1
                    except Exception as e:
                        continue
            
            stats['credential_count'] = cred_count
        
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting dashboard stats: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# NETKB (Network Knowledge Base) API ENDPOINTS
# ============================================================================

@app.route('/api/netkb/data')
def get_netkb_data():
    """Get network knowledge base data"""
    try:
        netkb_entries = []
        
        # Process scan results for host/service information
        scan_results_dir = getattr(shared_data, 'scan_results_dir', os.path.join('data', 'output', 'scan_results'))
        if os.path.exists(scan_results_dir):
            for filename in os.listdir(scan_results_dir):
                if filename.endswith('.txt'):
                    filepath = os.path.join(scan_results_dir, filename)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            if content.strip():
                                # Extract IP from filename or content
                                ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', filename)
                                host_ip = ip_match.group() if ip_match else 'Unknown'
                                
                                # Parse port/service info from content
                                for line in content.split('\n'):
                                    if '/tcp' in line or '/udp' in line:
                                        parts = line.split()
                                        if len(parts) >= 3:
                                            port = parts[0]
                                            service = parts[2] if len(parts) > 2 else 'unknown'
                                            
                                            netkb_entries.append({
                                                'id': f"scan_{host_ip}_{port}",
                                                'type': 'service',
                                                'host': host_ip,
                                                'port': port,
                                                'service': service,
                                                'description': f"Service {service} running on {port}",
                                                'severity': 'info',
                                                'discovered': os.path.getmtime(filepath),
                                                'source': 'Network Scan'
                                            })
                    except Exception as e:
                        continue
        
        # Process vulnerability scan results
        vuln_results_dir = getattr(shared_data, 'vulnerabilities_dir', os.path.join('data', 'output', 'vulnerabilities'))
        if os.path.exists(vuln_results_dir):
            for filename in os.listdir(vuln_results_dir):
                if filename.endswith('.txt'):
                    filepath = os.path.join(vuln_results_dir, filename)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            if content.strip():
                                # Extract vulnerability information
                                ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', filename)
                                host_ip = ip_match.group() if ip_match else 'Unknown'
                                
                                # Look for CVE patterns
                                cve_matches = re.findall(r'CVE-\d{4}-\d+', content)
                                for cve in cve_matches:
                                    netkb_entries.append({
                                        'id': f"vuln_{host_ip}_{cve}",
                                        'type': 'vulnerability',
                                        'host': host_ip,
                                        'port': '',
                                        'service': '',
                                        'description': f"Vulnerability {cve} detected",
                                        'severity': 'high',
                                        'discovered': os.path.getmtime(filepath),
                                        'source': 'Vulnerability Scan',
                                        'cve': cve
                                    })
                                
                                # Generic vulnerability entries for files without CVEs
                                if not cve_matches and len(content.strip()) > 50:
                                    netkb_entries.append({
                                        'id': f"vuln_{host_ip}_{os.path.basename(filename)}",
                                        'type': 'vulnerability',
                                        'host': host_ip,
                                        'port': '',
                                        'service': '',
                                        'description': f"Vulnerability scan results for {host_ip}",
                                        'severity': 'medium',
                                        'discovered': os.path.getmtime(filepath),
                                        'source': 'Vulnerability Scan'
                                    })
                    except Exception as e:
                        continue
        
        # Add some example entries if no real data exists
        if not netkb_entries:
            netkb_entries = [
                {
                    'id': 'example_1',
                    'type': 'service',
                    'host': '192.168.1.1',
                    'port': '22/tcp',
                    'service': 'ssh',
                    'description': 'SSH service detected',
                    'severity': 'info',
                    'discovered': time.time(),
                    'source': 'Network Scan'
                },
                {
                    'id': 'example_2',
                    'type': 'vulnerability',
                    'host': '192.168.1.100',
                    'port': '80/tcp',
                    'service': 'http',
                    'description': 'Outdated web server version detected',
                    'severity': 'medium',
                    'discovered': time.time(),
                    'source': 'Vulnerability Scan'
                }
            ]
        
        # Calculate statistics
        total_entries = len(netkb_entries)
        vulnerabilities = len([e for e in netkb_entries if e['type'] == 'vulnerability'])
        services = len([e for e in netkb_entries if e['type'] == 'service'])
        unique_hosts = len(set([e['host'] for e in netkb_entries]))
        
        return jsonify({
            'entries': netkb_entries,
            'statistics': {
                'total_entries': total_entries,
                'vulnerabilities': vulnerabilities,
                'services': services,
                'unique_hosts': unique_hosts
            }
        })
    except Exception as e:
        logger.error(f"Error getting NetKB data: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/netkb/entry/<entry_id>')
def get_netkb_entry(entry_id):
    """Get detailed information for a specific NetKB entry"""
    try:
        # This would normally fetch detailed information about a specific entry
        # For now, return a placeholder response
        return jsonify({
            'id': entry_id,
            'detailed_info': f"Detailed information for entry {entry_id}",
            'recommendations': [
                "Monitor this service regularly",
                "Consider updating to latest version",
                "Implement proper access controls"
            ],
            'references': [
                "https://nvd.nist.gov/",
                "https://cve.mitre.org/",
                "https://www.exploit-db.com/"
            ]
        })
    except Exception as e:
        logger.error(f"Error getting NetKB entry: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/netkb/export')
def export_netkb_data():
    """Export NetKB data in various formats"""
    try:
        format_type = request.args.get('format', 'json')
        
        # Get NetKB data directly
        netkb_entries = []
        
        # Process scan results for host/service information
        scan_results_dir = getattr(shared_data, 'scan_results_dir', os.path.join('data', 'output', 'scan_results'))
        if os.path.exists(scan_results_dir):
            for filename in os.listdir(scan_results_dir):
                if filename.endswith('.txt'):
                    filepath = os.path.join(scan_results_dir, filename)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            if content.strip():
                                ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', filename)
                                host_ip = ip_match.group() if ip_match else 'Unknown'
                                
                                for line in content.split('\n'):
                                    if '/tcp' in line or '/udp' in line:
                                        parts = line.split()
                                        if len(parts) >= 3:
                                            port = parts[0]
                                            service = parts[2] if len(parts) > 2 else 'unknown'
                                            
                                            netkb_entries.append({
                                                'type': 'service',
                                                'host': host_ip,
                                                'port': port,
                                                'service': service,
                                                'description': f"Service {service} running on {port}",
                                                'severity': 'info',
                                                'source': 'Network Scan'
                                            })
                    except Exception as e:
                        continue
        
        # Add example data if no real data
        if not netkb_entries:
            netkb_entries = [
                {
                    'type': 'service',
                    'host': '192.168.1.1',
                    'port': '22/tcp',
                    'service': 'ssh',
                    'description': 'SSH service detected',
                    'severity': 'info',
                    'source': 'Network Scan'
                }
            ]
        
        if format_type == 'csv':
            import csv
            import io
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow(['Type', 'Host', 'Port', 'Service', 'Description', 'Severity', 'Source'])
            
            # Write data
            for entry in netkb_entries:
                writer.writerow([
                    entry['type'],
                    entry['host'],
                    entry['port'],
                    entry['service'],
                    entry['description'],
                    entry['severity'],
                    entry['source']
                ])
            
            output.seek(0)
            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': 'attachment; filename=netkb_export.csv'}
            )
        else:
            # Default to JSON export
            export_data = {
                'entries': netkb_entries,
                'exported_at': datetime.now().isoformat(),
                'total_entries': len(netkb_entries)
            }
            return Response(
                json.dumps(export_data, indent=2),
                mimetype='application/json',
                headers={'Content-Disposition': 'attachment; filename=netkb_export.json'}
            )
    except Exception as e:
        logger.error(f"Error exporting NetKB data: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# SIGNAL HANDLERS
# ============================================================================

def handle_exit(signum, frame):
    """Handle exit signals"""
    logger.info("Shutting down web server...")
    shared_data.webapp_should_exit = True
    socketio.stop()
    sys.exit(0)


# ============================================================================
# MAIN
# ============================================================================

def run_server(host='0.0.0.0', port=8000):
    """Run the Flask server"""
    try:
        logger.info(f"Starting Bjorn web server on {host}:{port}")
        logger.info(f"Access the interface at http://{host}:{port}")
        
        # Start background status broadcaster
        socketio.start_background_task(broadcast_status_updates)
        
        # Run the server
        socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True)
    except Exception as e:
        logger.error(f"Error running server: {e}")
        raise


if __name__ == "__main__":
    # Set up signal handling
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)
    
    # Run the server
    run_server()
