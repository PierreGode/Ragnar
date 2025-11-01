#!/bin/bash

# ragnar Installation Script
# This script handles the complete installation of ragnar
# Author: infinition
# Version: 1.0 - 071124 - 0954

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging configuration
LOG_DIR="/var/log/ragnar_install"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/ragnar_install_$(date +%Y%m%d_%H%M%S).log"
VERBOSE=false

# Global variables
ragnar_USER="ragnar"
ragnar_PATH="/home/${ragnar_USER}/ragnar"
CURRENT_STEP=0
TOTAL_STEPS=9

if [[ "$1" == "--help" ]]; then
    echo "Usage: sudo ./install_ragnar.sh"
    echo "Make sure you have the necessary permissions and that all dependencies are met."
    exit 0
fi

# Function to display progress
show_progress() {
    echo -e "${BLUE}Step $CURRENT_STEP of $TOTAL_STEPS: $1${NC}"
}

# Logging function
log() {
    local level=$1
    shift
    local message="[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*"
    echo -e "$message" >> "$LOG_FILE"
    if [ "$VERBOSE" = true ] || [ "$level" != "DEBUG" ]; then
        case $level in
            "ERROR") echo -e "${RED}$message${NC}" ;;
            "SUCCESS") echo -e "${GREEN}$message${NC}" ;;
            "WARNING") echo -e "${YELLOW}$message${NC}" ;;
            "INFO") echo -e "${BLUE}$message${NC}" ;;
            *) echo -e "$message" ;;
        esac
    fi
}

# Error handling function
handle_error() {
    local error_code=$?
    local error_message=$1
    log "ERROR" "An error occurred during: $error_message (Error code: $error_code)"
    log "ERROR" "Check the log file for details: $LOG_FILE"

    echo -e "\n${RED}Would you like to:"
    echo "1. Retry this step"
    echo "2. Skip this step (not recommended)"
    echo "3. Exit installation${NC}"
    read -r choice

    case $choice in
        1) return 1 ;; # Retry
        2) return 0 ;; # Skip
        3) clean_exit 1 ;; # Exit
        *) handle_error "$error_message" ;; # Invalid choice
    esac
}

# Function to check command success
check_success() {
    if [ $? -eq 0 ]; then
        log "SUCCESS" "$1"
        return 0
    else
        handle_error "$1"
        return $?
    fi
}

# # Check system compatibility
# check_system_compatibility() {
#     log "INFO" "Checking system compatibility..."
    
#     # Check if running on Raspberry Pi
#     if ! grep -q "Raspberry Pi" /proc/cpuinfo; then
#         log "WARNING" "This system might not be a Raspberry Pi. Continue anyway? (y/n)"
#         read -r response
#         if [[ ! "$response" =~ ^[Yy]$ ]]; then
#             clean_exit 1
#         fi
#     fi
    
#     check_success "System compatibility check completed"
# }
# Check system compatibility
check_system_compatibility() {
    log "INFO" "Checking system compatibility..."
    local should_ask_confirmation=false
    
    # Check if running on Raspberry Pi
    if ! grep -q "Raspberry Pi" /proc/cpuinfo; then
        log "WARNING" "This system might not be a Raspberry Pi"
        should_ask_confirmation=true
    fi

    # Check RAM (Raspberry Pi Zero has 512MB RAM)
    total_ram=$(free -m | awk '/^Mem:/{print $2}')
    if [ "$total_ram" -lt 410 ]; then
        log "WARNING" "Low RAM detected. Required: 512MB (410 With OS Running), Found: ${total_ram}MB"
        echo -e "${YELLOW}Your system has less RAM than recommended. This might affect performance, but you can continue.${NC}"
        should_ask_confirmation=true
    else
        log "SUCCESS" "RAM check passed: ${total_ram}MB available"
    fi

    # Check available disk space
    available_space=$(df -m /home | awk 'NR==2 {print $4}')
    if [ "$available_space" -lt 2048 ]; then
        log "WARNING" "Low disk space. Recommended: 1GB, Found: ${available_space}MB"
        echo -e "${YELLOW}Your system has less free space than recommended. This might affect installation.${NC}"
        should_ask_confirmation=true
    else
        log "SUCCESS" "Disk space check passed: ${available_space}MB available"
    fi

    # Check OS version
    if [ -f "/etc/os-release" ]; then
        source /etc/os-release
        
        # Verify if it's Raspbian
        if [ "$NAME" != "Raspbian GNU/Linux" ]; then
            log "WARNING" "Different OS detected. Recommended: Raspbian GNU/Linux, Found: ${NAME}"
            echo -e "${YELLOW}Your system is not running Raspbian GNU/Linux.${NC}"
            should_ask_confirmation=true
        fi
        
        # Compare versions (expecting Bookworm = 12)
        expected_version="12"
        if [ "$VERSION_ID" != "$expected_version" ]; then
            log "WARNING" "Different OS version detected"
            echo -e "${YELLOW}This script was tested with Raspbian GNU/Linux 12 (bookworm)${NC}"
            echo -e "${YELLOW}Current system: ${PRETTY_NAME}${NC}"
            if [ "$VERSION_ID" -lt "$expected_version" ]; then
                echo -e "${YELLOW}Your system version ($VERSION_ID) is older than recommended ($expected_version)${NC}"
            elif [ "$VERSION_ID" -gt "$expected_version" ]; then
                echo -e "${YELLOW}Your system version ($VERSION_ID) is newer than tested ($expected_version)${NC}"
            fi
            should_ask_confirmation=true
        else
            log "SUCCESS" "OS version check passed: ${PRETTY_NAME}"
        fi
    else
        log "WARNING" "Could not determine OS version (/etc/os-release not found)"
        should_ask_confirmation=true
    fi

    # Check if system is 32-bit ARM (armhf)
    architecture=$(dpkg --print-architecture)
    if [ "$architecture" != "armhf" ]; then
        log "WARNING" "Different architecture detected. Expected: armhf, Found: ${architecture}"
        echo -e "${YELLOW}This script was tested with armhf architecture${NC}"
        should_ask_confirmation=true
    fi
    
    # Additional Pi Zero specific checks if possible
    if ! (grep -q "Pi Zero" /proc/cpuinfo || grep -q "BCM2835" /proc/cpuinfo); then
        log "WARNING" "Could not confirm if this is a Raspberry Pi Zero"
        echo -e "${YELLOW}This script was designed for Raspberry Pi Zero${NC}"
        should_ask_confirmation=true
    else
        log "SUCCESS" "Raspberry Pi Zero detected"
    fi

    if [ "$should_ask_confirmation" = true ]; then
        echo -e "\n${YELLOW}Some system compatibility warnings were detected (see above).${NC}"
        echo -e "${YELLOW}The installation might not work as expected.${NC}"
        echo -e "${YELLOW}Do you want to continue anyway? (y/n)${NC}"
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            log "INFO" "Installation aborted by user after compatibility warnings"
            clean_exit 1
        fi
    else
        log "SUCCESS" "All compatibility checks passed"
    fi

    log "INFO" "System compatibility check completed"
    return 0
}

# Check internet connectivity
check_internet() {
    log "INFO" "Checking internet connectivity..."
    
    # Try to ping common servers
    if ping -c 2 8.8.8.8 > /dev/null 2>&1 || ping -c 2 1.1.1.1 > /dev/null 2>&1; then
        log "SUCCESS" "Internet connectivity confirmed"
        
        # Test DNS resolution
        if ping -c 1 pypi.org > /dev/null 2>&1; then
            log "SUCCESS" "DNS resolution working"
        else
            log "WARNING" "DNS resolution issues detected. Package installation may be slow."
            log "INFO" "Consider checking /etc/resolv.conf or your network settings"
        fi
        return 0
    else
        log "WARNING" "No internet connectivity detected!"
        echo -e "${YELLOW}Internet connection is required to download Python packages.${NC}"
        echo -e "${YELLOW}Please check your network connection and try again.${NC}"
        echo -e "\nDo you want to:"
        echo "1. Continue anyway (installation may fail)"
        echo "2. Exit and fix network issues first (recommended)"
        read -r choice
        case $choice in
            1) 
                log "WARNING" "Continuing without verified internet connection"
                return 0
                ;;
            *)
                log "INFO" "Installation aborted - please fix network issues first"
                clean_exit 1
                ;;
        esac
    fi
}


# Install system dependencies
install_dependencies() {
    log "INFO" "Installing system dependencies..."
    
    # Update package list
    apt-get update
    
    # List of required packages based on README
    packages=(
        "python3-pip"
        "wget"
        "lsof"
        "git"
        "libopenjp2-7"
        "nmap"
        "libopenblas-dev"
        "bluez-tools"
        "bluez"
        "dhcpcd5"
        "bridge-utils"
        "python3-pil"
        "libjpeg-dev"
        "zlib1g-dev"
        "libpng-dev"
        "python3-dev"
        "libffi-dev"
        "libssl-dev"
        "libgpiod-dev"
        "libi2c-dev"
        "build-essential"
        "python3-sqlalchemy"
        "python3-pandas"
        "python3-numpy"
        "hostapd"
        "dnsmasq"
    )
    
    # Optional packages that may not be available in all distributions
    optional_packages=(
        "libatlas-base-dev"
    )
    
    # Optional packages that may not be available in all distributions
    optional_packages=(
        "libatlas-base-dev"
    )
    
    # Install required packages
    for package in "${packages[@]}"; do
        log "INFO" "Installing $package..."
        apt-get install -y "$package"
        check_success "Installed $package"
    done
    
    # Install optional packages (don't fail if unavailable)
    for package in "${optional_packages[@]}"; do
        log "INFO" "Attempting to install optional package: $package..."
        if apt-get install -y "$package" 2>/dev/null; then
            log "SUCCESS" "Installed optional package: $package"
        else
            log "WARNING" "Optional package $package not available (this is OK, using alternatives)"
        fi
    done
    
    # Update nmap scripts
    nmap --script-updatedb
    check_success "Dependencies installation completed"
}

# Configure system limits
configure_system_limits() {
    log "INFO" "Configuring system limits..."

    # Configure /etc/security/limits.conf
    cat >> /etc/security/limits.conf << EOF
* soft nofile 65535
* hard nofile 65535
root soft nofile 65535
root hard nofile 65535
EOF

    # Configure systemd limits
    sed -i '/^#DefaultLimitNOFILE=/d' /etc/systemd/system.conf
    echo "DefaultLimitNOFILE=65535" >> /etc/systemd/system.conf
    sed -i '/^#DefaultLimitNOFILE=/d' /etc/systemd/user.conf
    echo "DefaultLimitNOFILE=65535" >> /etc/systemd/user.conf

    # Create /etc/security/limits.d/90-nofile.conf
    cat > /etc/security/limits.d/90-nofile.conf << EOF
root soft nofile 65535
root hard nofile 65535
EOF

    # Configure sysctl
    echo "fs.file-max = 2097152" >> /etc/sysctl.conf
    sysctl -p

    check_success "System limits configuration completed"
}

# Configure SPI and I2C
configure_interfaces() {
    log "INFO" "Configuring SPI and I2C interfaces..."
    
    # Enable SPI and I2C using raspi-config
    raspi-config nonint do_spi 0
    raspi-config nonint do_i2c 0
    
    check_success "Interface configuration completed"
}

# Setup ragnar
setup_ragnar() {
    log "INFO" "Setting up ragnar..."
    
    # Create ragnar user if it doesn't exist
    if ! id -u $ragnar_USER >/dev/null 2>&1; then
        adduser --disabled-password --gecos "" $ragnar_USER
        check_success "Created ragnar user"
    fi

    # Check for existing ragnar directory
    cd /home/$ragnar_USER
    if [ -d "ragnar" ]; then
        log "INFO" "Using existing ragnar directory"
        echo -e "${GREEN}Using existing ragnar directory${NC}"
    else
        # No existing directory, proceed with clone
        log "INFO" "Cloning ragnar repository"
        #git clone https://github.com/infinition/ragnar.git
        git clone https://github.com/PierreGode/ragnar.git
        check_success "Cloned ragnar repository"
    fi

    cd ragnar

    # Update the shared_config.json file with the selected EPD version
    log "INFO" "Updating E-Paper display configuration..."
    if [ -f "config/shared_config.json" ]; then
        sed -i "s/\"epd_type\": \"[^\"]*\"/\"epd_type\": \"$EPD_VERSION\"/" config/shared_config.json
        check_success "Updated E-Paper display configuration to $EPD_VERSION"
    else
        log "ERROR" "Configuration file not found: config/shared_config.json"
        handle_error "E-Paper display configuration update"
    fi

    # Install requirements with --break-system-packages flag
    log "INFO" "Installing Python requirements..."
    
    # Install packages that can fail separately to handle errors
    log "INFO" "Installing core Python packages..."
    
    # Function to check if a Python package is installed
    check_python_package() {
        python3 -c "import $1" 2>/dev/null
        return $?
    }
    
    # Try to install RPi.GPIO and spidev
    if ! check_python_package "RPi.GPIO"; then
        log "INFO" "Installing RPi.GPIO and spidev..."
        pip3 install --break-system-packages RPi.GPIO==0.7.1 spidev==3.5 || {
            log "WARNING" "Failed to install RPi.GPIO or spidev, trying without version pinning..."
            pip3 install --break-system-packages RPi.GPIO spidev
        }
    else
        log "INFO" "RPi.GPIO already installed, skipping"
    fi
    
    # Install Pillow - use system package if pip fails
    if ! check_python_package "PIL"; then
        log "INFO" "Installing Pillow..."
        pip3 install --break-system-packages "Pillow>=10.0.0" || {
            log "WARNING" "Pillow pip install failed, using system package python3-pil"
            apt-get install -y python3-pil
        }
    else
        log "INFO" "Pillow already installed, skipping"
    fi
    
    # Install numpy and pandas - prefer system packages but fallback to pip
    log "INFO" "Checking numpy and pandas..."
    if ! check_python_package "numpy" || ! check_python_package "pandas"; then
        log "INFO" "Installing numpy and pandas (this may take a while)..."
        pip3 install --break-system-packages --retries 5 --timeout 300 "numpy>=1.24.0" "pandas>=2.0.0" || {
            log "WARNING" "Pandas/numpy pip install failed, relying on system packages"
        }
    else
        log "INFO" "numpy and pandas already installed, skipping"
    fi
    
    # Install remaining packages from requirements.txt with retry logic
    log "INFO" "Installing remaining Python packages..."
    
    # Array of packages to install with their import names
    declare -A packages=(
        ["rich>=13.0.0"]="rich"
        ["netifaces==0.11.0"]="netifaces"
        ["ping3>=4.0.0"]="ping3"
        ["get-mac>=0.9.0"]="get_mac"
        ["paramiko>=3.0.0"]="paramiko"
        ["smbprotocol>=1.10.0"]="smbprotocol"
        ["pysmb>=1.2.0"]="smb"
        ["pymysql>=1.0.0"]="pymysql"
        ["python-nmap>=0.7.0"]="nmap"
        ["flask>=3.0.0"]="flask"
        ["flask-socketio>=5.3.0"]="flask_socketio"
        ["flask-cors>=4.0.0"]="flask_cors"
    )
    
    # Install each package individually with retries if not already installed
    for package in "${!packages[@]}"; do
        import_name="${packages[$package]}"
        if check_python_package "$import_name"; then
            log "INFO" "$package already installed, skipping"
        else
            log "INFO" "Installing $package..."
            pip3 install --break-system-packages --retries 3 --timeout 180 "$package" || {
                log "WARNING" "Failed to install $package after retries. Continuing..."
            }
        fi
    done
    
    check_success "Installed Python requirements"

    # Configure modern webapp by default
    log "INFO" "Configuring modern web interface..."
    if [ -f "$ragnar_PATH/ragnar.py" ] && [ -f "$ragnar_PATH/webapp_modern.py" ]; then
        # Backup original ragnar.py if not already backed up
        if [ ! -f "$ragnar_PATH/ragnar.py.original" ]; then
            cp "$ragnar_PATH/ragnar.py" "$ragnar_PATH/ragnar.py.original"
        fi
        
        # Update ragnar.py to use modern webapp
        if grep -q "from webapp import web_thread" "$ragnar_PATH/ragnar.py"; then
            sed -i 's/from webapp import web_thread/# Old webapp - replaced with modern\n# from webapp import web_thread\nfrom webapp_modern import run_server as web_thread/' "$ragnar_PATH/ragnar.py"
            log "SUCCESS" "Configured to use modern web interface"
        else
            log "INFO" "Modern webapp already configured or different setup detected"
        fi
    else
        log "WARNING" "Modern webapp files not found, using default configuration"
    fi

    # Set correct permissions and ownership
    chown -R $ragnar_USER:$ragnar_USER /home/$ragnar_USER/ragnar
    chmod -R 755 /home/$ragnar_USER/ragnar
    
    # Make utility scripts executable with proper ownership
    chmod +x $ragnar_PATH/switch_webapp.sh 2>/dev/null || true
    chmod +x $ragnar_PATH/kill_port_8000.sh 2>/dev/null || true
    chmod +x $ragnar_PATH/update_ragnar.sh 2>/dev/null || true
    chmod +x $ragnar_PATH/quick_update.sh 2>/dev/null || true
    chmod +x $ragnar_PATH/uninstall_ragnar.sh 2>/dev/null || true
    chmod +x $ragnar_PATH/wifi_fix.sh 2>/dev/null || true
    chmod +x $ragnar_PATH/install_modern_webapp.sh 2>/dev/null || true
    
    # Ensure ragnar user owns all script files
    chown $ragnar_USER:$ragnar_USER $ragnar_PATH/*.sh 2>/dev/null || true
    
    # Validate and fix actions.json file
    log "INFO" "Validating actions.json configuration..."
    python3 << 'PYTHON_EOF'
import json
import os

actions_file = "/home/ragnar/ragnar/config/actions.json"

# Check if scanning module exists in actions.json
try:
    with open(actions_file, 'r') as f:
        actions = json.load(f)
    
    # Check if scanning module is present
    has_scanning = any(action.get('b_module') == 'scanning' for action in actions)
    
    if not has_scanning:
        print("WARNING: scanning module missing from actions.json, adding it...")
        scanning_action = {
            "b_module": "scanning",
            "b_class": "NetworkScanner",
            "b_port": None,
            "b_status": "network_scanner",
            "b_parent": None
        }
        actions.insert(0, scanning_action)
        
        with open(actions_file, 'w') as f:
            json.dump(actions, f, indent=4)
        print("SUCCESS: Added scanning module to actions.json")
    else:
        print("SUCCESS: scanning module found in actions.json")
        
except Exception as e:
    print(f"ERROR validating actions.json: {e}")
PYTHON_EOF
    
    # Add ragnar user to necessary groups
    usermod -a -G spi,gpio,i2c $ragnar_USER
    check_success "Added ragnar user to required groups"
}


# Configure services
setup_services() {
    log "INFO" "Setting up system services..."
    
    # Create kill_port_8000.sh script
    cat > $ragnar_PATH/kill_port_8000.sh << 'EOF'
#!/bin/bash
PORT=8000
PIDS=$(lsof -t -i:$PORT)
if [ -n "$PIDS" ]; then
    echo "Killing PIDs using port $PORT: $PIDS"
    kill -9 $PIDS
fi
EOF
    chmod +x $ragnar_PATH/kill_port_8000.sh
    chown ragnar:ragnar $ragnar_PATH/kill_port_8000.sh

    # Create ragnar service
    cat > /etc/systemd/system/ragnar.service << EOF
[Unit]
Description=ragnar Service
DefaultDependencies=no
Before=basic.target
After=local-fs.target

[Service]
ExecStartPre=/home/ragnar/ragnar/kill_port_8000.sh
ExecStart=/usr/bin/python3 /home/ragnar/ragnar/ragnar.py
WorkingDirectory=/home/ragnar/ragnar
StandardOutput=inherit
StandardError=inherit
Restart=always
User=root

# Check open files and restart if it reached the limit (ulimit -n buffer of 1000)
ExecStartPost=/bin/bash -c 'FILE_LIMIT=\$(ulimit -n); THRESHOLD=\$(( FILE_LIMIT - 1000 )); while :; do TOTAL_OPEN_FILES=\$(lsof | wc -l); if [ "\$TOTAL_OPEN_FILES" -ge "\$THRESHOLD" ]; then echo "File descriptor threshold reached: \$TOTAL_OPEN_FILES (threshold: \$THRESHOLD). Restarting service."; systemctl restart ragnar.service; exit 0; fi; sleep 10; done &'

[Install]
WantedBy=multi-user.target
EOF

    # Configure PAM
    echo "session required pam_limits.so" >> /etc/pam.d/common-session
    echo "session required pam_limits.so" >> /etc/pam.d/common-session-noninteractive

    # Enable and start services
    systemctl daemon-reload
    systemctl enable ragnar.service

    check_success "Services setup completed"
}

# Configure USB Gadget
configure_usb_gadget() {
    log "INFO" "Configuring USB Gadget..."

    # Modify cmdline.txt
    sed -i 's/rootwait/rootwait modules-load=dwc2,g_ether/' /boot/firmware/cmdline.txt

    # Modify config.txt
    echo "dtoverlay=dwc2" >> /boot/firmware/config.txt

    # Create USB gadget script
    cat > /usr/local/bin/usb-gadget.sh << 'EOF'
#!/bin/bash
set -e

modprobe libcomposite
cd /sys/kernel/config/usb_gadget/
mkdir -p g1
cd g1

echo 0x1d6b > idVendor
echo 0x0104 > idProduct
echo 0x0100 > bcdDevice
echo 0x0200 > bcdUSB

mkdir -p strings/0x409
echo "fedcba9876543210" > strings/0x409/serialnumber
echo "Raspberry Pi" > strings/0x409/manufacturer
echo "Pi Zero USB" > strings/0x409/product

mkdir -p configs/c.1/strings/0x409
echo "Config 1: ECM network" > configs/c.1/strings/0x409/configuration
echo 250 > configs/c.1/MaxPower

mkdir -p functions/ecm.usb0

if [ -L configs/c.1/ecm.usb0 ]; then
    rm configs/c.1/ecm.usb0
fi
ln -s functions/ecm.usb0 configs/c.1/

max_retries=10
retry_count=0

while ! ls /sys/class/udc > UDC 2>/dev/null; do
    if [ $retry_count -ge $max_retries ]; then
        echo "Error: Device or resource busy after $max_retries attempts."
        exit 1
    fi
    retry_count=$((retry_count + 1))
    sleep 1
done

if ! ip addr show usb0 | grep -q "172.20.2.1"; then
    ifconfig usb0 172.20.2.1 netmask 255.255.255.0
else
    echo "Interface usb0 already configured."
fi
EOF

    chmod +x /usr/local/bin/usb-gadget.sh

    # Create USB gadget service
    cat > /etc/systemd/system/usb-gadget.service << EOF
[Unit]
Description=USB Gadget Service
After=network.target

[Service]
ExecStartPre=/sbin/modprobe libcomposite
ExecStart=/usr/local/bin/usb-gadget.sh
Type=simple
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    # Configure network interface
    cat >> /etc/network/interfaces << EOF

allow-hotplug usb0
iface usb0 inet static
    address 172.20.2.1
    netmask 255.255.255.0
EOF

    # Enable and start services
    systemctl daemon-reload
    systemctl enable systemd-networkd
    systemctl enable usb-gadget
    systemctl start systemd-networkd
    systemctl start usb-gadget

    check_success "USB Gadget configuration completed"
}

# Verify installation
verify_installation() {
    log "INFO" "Verifying installation..."
    
    # Check if services are running
    if ! systemctl is-active --quiet ragnar.service; then
        log "WARNING" "ragnar service is not running"
    else
        log "SUCCESS" "ragnar service is running"
    fi
    
    # Check web interface
    sleep 5
    if curl -s http://localhost:8000 > /dev/null; then
        log "SUCCESS" "Web interface is accessible"
    else
        log "WARNING" "Web interface is not responding"
    fi
}

# Clean exit function
clean_exit() {
    local exit_code=$1
    if [ $exit_code -eq 0 ]; then
        log "SUCCESS" "ragnar installation completed successfully!"
        log "INFO" "Log file available at: $LOG_FILE"
    else
        log "ERROR" "ragnar installation failed!"
        log "ERROR" "Check the log file for details: $LOG_FILE"
    fi
    exit $exit_code
}

# Main installation process
main() {
    log "INFO" "Starting ragnar installation..."

    # Check if script is run as root
    if [ "$(id -u)" -ne 0 ]; then
        echo "This script must be run as root. Please use 'sudo'."
        exit 1
    fi

    echo -e "${BLUE}ragnar Installation Options:${NC}"
    echo "1. Full installation (recommended)"
    echo "2. Custom installation"
    read -p "Choose an option (1/2): " install_option

    # E-Paper Display Selection
    echo -e "\n${BLUE}Please select your E-Paper Display version:${NC}"
    echo "1. epd2in13"
    echo "2. epd2in13_V2"
    echo "3. epd2in13_V3"
    echo "4. epd2in13_V4"
    echo "5. epd2in7"
    
    while true; do
        read -p "Enter your choice (1-4): " epd_choice
        case $epd_choice in
            1) EPD_VERSION="epd2in13"; break;;
            2) EPD_VERSION="epd2in13_V2"; break;;
            3) EPD_VERSION="epd2in13_V3"; break;;
            4) EPD_VERSION="epd2in13_V4"; break;;
            5) EPD_VERSION="epd2in7"; break;;
            *) echo -e "${RED}Invalid choice. Please select 1-5.${NC}";;
        esac
    done

    log "INFO" "Selected E-Paper Display version: $EPD_VERSION"

    case $install_option in
        1)
            CURRENT_STEP=1; show_progress "Checking system compatibility"
            check_system_compatibility
            
            CURRENT_STEP=2; show_progress "Checking internet connectivity"
            check_internet

            CURRENT_STEP=3; show_progress "Installing system dependencies"
            install_dependencies

            CURRENT_STEP=4; show_progress "Configuring system limits"
            configure_system_limits

            CURRENT_STEP=5; show_progress "Configuring interfaces"
            configure_interfaces

            CURRENT_STEP=6; show_progress "Setting up ragnar"
            setup_ragnar

            CURRENT_STEP=7; show_progress "Configuring USB Gadget"
            configure_usb_gadget

            CURRENT_STEP=8; show_progress "Setting up services"
            setup_services

            CURRENT_STEP=8; show_progress "Verifying installation"
            verify_installation
            ;;
        2)
            echo "Custom installation - select components to install:"
            read -p "Install dependencies? (y/n): " deps
            read -p "Configure system limits? (y/n): " limits
            read -p "Configure interfaces? (y/n): " interfaces
            read -p "Setup ragnar? (y/n): " ragnar
            read -p "Configure USB Gadget? (y/n): " usb_gadget
            read -p "Setup services? (y/n): " services

            [ "$deps" = "y" ] && install_dependencies
            [ "$limits" = "y" ] && configure_system_limits
            [ "$interfaces" = "y" ] && configure_interfaces
            [ "$ragnar" = "y" ] && setup_ragnar
            [ "$usb_gadget" = "y" ] && configure_usb_gadget
            [ "$services" = "y" ] && setup_services
            verify_installation
            ;;
        *)
            log "ERROR" "Invalid option selected"
            clean_exit 1
            ;;
    esac

    # Git repository is preserved for updates
    # Use .gitignore to protect runtime data and configurations
    log "INFO" "Git repository preserved for future updates"

    log "SUCCESS" "ragnar installation completed!"
    log "INFO" "Please reboot your system to apply all changes."
    echo -e "\n${GREEN}Installation completed successfully!${NC}"
    echo -e "${YELLOW}Important notes:${NC}"
    echo "1. If configuring Windows PC for USB gadget connection:"
    echo "   - Set static IP: 172.20.2.2"
    echo "   - Subnet Mask: 255.255.255.0"
    echo "   - Default Gateway: 172.20.2.1"
    echo "   - DNS Servers: 8.8.8.8, 8.8.4.4"
    echo "2. Web interface will be available at: http://[device-ip]:8000"
    echo "3. Make sure your e-Paper HAT (2.13-inch) is properly connected"
    echo -e "\n${BLUE}To update ragnar in the future:${NC}"
    echo "   cd /home/ragnar/ragnar"
    echo "   sudo git stash  # Save any local changes"
    echo "   sudo git pull   # Get latest updates"
    echo "   sudo systemctl restart ragnar"

    read -p "Would you like to reboot now? (y/n): " reboot_now
    if [ "$reboot_now" = "y" ]; then
        if reboot; then
            log "INFO" "System reboot initiated."
        else
            log "ERROR" "Failed to initiate reboot."
            exit 1
        fi
    else
        echo -e "${YELLOW}Reboot your system to apply all changes & run ragnar service.${NC}"
    fi
}

main




