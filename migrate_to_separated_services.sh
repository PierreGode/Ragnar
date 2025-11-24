#!/bin/bash
# Migration Script for Service Separation
# This script helps migrate existing Ragnar installations to the new separated service architecture

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ragnar_PATH="/home/ragnar/Ragnar"

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}Ragnar Service Separation Migration${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}This script must be run as root. Please use 'sudo'.${NC}"
    exit 1
fi

# Check if Ragnar is installed
if [ ! -d "$ragnar_PATH" ]; then
    echo -e "${RED}Ragnar installation not found at $ragnar_PATH${NC}"
    exit 1
fi

echo -e "${YELLOW}This script will:${NC}"
echo "1. Stop the current ragnar.service"
echo "2. Create the new ragnar-web.service"
echo "3. Update service configurations with resource limits"
echo "4. Enable both services"
echo "5. Start both services"
echo ""
read -p "Continue? (y/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Migration cancelled.${NC}"
    exit 0
fi

# Step 1: Stop existing service
echo ""
echo -e "${BLUE}[1/5] Stopping existing ragnar.service...${NC}"
systemctl stop ragnar.service
echo -e "${GREEN}✓ Service stopped${NC}"

# Step 2: Create kill_port_8000.sh if it doesn't exist
echo ""
echo -e "${BLUE}[2/5] Creating helper scripts...${NC}"
if [ ! -f "$ragnar_PATH/kill_port_8000.sh" ]; then
    cat > $ragnar_PATH/kill_port_8000.sh << 'EOF'
#!/bin/bash
PORT=8000
PIDS=$(lsof -w -t -i:$PORT 2>/dev/null)
if [ -n "$PIDS" ]; then
    echo "Killing PIDs using port $PORT: $PIDS"
    kill -9 $PIDS
fi
EOF
    chmod +x $ragnar_PATH/kill_port_8000.sh
    chown ragnar:ragnar $ragnar_PATH/kill_port_8000.sh
    echo -e "${GREEN}✓ Created kill_port_8000.sh${NC}"
else
    echo -e "${GREEN}✓ kill_port_8000.sh already exists${NC}"
fi

# Step 3: Create new service files
echo ""
echo -e "${BLUE}[3/5] Creating systemd service files...${NC}"

# Create ragnar-core service (updated version)
cat > /etc/systemd/system/ragnar.service << EOF
[Unit]
Description=Ragnar Core Service (Orchestrator + Scanner + Display)
DefaultDependencies=no
Before=basic.target
After=local-fs.target

[Service]
ExecStart=/usr/bin/python3 -OO /home/ragnar/Ragnar/Ragnar.py
WorkingDirectory=/home/ragnar/Ragnar
StandardOutput=inherit
StandardError=inherit
Restart=always
User=root

# Resource limits to prevent OOM
MemoryMax=384M
MemoryHigh=320M

[Install]
WantedBy=multi-user.target
EOF

echo -e "${GREEN}✓ Created ragnar.service${NC}"

# Create ragnar-web service
cat > /etc/systemd/system/ragnar-web.service << EOF
[Unit]
Description=Ragnar Web Service (Flask Web UI)
DefaultDependencies=no
After=network.target ragnar.service
Wants=ragnar.service

[Service]
ExecStartPre=/home/ragnar/Ragnar/kill_port_8000.sh
ExecStart=/usr/bin/python3 -OO /home/ragnar/Ragnar/ragnar_web.py
WorkingDirectory=/home/ragnar/Ragnar
StandardOutput=inherit
StandardError=inherit
Restart=always
RestartSec=10
User=root

# Resource limits to prevent OOM
MemoryMax=256M
MemoryHigh=200M

[Install]
WantedBy=multi-user.target
EOF

echo -e "${GREEN}✓ Created ragnar-web.service${NC}"

# Step 4: Reload systemd and enable services
echo ""
echo -e "${BLUE}[4/5] Reloading systemd and enabling services...${NC}"
systemctl daemon-reload
systemctl enable ragnar.service
systemctl enable ragnar-web.service
echo -e "${GREEN}✓ Services enabled${NC}"

# Step 5: Start services
echo ""
echo -e "${BLUE}[5/5] Starting services...${NC}"
systemctl start ragnar.service
sleep 3
systemctl start ragnar-web.service
sleep 2

# Verify services are running
echo ""
echo -e "${BLUE}Verifying services...${NC}"
if systemctl is-active --quiet ragnar.service; then
    echo -e "${GREEN}✓ ragnar.service is running${NC}"
else
    echo -e "${RED}✗ ragnar.service is not running${NC}"
    echo -e "${YELLOW}Check logs with: sudo journalctl -u ragnar.service -xe${NC}"
fi

if systemctl is-active --quiet ragnar-web.service; then
    echo -e "${GREEN}✓ ragnar-web.service is running${NC}"
else
    echo -e "${RED}✗ ragnar-web.service is not running${NC}"
    echo -e "${YELLOW}Check logs with: sudo journalctl -u ragnar-web.service -xe${NC}"
fi

# Check web interface
echo ""
echo -e "${BLUE}Checking web interface...${NC}"
sleep 2
if curl -s http://localhost:8000 > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Web interface is accessible at http://localhost:8000${NC}"
else
    echo -e "${YELLOW}⚠ Web interface is not responding yet (may need more time to start)${NC}"
fi

echo ""
echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}Migration Complete!${NC}"
echo -e "${GREEN}======================================${NC}"
echo ""
echo -e "${BLUE}Service Management Commands:${NC}"
echo "  sudo systemctl status ragnar         # Check core service"
echo "  sudo systemctl status ragnar-web     # Check web service"
echo "  sudo systemctl restart ragnar        # Restart core"
echo "  sudo systemctl restart ragnar-web    # Restart web UI"
echo ""
echo -e "${BLUE}View Logs:${NC}"
echo "  sudo journalctl -u ragnar -f         # Core service logs"
echo "  sudo journalctl -u ragnar-web -f     # Web service logs"
echo ""
echo -e "${BLUE}Helper Script:${NC}"
echo "  $ragnar_PATH/ragnar-service-manager.sh status"
echo ""
echo -e "${YELLOW}Note: The web UI and core now run independently for better stability!${NC}"
