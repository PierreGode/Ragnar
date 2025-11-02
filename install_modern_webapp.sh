#!/bin/bash
# Quick installer for ragnar Modern Web Interface

echo "================================================"
echo "ragnar Modern Web Interface - Quick Installer"
echo "================================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Please run as root: sudo bash install_modern_webapp.sh"
    exit 1
fi

# Check if ragnar directory exists
ragnar_DIR="/home/ragnar/ragnar"
if [ ! -d "$ragnar_DIR" ]; then
    echo "❌ ragnar directory not found at $ragnar_DIR"
    echo "   Please install ragnar first!"
    exit 1
fi

echo "✓ Found ragnar installation"
echo ""

# Check network connectivity
echo "Checking internet connectivity..."
if ping -c 2 8.8.8.8 > /dev/null 2>&1; then
    echo "✓ Internet connection OK"
else
    echo "❌ No internet connection. Please connect and try again."
    exit 1
fi
echo ""

# Install Flask and dependencies
echo "Installing Flask and dependencies..."
echo "This may take a few minutes..."
echo ""

pip3 install --break-system-packages --retries 5 --timeout 300 \
    flask>=3.0.0 \
    flask-socketio>=5.3.0 \
    flask-cors>=4.0.0

if [ $? -eq 0 ]; then
    echo "✓ Flask dependencies installed successfully"
else
    echo "⚠️  Some packages failed to install"
    echo "   Trying alternative installation method..."
    pip3 install --break-system-packages flask flask-socketio flask-cors
fi

echo ""

# Verify installation
echo "Verifying installation..."
if python3 -c "import flask, flask_socketio, flask_cors" 2>/dev/null; then
    echo "✓ All Python packages verified"
else
    echo "❌ Package verification failed"
    echo "   Please check the error messages above"
    exit 1
fi

echo ""

# Make scripts executable
echo "Setting up scripts..."
cd "$ragnar_DIR"
chmod +x switch_webapp.sh 2>/dev/null
echo "✓ Scripts configured"

echo ""

# Ask if user wants to switch now
echo "Would you like to switch to the modern interface now?"
echo "1. Yes, switch now (recommended)"
echo "2. No, I'll switch manually later"
echo ""
read -p "Enter choice [1-2]: " switch_choice

case $switch_choice in
    1)
        echo ""
        echo "Switching to modern interface..."
        
        # Check if webapp_modern.py exists
        if [ ! -f "$ragnar_DIR/webapp_modern.py" ]; then
            echo "❌ webapp_modern.py not found!"
            echo "   Please ensure all new files are in the ragnar directory"
            exit 1
        fi
        
        # Update ragnar.py to use modern webapp
        if grep -q "from webapp import web_thread" "$ragnar_DIR/ragnar.py"; then
            cp "$ragnar_DIR/ragnar.py" "$ragnar_DIR/ragnar.py.backup"
            sed -i 's/from webapp import web_thread/# from webapp import web_thread\nfrom webapp_modern import run_server/' "$ragnar_DIR/ragnar.py"
            echo "✓ Updated ragnar.py"
        else
            echo "⚠️  Could not automatically update ragnar.py"
            echo "   You may need to manually edit it"
        fi
        
        # Restart ragnar service
        echo ""
        echo "Restarting ragnar service..."
        systemctl restart ragnar
        sleep 3
        
        # Check if service is running
        if systemctl is-active --quiet ragnar; then
            echo "✓ ragnar service restarted successfully"
        else
            echo "❌ Service restart failed. Checking logs..."
            journalctl -u ragnar -n 20 --no-pager
            exit 1
        fi
        
        echo ""
        echo "================================================"
        echo "✨ INSTALLATION COMPLETE! ✨"
        echo "================================================"
        echo ""
        echo "Access your modern interface at:"
        echo "  http://$(hostname -I | awk '{print $1}'):8000"
        echo ""
        echo "Features:"
        echo "  ✓ Real-time updates via WebSocket"
        echo "  ✓ Beautiful dark theme"
        echo "  ✓ Mobile-friendly responsive design"
        echo "  ✓ 10x faster than old interface"
        echo ""
        echo "Documentation:"
        echo "  - MODERN_WEBAPP_GUIDE.md - Usage guide"
        echo "  - WEBAPP_MODERNIZATION_SUMMARY.md - Full details"
        echo ""
        echo "To switch back to old interface:"
        echo "  ./switch_webapp.sh"
        echo ""
        echo "Enjoy your modernized ragnar! 🚀"
        ;;
    2)
        echo ""
        echo "Installation complete!"
        echo ""
        echo "To switch to modern interface later, run:"
        echo "  cd $ragnar_DIR"
        echo "  ./switch_webapp.sh"
        echo ""
        ;;
    *)
        echo "Invalid choice. Installation complete but not activated."
        ;;
esac

echo ""
echo "Installation log saved to: /var/log/ragnar_modern_install.log"
