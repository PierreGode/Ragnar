#!/bin/bash
# Fix nmap sudo access for Ragnar
# This script creates a sudoers file to allow the ragnar user to run nmap without password

echo "Creating sudoers configuration for ragnar user to run nmap..."
echo 'ragnar ALL=(ALL) NOPASSWD: /usr/bin/nmap' | sudo tee /etc/sudoers.d/ragnar-nmap
sudo chmod 0440 /etc/sudoers.d/ragnar-nmap

echo "Verifying sudoers configuration..."
sudo cat /etc/sudoers.d/ragnar-nmap

echo ""
echo "Testing nmap sudo access..."
sudo nmap --version | head -3

echo ""
echo "✅ Done! Ragnar can now run nmap with sudo without password."
echo "Restart Ragnar service: sudo systemctl restart ragnar"
