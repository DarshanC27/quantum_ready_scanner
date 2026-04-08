#!/bin/bash
# Quantum Ready — One-Click Deploy Script
# Run this on a fresh Ubuntu 22.04/24.04 VPS
# Usage: curl -sSL https://raw.githubusercontent.com/DarshanC27/quantum_ready_scanner/main/deploy.sh | bash

set -e

echo "🔮 Quantum Ready — Deploying PQC Scanner..."

# Install Docker if not present
if ! command -v docker &> /dev/null; then
    echo "📦 Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker $USER
fi

# Install Docker Compose if not present
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "📦 Installing Docker Compose..."
    sudo apt-get install -y docker-compose-plugin
fi

# Clone repo
echo "📥 Cloning repository..."
git clone https://github.com/DarshanC27/quantum_ready_scanner.git /opt/quantum-ready
cd /opt/quantum-ready

# Build and start
echo "🔨 Building Docker image (this takes 2-3 minutes)..."
docker compose up -d --build

echo ""
echo "✅ Quantum Ready is live!"
echo "   Backend API: http://$(curl -s ifconfig.me):5000"
echo "   Health check: http://$(curl -s ifconfig.me):5000/api/health"
echo ""
echo "Next: Point your frontend VITE_API_URL to this server's IP"
