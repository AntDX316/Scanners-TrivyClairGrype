#!/bin/bash
# Single command to run all vulnerability scanners using Docker
# No local installation required - just Docker!

echo "🚀 Running All Vulnerability Scanners with Docker"
echo "================================================"

# Check if Docker is running
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker first."
    echo "   Download from: https://www.docker.com/products/docker-desktop"
    exit 1
fi

# Get target from command line argument or default to current directory
TARGET=${1:-.}

echo "📦 Target: $TARGET"
echo "📁 Results will be saved to: results/"
echo ""

# Run the Docker-based scanner
python3 scan_docker.py "$TARGET"

echo ""
echo "✅ All scans completed!"
echo "📊 Check the results/ directory for detailed reports"
echo "🌐 HTML report should open automatically in your browser"
