#!/bin/bash

# Identity Hygiene Scanner Setup Script
# This script automates the setup process

set -e  # Exit on error

echo "🔐 Identity Hygiene Scanner - Setup"
echo "===================================="
echo ""

# Check Python version
echo "Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "❌ Error: Python 3.8 or higher is required (found $python_version)"
    exit 1
fi
echo "✅ Python version: $python_version"
echo ""

# Create virtual environment
echo "Creating virtual environment..."
if [ -d "venv" ]; then
    echo "⚠️  Virtual environment already exists. Skipping creation."
else
    python3 -m venv venv
    echo "✅ Virtual environment created"
fi
echo ""

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate || {
    echo "❌ Failed to activate virtual environment"
    exit 1
}
echo "✅ Virtual environment activated"
echo ""

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip --quiet
echo "✅ Pip upgraded"
echo ""

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt --quiet
echo "✅ Dependencies installed"
echo ""

# Generate secret key
echo "Generating secure secret key..."
secret_key=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
echo "export SECRET_KEY='$secret_key'" > .env
echo "✅ Secret key generated and saved to .env"
echo ""

# Run tests (optional)
read -p "Run tests? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Running tests..."
    python -m pytest tests/ -v
    echo ""
fi

# Final instructions
echo "✅ Setup complete!"
echo ""
echo "To start the application:"
echo "  1. Activate the virtual environment:"
echo "     source venv/bin/activate"
echo ""
echo "  2. Run the application:"
echo "     python run.py"
echo ""
echo "  3. Open your browser to:"
echo "     http://127.0.0.1:5000"
echo ""
echo "⚠️  For production deployment, see README.md"
echo ""
