#!/bin/bash

echo "Installing Security Log Analyzer dependencies for Linux..."

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is not installed! Please install Python 3.7 or higher."
    echo "You can use your distribution's package manager to install Python."
    echo "For example: sudo apt install python3 python3-pip (Ubuntu/Debian)"
    echo "Or: sudo dnf install python3 python3-pip (Fedora)"
    exit 1
fi

# Check Python version
python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
if (( $(echo "$python_version < 3.7" | bc -l) )); then
    echo "Python version $python_version detected. Please update to Python 3.7 or higher."
    exit 1
fi

# For NixOS users
if [ -f /etc/NIXOS ]; then
    echo "NixOS detected. Please use nix-shell instead:"
    echo "nix-shell"
    echo "Then run: python3 main.py data/sample_logs.log"
    exit 0
fi

# Install required packages
echo "Installing required Python packages..."
pip3 install -r requirements.txt

echo ""
echo "Installation complete!"
echo ""
echo "To run the Security Log Analyzer:"
echo "python3 main.py data/sample_logs.log"
echo ""

# Create a shortcut if desired
read -p "Would you like to create a desktop shortcut? (y/n): " create_shortcut
if [[ $create_shortcut == "y" || $create_shortcut == "Y" ]]; then
    python3 -c "from src.platform_utils import create_desktop_shortcut; create_desktop_shortcut('main.py')"
    echo "Desktop shortcut created."
fi