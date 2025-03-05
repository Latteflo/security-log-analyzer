# Security Log Analyzer with AI Features

A Python tool for analyzing security logs, detecting anomalies, and extracting insights using AI/ML techniques.

## Features

- **Log Parsing**: Support for multiple log formats (Generic, Apache, Windows, SSH)
- **Anomaly Detection**: ML-based detection of unusual patterns in log data
- **NLP Analysis**: Extract security-related terms and patterns from log messages
- **Visualization**: Generate visual insights about security events
- **HTML Reporting**: Create comprehensive security reports with visualizations

## Requirements

- Python 3.7+
- Required libraries: 
  - pandas
  - numpy
  - matplotlib
  - seaborn
  - scikit-learn

## Installation

### Windows

1. Clone this repository
2. Run the Windows installer script:

```
install_windows.bat
```

### macOS

1. Clone this repository
2. Run the macOS installer script:

```bash
chmod +x install_macos.sh
./install_macos.sh
```

### Linux

1. Clone this repository
2. Run the Linux installer script:

```bash
chmod +x install_linux.sh
./install_linux.sh
```

### NixOS

1. Clone this repository
2. Enter the development environment:

```bash
nix-shell
```

This will automatically set up all required dependencies from the `shell.nix` file.

### Manual Installation (Any OS)

If the installer scripts don't work for your system:

1. Install Python 3.7 or higher
2. Install required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
# Windows
python main.py path\to\your\logfile.log

# macOS/Linux
python3 main.py path/to/your/logfile.log

# NixOS
nix-shell
python main.py path/to/your/logfile.log
```

### Options

- `--output` or `-o`: Specify output directory for reports (default: current directory)
- `--no-report`: Skip HTML report generation
- `--open`: Automatically open the HTML report after generation
- `--check-env`: Check your environment and installed dependencies
- `--list-logs`: Show common log locations for your operating system

### Examples

```bash
# Basic analysis with report generation
python main.py data/sample_logs.log

# Save report to specific directory and open it automatically
python main.py data/sample_logs.log --output reports --open

# Check your environment before running the tool
python main.py --check-env

# Find common log locations on your system
python main.py --list-logs
```

### Using with System Logs

#### Windows Event Logs

For Windows users, the tool can analyze exported event logs. To export Windows event logs:

1. Open Event Viewer
2. Select the log type (e.g., System, Security)
3. Right-click and select "Save All Events As..."
4. Save as Text format (.txt)
5. Run: `python main.py path\to\exported_log.txt`

#### Linux/macOS Logs

For Linux/macOS users, the tool can analyze standard system logs:

```bash
# Analyze authentication logs
sudo cp /var/log/auth.log ~/auth.log
sudo chmod 644 ~/auth.log
python3 main.py ~/auth.log

# Analyze secure logs
sudo cp /var/log/secure ~/secure.log
sudo chmod 644 ~/secure.log
python3 main.py ~/secure.log
```

## Project Structure

```
security-log-analyzer/
├── README.md
├── requirements.txt
├── shell.nix                   # NixOS environment configuration
├── install_windows.bat         # Windows installer script
├── install_macos.sh            # macOS installer script 
├── install_linux.sh            # Linux installer script
├── data/
│   └── sample_logs.log         # Sample log file for testing
├── src/
│   ├── __init__.py
│   ├── log_parser.py           # Parses different log formats
│   ├── anomaly_detector.py     # Detects unusual patterns using ML
│   ├── nlp_analyzer.py         # Analyzes log content using NLP
│   ├── visualizer.py           # Creates visualizations and reports
│   └── platform_utils.py       # OS-specific utilities
└── main.py                     # Main script
```

## AI/ML Features

- **Isolation Forest** for unsupervised anomaly detection
- **TF-IDF Vectorization** for log message analysis
- **K-Means Clustering** to identify common log patterns
- **Pattern Recognition** to detect security incidents

## Future Improvements

- Add support for more log formats
- Implement more advanced ML models for anomaly detection
- Add real-time monitoring capabilities
- Implement automated alert system
- Support for log correlation across multiple sources

## Authors

Latteflo
With assistance from Claude AI (Anthropic)
