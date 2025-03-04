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

1. Clone this repository
2. Install required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python main.py path/to/your/logfile.log
```

### Options

- `--output` or `-o`: Specify output directory for reports (default: current directory)
- `--no-report`: Skip HTML report generation

### Example

```bash
python main.py data/sample_logs.log --output reports
```

## Project Structure

```
security-log-analyzer/
├── README.md
├── requirements.txt
├── data/
│   └── sample_logs.log
├── src/
│   ├── __init__.py
│   ├── log_parser.py       # Parses different log formats
│   ├── anomaly_detector.py # Detects unusual patterns using ML
│   ├── nlp_analyzer.py     # Analyzes log content using NLP
│   └── visualizer.py       # Creates visualizations and reports
└── main.py                 # Main script
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

## License

MIT

## Author

Latteflo