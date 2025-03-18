# Log-Analyzer: Enhanced SIEM with AI/ML Capabilities

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Elasticsearch](https://img.shields.io/badge/elasticsearch-8.10.4-yellow)
![Kibana](https://img.shields.io/badge/kibana-8.10.4-purple)

A comprehensive Security Information and Event Management (SIEM) solution enhanced with AI/ML-powered log analysis, offering advanced anomaly detection and natural language processing capabilities.

## Overview

This project combines the powerful Elastic Stack (Elasticsearch, Kibana, Filebeat) with a custom Python-based Security Log Analyzer to create a complete security monitoring solution. The system collects, stores, and visualizes security logs while leveraging machine learning and NLP techniques to uncover hidden patterns, detect anomalies, and extract actionable insights.

![Architecture Overview](https://via.placeholder.com/800x400.png?text=Enhanced+SIEM+Architecture)

## Features

### Core SIEM Capabilities
- **Log Collection**: Capture logs from multiple sources with Filebeat
- **Centralized Storage**: Index and store security data in Elasticsearch
- **Real-time Visualization**: Monitor security events through Kibana dashboards
- **Time-series Analysis**: Track security patterns over extended periods
- **Docker-based Deployment**: Easy setup with containerized components

### Enhanced Analytics
- **ML-based Anomaly Detection**: Identify suspicious patterns and outliers
- **NLP Analysis**: Extract insights from log message content
- **Automated Security Reporting**: Generate comprehensive security reports
- **Bi-directional Integration**: Read from and write enriched data back to Elasticsearch
- **Custom Dashboards**: Visualize ML/NLP findings in Kibana

## Project Structure

```
log-analyzer/
├── config/                  # Configuration files
│   ├── filebeat/            # Filebeat configuration
│   │   └── filebeat.yml     # Filebeat settings
│   └── logstash/            # Logstash configuration (optional)
│       └── pipeline/        # Logstash processing pipelines
│           └── main.conf    # Main pipeline configuration
├── data/                    # Log data directory
│   └── sample.log           # Sample security logs for testing
├── scripts/                 # Deployment and setup scripts
│   ├── setup/               # Setup scripts
│   │   ├── init.sh          # Initialization script
│   │   ├── install_linux.sh # Linux installation script
│   │   ├── install_macos.sh # MacOS installation script
│   │   └── install_windows.bat # Windows installation script
├── src/                     # Python source code
│   ├── anomaly_detector.py  # ML-based anomaly detection
│   ├── elasticsearch_connector.py # Elasticsearch integration
│   ├── log_parser.py        # Log parsing utilities
│   ├── main.py              # Main Python application
│   ├── nlp_analyzer.py      # Natural language processing
│   ├── platform_utils.py    # Platform-specific utilities
│   └── visualizer.py        # Visualization and reporting
├── .env                     # Environment variables (not committed)
├── docker-compose.core.yml  # Docker Compose configuration
├── README.md                # Project documentation
├── requirements.txt         # Python dependencies
└── shell.nix               # Nix environment configuration
```

## Prerequisites

- Docker and Docker Compose
- Python 3.8 or higher
- 4GB RAM minimum (8GB recommended)
- 20GB free disk space

## Quick Start

### Setting up the SIEM Stack

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/log-analyzer.git
   cd log-analyzer
   ```

2. Create a `.env` file (optional):
   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

3. Start the core SIEM stack:
   ```bash
   docker-compose -f docker-compose.core.yml up -d
   ```

4. Access Kibana at [http://localhost:5601](http://localhost:5601)
   - Default credentials: elastic / changeme

### Setting up the Python Analyzer

1. Create a Python virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up Elasticsearch credentials:
   Create or edit the `.env` file:
   ```
   ES_USERNAME=elastic
   ES_PASSWORD=changeme
   ES_HOSTS=http://localhost:9200
   ```

## Usage

### Basic SIEM Usage

1. **Ingest Logs**: Place log files in the `data/` directory
2. **Create a Data View in Kibana**:
   - Go to Stack Management > Data Views
   - Create a view with pattern `filebeat-*`
   - Set the timestamp field to `@timestamp`
3. **View Logs in Discover**:
   - Navigate to Discover
   - Select your data view
   - Adjust the time range to see your data
4. **Create Dashboards**:
   - Go to Dashboard > Create dashboard
   - Add visualizations for security events

### Using the Python Analyzer

#### Analyze Local Log Files

```bash
python src/main.py --log-file data/sample.log --output ./reports --open
```

#### Analyze Data from Your SIEM

```bash
# Analyze last 7 days of logs
python src/main.py --elasticsearch --es-index "filebeat-*" --time-from "now-7d"

# Analyze a specific date range
python src/main.py --elasticsearch --es-index "filebeat-*" --time-from "2023-01-01" --time-to "2025-03-31"
```

#### Create Enhanced Kibana Dashboards

After running the analyzer with `--elasticsearch` flag:

1. In Kibana, create a new data view with pattern `security-analysis*`
2. Set the timestamp field to `analysis_timestamp`
3. Create visualizations for:
   - Anomaly scores over time
   - Security event distribution
   - NLP sentiment analysis
   - High-risk events table

## Key Components

### Filebeat

Filebeat is configured to collect logs from the `data/` directory and send them to Elasticsearch. The configuration is in `config/filebeat/filebeat.yml`.

### Elasticsearch

Elasticsearch stores and indexes all security events and analysis results. It runs with security features disabled in development mode.

### Kibana

Kibana provides the visualization interface for both raw security data and enriched analysis results.

### Python Security Analyzer

The Python analyzer enhances the SIEM with:

- **Anomaly Detection**: Identifies unusual patterns in log data
- **NLP Analysis**: Extracts insights from log messages
- **Elasticsearch Integration**: Reads from and writes to your SIEM
- **Reporting**: Generates HTML reports with interactive visualizations

## Customization

### Adding Custom Log Sources

1. Modify `config/filebeat/filebeat.yml` to include additional log sources
2. Update the Python log parser in `src/log_parser.py` to handle new log formats

### Creating Custom Detection Rules

1. Modify `src/anomaly_detector.py` to implement custom detection algorithms
2. Update `src/nlp_analyzer.py` to extract additional security insights

### Extending the SIEM

1. Add additional Elastic Stack components like Logstash for complex data transformation
2. Integrate with additional data sources using Beats family collectors

## Security Considerations

This project is configured for development and testing. For production deployment:

1. Enable Elasticsearch security features
2. Configure proper authentication and TLS encryption
3. Implement proper data retention policies
4. Consider network segmentation for the SIEM components


## Acknowledgements

- The Elastic Stack team for Elasticsearch, Kibana, and Filebeat
- The open-source security community for tools and techniques
- Contributors to the machine learning and NLP libraries used in this project

---

### Authors

Latteflo With assistance from Claude AI (Anthropic)