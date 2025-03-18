#!/bin/bash
# SIEM Project Initialization Script

set -e

echo "Setting up SIEM project environment..."

# Create directory structure
mkdir -p config/filebeat
mkdir -p config/logstash/pipeline
mkdir -p config/logstash/config
mkdir -p data
mkdir -p logs
mkdir -p scripts/setup
mkdir -p scripts/testing

# Create sample log file if it doesn't exist
if [ ! -f data/sample.log ]; then
  echo "Creating sample log data..."
  cat > data/sample.log << EOF
2023-11-15T10:00:00 INFO  Sample log entry for SIEM testing
2023-11-15T10:01:00 WARN  Suspicious login attempt from 192.168.1.100
2023-11-15T10:02:00 ERROR Failed login for user admin from 192.168.1.100
2023-11-15T10:03:00 INFO  User john logged in successfully
2023-11-15T10:04:00 WARN  Multiple failed login attempts detected
2023-11-15T10:05:00 ERROR Possible brute force attack from 192.168.1.100
EOF
fi

# Create Filebeat configuration
cat > config/filebeat/filebeat.yml << EOF
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /logs/*.log
  fields:
    log_type: security_event
  fields_under_root: true
  tags: ["security", "siem"]

filebeat.config.modules:
  path: \${path.config}/modules.d/*.yml
  reload.enabled: false

setup.template.settings:
  index.number_of_shards: 1
  index.number_of_replicas: 0

setup.kibana:
  host: "kibana:5601"

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  indices:
    - index: "filebeat-%{[agent.version]}-%{+yyyy.MM.dd}"

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644
EOF

echo "Setup complete! Start your SIEM with: docker-compose -f docker-compose.core.yml up -d"