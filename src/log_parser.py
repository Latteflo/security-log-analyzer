import re
import pandas as pd
from datetime import datetime

class LogParser:
    """
    Class for parsing and preprocessing security logs
    """
    def __init__(self):
        # Common log patterns for different security log formats
        self.patterns = {
            'generic': r'(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s+(\w+)\s+\[([^\]]+)\]\s+(.*)',
            'apache': r'(\S+) (\S+) (\S+) \[([^:]+):(\d+:\d+:\d+) ([^\]]+)\] "(\S+) (.*?) (\S+)" (\d+) (\S+)',
            'windows': r'(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s+(\w+)\s+(\w+)\s+(.*)',
            'ssh': r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]:\s+(.*)'
        }
    
    def detect_log_type(self, log_line):
        """Determine the type of log based on its pattern"""
        for log_type, pattern in self.patterns.items():
            if re.match(pattern, log_line):
                return log_type
        return "unknown"
    
    def parse_log_file(self, file_path):
        """
        Parse a log file and convert it to a pandas DataFrame
        """
        log_data = []
        
        with open(file_path, 'r') as f:
            for line in f:
                log_type = self.detect_log_type(line.strip())
                
                if log_type == "unknown":
                    # Store unparsed lines with minimal info
                    log_data.append({
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'log_type': 'unknown',
                        'severity': 'INFO',
                        'message': line.strip(),
                        'source': 'unknown'
                    })
                    continue
                
                # Parse according to the detected type
                if log_type == 'generic':
                    match = re.match(self.patterns[log_type], line.strip())
                    if match:
                        timestamp, severity, source, message = match.groups()
                        log_data.append({
                            'timestamp': timestamp,
                            'log_type': log_type,
                            'severity': severity,
                            'source': source,
                            'message': message
                        })
                
                elif log_type == 'apache':
                    match = re.match(self.patterns[log_type], line.strip())
                    if match:
                        ip, ident, user, date, time, zone, method, path, protocol, status, size = match.groups()
                        log_data.append({
                            'timestamp': f"{date} {time}",
                            'log_type': log_type,
                            'severity': 'INFO',
                            'source': ip,
                            'message': f"{method} {path} {protocol} {status}",
                            'status_code': status,
                            'request_path': path
                        })
                
                elif log_type == 'windows':
                    match = re.match(self.patterns[log_type], line.strip())
                    if match:
                        timestamp, severity, source, message = match.groups()
                        log_data.append({
                            'timestamp': timestamp,
                            'log_type': log_type, 
                            'severity': severity,
                            'source': source,
                            'message': message
                        })
                        
                elif log_type == 'ssh':
                    match = re.match(self.patterns[log_type], line.strip())
                    if match:
                        timestamp, message = match.groups()
                        # Determine if this is a failed login attempt
                        is_failed = "Failed password" in message or "Invalid user" in message
                        severity = "WARNING" if is_failed else "INFO"
                        
                        # Extract username and IP if available
                        user_match = re.search(r'user (\S+)', message)
                        ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', message)
                        
                        username = user_match.group(1) if user_match else "unknown"
                        source_ip = ip_match.group(1) if ip_match else "unknown"
                        
                        log_data.append({
                            'timestamp': timestamp,
                            'log_type': log_type,
                            'severity': severity,
                            'source': source_ip,
                            'username': username,
                            'message': message,
                            'failed_attempt': is_failed
                        })
        
        # Convert to DataFrame
        return pd.DataFrame(log_data)
    
    def extract_features(self, df):
        """
        Extract relevant features from the log data for analysis
        """
        # Convert timestamp to datetime
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        
        # Extract hour of day
        df['hour'] = df['timestamp'].dt.hour
        
        # Extract day of week
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        
        # Flag potential security events
        df['is_security_event'] = df['message'].str.contains(
            'fail|error|warn|attack|invalid|compromise|threat|attempt|denied|violation|suspicious',
            case=False
        )
        
        return df
    
    def preprocess_for_ml(self, df):
        """
        Prepare the log data for machine learning analysis
        """
        # Filter to include only relevant columns
        ml_df = df[['timestamp', 'log_type', 'severity', 'message', 'source', 'is_security_event', 'hour', 'day_of_week']]
        
        # Create one-hot encoding for categorical variables
        ml_df = pd.get_dummies(ml_df, columns=['log_type', 'severity'])
        
        # Fill any missing values
        ml_df = ml_df.fillna('unknown')
        
        return ml_df