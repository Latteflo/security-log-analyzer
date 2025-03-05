#!/usr/bin/env python3
"""
Security Log Analyzer

A tool for analyzing security logs using AI/ML techniques to detect anomalies
and extract insights.

Author: Florentina Simion
"""

import os
import sys
import platform
import argparse
import pandas as pd
from datetime import datetime

from src.log_parser import LogParser
from src.anomaly_detector import AnomalyDetector
from src.nlp_analyzer import NLPAnalyzer
from src.visualizer import Visualizer
from src.platform_utils import get_os_name, open_file_in_os, get_log_directories

def process_logs(log_file_path, output_dir=None, generate_report=True, open_report=False):
    """
    Process security logs and analyze them
    """
    print(f"Processing log file: {log_file_path}")
    print(f"Operating system: {get_os_name()}")
    
    # Create output directory if it doesn't exist
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Initialize components
    log_parser = LogParser()
    anomaly_detector = AnomalyDetector()
    nlp_analyzer = NLPAnalyzer()
    visualizer = Visualizer()
    
    # Process log file
    print("Parsing logs...")
    logs_df = log_parser.parse_log_file(log_file_path)
    
    # Extract features
    print("Extracting features...")
    logs_df = log_parser.extract_features(logs_df)
    
    # Prepare for ML analysis
    logs_df = log_parser.preprocess_for_ml(logs_df)
    
    # Detect anomalies
    print("Detecting anomalies...")
    logs_df = anomaly_detector.analyze(logs_df)
    
    # Perform NLP analysis
    print("Performing NLP analysis...")
    logs_df, nlp_summary = nlp_analyzer.analyze(logs_df)
    
    # Display summary information
    total_logs = len(logs_df)
    anomaly_count = logs_df['is_anomaly'].sum() if 'is_anomaly' in logs_df.columns else 0
    
    print("\n=== Analysis Summary ===")
    print(f"Total log entries: {total_logs}")
    print(f"Detected anomalies: {anomaly_count} ({(anomaly_count/total_logs)*100:.2f}%)")
    
    if 'security_term_count' in logs_df.columns:
        security_events = logs_df[logs_df['security_term_count'] > 0].shape[0]
        print(f"Security-related events: {security_events} ({(security_events/total_logs)*100:.2f}%)")
    
    # Generate HTML report
    if generate_report:
        print("\nGenerating HTML report...")
        html_report = visualizer.generate_html_report(logs_df, nlp_summary)
        
        # Save report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_filename = os.path.join(output_dir or '.', f'security_report_{timestamp}.html')
        
        with open(report_filename, 'w') as f:
            f.write(html_report)
            
        print(f"Report saved to: {report_filename}")
        
        # Open the report automatically if requested
        if open_report:
            print("Opening report in default browser...")
            if open_file_in_os(report_filename):
                print("Report opened successfully.")
            else:
                print(f"Could not open the report automatically. Please open {report_filename} manually.")
    
    # Return the processed dataframe and summary for further analysis
    return logs_df, nlp_summary

def check_environment():
    """Check and print environment information"""
    system = platform.system()
    release = platform.release()
    
    print(f"Operating System: {system} {release}")
    print(f"Python Version: {platform.python_version()}")
    
    # Check for required libraries
    try:
        import matplotlib
        print(f"Matplotlib Version: {matplotlib.__version__}")
    except ImportError:
        print("Warning: Matplotlib not found. Visualization will not work.")
    
    try:
        import sklearn
        print(f"Scikit-learn Version: {sklearn.__version__}")
    except ImportError:
        print("Warning: Scikit-learn not found. Machine learning features will not work.")
    
    try:
        import seaborn
        print(f"Seaborn Version: {seaborn.__version__}")
    except ImportError:
        print("Warning: Seaborn not found. Some visualizations may be limited.")
    
    print("Environment check completed.\n")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Security Log Analyzer')
    parser.add_argument('log_file', help='Path to the log file to analyze')
    parser.add_argument('--output', '-o', help='Output directory for reports and visualizations')
    parser.add_argument('--no-report', action='store_true', help='Skip HTML report generation')
    parser.add_argument('--check-env', action='store_true', help='Check environment and dependencies')
    parser.add_argument('--open', action='store_true', help='Open the HTML report after generation')
    parser.add_argument('--list-logs', action='store_true', help='List common log locations for your operating system')
    
    args = parser.parse_args()
    
    # If requested, list common log locations for this OS
    if args.list_logs:
        print(f"Common log locations for {get_os_name()}:")
        for log_dir in get_log_directories():
            print(f"  - {log_dir}")
        sys.exit(0)
    
    # Check environment if requested
    if args.check_env:
        check_environment()
    
    # Use cross-platform path handling
    log_file_path = os.path.abspath(args.log_file)
    output_dir = os.path.abspath(args.output) if args.output else None
    
    # Check if file exists
    if not os.path.isfile(log_file_path):
        print(f"Error: Log file not found: {log_file_path}")
        sys.exit(1)
    
    # Process logs
    process_logs(log_file_path, output_dir, not args.no_report, args.open)

if __name__ == '__main__':
    main()