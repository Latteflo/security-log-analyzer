#!/usr/bin/env python3
"""
Security Log Analyzer

A tool for analyzing security logs using AI/ML techniques to detect anomalies
and extract insights.

Author: Latteflo
"""
import os
import sys
import platform
import argparse
import logging
from datetime import datetime
from multiprocessing import Pool
import pandas as pd
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Import core modules with error handling
try:
    from src.log_parser import LogParser
    from src.anomaly_detector import AnomalyDetector
    from src.nlp_analyzer import NLPAnalyzer
    from src.visualizer import Visualizer
    from src.platform_utils import get_os_name, open_file_in_os, get_log_directories
    from src.elasticsearch_connector import ElasticsearchConnector
except ImportError as e:
    logger.error(f"Error importing modules: {e}. Ensure all dependencies are installed.")
    sys.exit(1)


def process_logs(log_file_path=None, output_dir=None, generate_report=True, open_report=False, 
                 use_elasticsearch=False, es_index=None, time_range=None, write_results=True):
    """Process security logs and analyze them."""
    logger.info(f"Operating system: {get_os_name()}")

    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Initialize components
    log_parser = LogParser()
    anomaly_detector = AnomalyDetector()
    nlp_analyzer = NLPAnalyzer()
    visualizer = Visualizer()
    es_connector = None
    
    if use_elasticsearch:
        es_connector = ElasticsearchConnector()
        if not es_connector.client:
            logger.error("Failed to connect to Elasticsearch. Check connection settings.")
            sys.exit(1)

    # Get logs from file or Elasticsearch
    logs_df = None
    if use_elasticsearch and es_connector:
        logger.info(f"Fetching logs from Elasticsearch index: {es_index}...")
        logs = es_connector.fetch_logs(index_pattern=es_index, time_range=time_range)
        if logs:
            logs_df = pd.DataFrame(logs)
        else:
            logger.error("Failed to retrieve logs from Elasticsearch.")
            sys.exit(1)
    elif log_file_path:
        logger.info(f"Processing log file: {log_file_path}")
        # Parse log file
        logger.info("Parsing logs...")
        try:
            with Pool(processes=4) as pool:  # Parallel processing
                logs_df = pool.apply(log_parser.parse_log_file, (log_file_path,))
        except Exception as e:
            logger.error(f"Error processing logs: {e}")
            sys.exit(1)
    else:
        logger.error("No log source specified. Provide either a log file or enable Elasticsearch.")
        sys.exit(1)

    if logs_df is None or logs_df.empty:
        logger.error("No valid log entries found. Exiting.")
        sys.exit(1)

    # Extract features
    logger.info("Extracting features...")
    logs_df = log_parser.extract_features(logs_df)
    
    # Prepare for ML analysis
    logs_df = log_parser.preprocess_for_ml(logs_df)

    # Detect anomalies
    logger.info("Detecting anomalies...")
    logs_df = anomaly_detector.analyze(logs_df)

    # Perform NLP analysis
    logger.info("Performing NLP analysis...")
    logs_df, nlp_summary = nlp_analyzer.analyze(logs_df)

    # Display summary
    total_logs = len(logs_df)
    anomaly_count = logs_df['is_anomaly'].sum() if 'is_anomaly' in logs_df.columns else 0

    logger.info("\n=== Analysis Summary ===")
    logger.info(f"Total log entries: {total_logs}")
    logger.info(f"Detected anomalies: {anomaly_count} ({(anomaly_count/total_logs)*100:.2f}%)")

    if 'security_term_count' in logs_df.columns:
        security_events = logs_df[logs_df['security_term_count'] > 0].shape[0]
        logger.info(f"Security-related events: {security_events} ({(security_events/total_logs)*100:.2f}%)")

    # Write results back to Elasticsearch if requested
    if use_elasticsearch and es_connector and write_results:
        logger.info("Writing analysis results back to Elasticsearch...")
        if es_connector.write_analysis_results(logs_df, index_name="security-analysis"):
            logger.info("Successfully wrote analysis results to Elasticsearch")
        else:
            logger.warning("Failed to write all analysis results to Elasticsearch")

    # Generate and save HTML report
    if generate_report:
        logger.info("\nGenerating HTML report...")
        html_report = visualizer.generate_html_report(logs_df, nlp_summary)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_filename = os.path.join(output_dir or '.', f'security_report_{timestamp}.html')

        try:
            with open(report_filename, 'w') as f:
                f.write(html_report)
            logger.info(f"Report saved to: {report_filename}")
        except IOError as e:
            logger.error(f"Error saving report: {e}")
            sys.exit(1)

        if open_report:
            logger.info("Opening report in default browser...")
            if open_file_in_os(report_filename):
                logger.info("Report opened successfully.")
            else:
                logger.warning(f"Could not open the report automatically. Please open {report_filename} manually.")

    return logs_df, nlp_summary


def check_environment():
    """Check and print environment information."""
    system = platform.system()
    release = platform.release()

    logger.info(f"Operating System: {system} {release}")
    logger.info(f"Python Version: {platform.python_version()}")

    dependencies = {
        "matplotlib": "Visualization",
        "sklearn": "Machine Learning",
        "seaborn": "Advanced Visualizations",
        "elasticsearch": "Elasticsearch Integration",
        "pandas": "Data Processing"
    }

    for lib, feature in dependencies.items():
        try:
            __import__(lib)
            logger.info(f"{lib.capitalize()} installed. ({feature} enabled)")
        except ImportError:
            logger.warning(f"{lib.capitalize()} not found. {feature} features may not work.")


def main():
    """Main function to handle CLI input."""
    parser = argparse.ArgumentParser(description="Security Log Analyzer")
    parser.add_argument("--log-file", help="Path to the log file to analyze")
    parser.add_argument("--output", "-o", help="Output directory for reports and visualizations")
    parser.add_argument("--no-report", action="store_true", help="Skip HTML report generation")
    parser.add_argument("--check-env", action="store_true", help="Check environment and dependencies")
    parser.add_argument("--open", action="store_true", help="Open the HTML report after generation")
    parser.add_argument("--list-logs", action="store_true", help="List common log locations for your OS")
    
    # Elasticsearch options
    parser.add_argument("--elasticsearch", "-es", action="store_true", help="Use Elasticsearch as data source")
    parser.add_argument("--es-index", default="filebeat-*", help="Elasticsearch index pattern to query")
    parser.add_argument("--time-from", help="Start time for log query (e.g., 'now-7d')")
    parser.add_argument("--time-to", default="now", help="End time for log query")
    parser.add_argument("--no-write", action="store_true", help="Don't write analysis results back to Elasticsearch")

    args = parser.parse_args()

    if args.list_logs:
        logger.info(f"Common log locations for {get_os_name()}:")
        for log_dir in get_log_directories():
            logger.info(f"  - {log_dir}")
        sys.exit(0)

    if args.check_env:
        check_environment()

    # Prepare time range if using Elasticsearch
    time_range = None
    if args.elasticsearch and (args.time_from or args.time_to):
        time_range = {}
        if args.time_from:
            time_range["gte"] = args.time_from
        if args.time_to:
            time_range["lte"] = args.time_to

    # Validate input
    if not args.elasticsearch and not args.log_file:
        parser.error("Either --log-file or --elasticsearch is required")
        sys.exit(1)

    if args.log_file and not os.path.isfile(os.path.abspath(args.log_file)):
        logger.error(f"Error: Log file not found: {args.log_file}")
        sys.exit(1)

    log_file_path = os.path.abspath(args.log_file) if args.log_file else None
    output_dir = os.path.abspath(args.output) if args.output else None

    process_logs(
        log_file_path=log_file_path, 
        output_dir=output_dir, 
        generate_report=not args.no_report, 
        open_report=args.open,
        use_elasticsearch=args.elasticsearch,
        es_index=args.es_index,
        time_range=time_range,
        write_results=not args.no_write
    )


if __name__ == "__main__":
    main()
    