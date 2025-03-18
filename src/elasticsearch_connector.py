#!/usr/bin/env python3
"""
Elasticsearch connector for Security Log Analyzer

Handles interactions with Elasticsearch for reading and writing security data.
"""
import os
import json
import logging
from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

class ElasticsearchConnector:
    """Handles all interactions with Elasticsearch."""
    
    def __init__(self, hosts=None, username=None, password=None, use_ssl=True):
        """Initialize Elasticsearch connection."""
        self.hosts = hosts or ["http://localhost:9200"]
        self.username = username or os.getenv("ES_USERNAME", "elastic")
        self.password = password or os.getenv("ES_PASSWORD", "changeme")
        self.use_ssl = use_ssl
        self.client = None
        self.connect()
        
    def connect(self):
        """Establish connection to Elasticsearch."""
        try:
            self.client = Elasticsearch(
                self.hosts,
                basic_auth=(self.username, self.password),
                verify_certs=self.use_ssl
            )
            if self.client.ping():
                logger.info(f"Connected to Elasticsearch cluster: {self.client.info()['cluster_name']}")
            else:
                logger.error("Failed to connect to Elasticsearch")
                self.client = None
        except Exception as e:
            logger.error(f"Error connecting to Elasticsearch: {e}")
            self.client = None
    
    def fetch_logs(self, index_pattern="filebeat-*", time_range=None, query=None, size=10000):
        """Fetch logs from Elasticsearch."""
        if not self.client:
            logger.error("Not connected to Elasticsearch")
            return None
            
        try:
            # Default query matches all documents
            search_query = {"match_all": {}}
            
            # Build the query
            body = {
                "size": size,
                "query": {
                    "bool": {
                        "must": [search_query]
                    }
                },
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
            
            # Add time range if provided
            if time_range:
                body["query"]["bool"]["filter"] = [
                    {
                        "range": {
                            "@timestamp": time_range
                        }
                    }
                ]
            
            # Add custom query if provided
            if query:
                body["query"]["bool"]["must"] = [query]
            
            # Execute search
            response = self.client.search(index=index_pattern, body=body)
            
            # Convert to DataFrame-friendly format
            hits = response["hits"]["hits"]
            logs = []
            for hit in hits:
                source = hit["_source"]
                # Add the Elasticsearch document ID
                source["_id"] = hit["_id"]
                logs.append(source)
                
            logger.info(f"Retrieved {len(logs)} logs from Elasticsearch")
            return logs
            
        except Exception as e:
            logger.error(f"Error fetching logs from Elasticsearch: {e}")
            return None
    
    def write_analysis_results(self, df, index_name="security-analysis"):
        """Write analysis results back to Elasticsearch."""
        if not self.client:
            logger.error("Not connected to Elasticsearch")
            return False
            
        try:
            # Create index with appropriate mappings if it doesn't exist
            if not self.client.indices.exists(index=index_name):
                mappings = {
                    "mappings": {
                        "properties": {
                            "@timestamp": {"type": "date"},
                            "message": {"type": "text"},
                            "log_level": {"type": "keyword"},
                            "source_ip": {"type": "ip"},
                            "is_anomaly": {"type": "boolean"},
                            "anomaly_score": {"type": "float"},
                            "security_term_count": {"type": "integer"},
                            "sentiment_score": {"type": "float"},
                            "analysis_timestamp": {"type": "date"}
                        }
                    }
                }
                self.client.indices.create(index=index_name, body=mappings)
                logger.info(f"Created index {index_name} with security analysis mappings")
            
            # Prepare documents for bulk indexing
            actions = []
            for _, row in df.iterrows():
                doc = row.to_dict()
                # Add analysis timestamp
                doc["analysis_timestamp"] = datetime.now().isoformat()
                
                # Handle non-serializable objects
                for key, value in doc.items():
                    if not isinstance(value, (str, int, float, bool, list, dict)) and value is not None:
                        doc[key] = str(value)
                
                action = {
                    "_index": index_name,
                    "_source": doc
                }
                
                # Add document ID if available
                if "_id" in doc:
                    action["_id"] = doc["_id"]
                    
                actions.append(action)
            
            # Perform bulk indexing
            success, failed = bulk(self.client, actions, stats_only=True)
            logger.info(f"Indexed {success} documents to {index_name}, {failed} failed")
            return success > 0
            
        except Exception as e:
            logger.error(f"Error writing analysis results to Elasticsearch: {e}")
            return False