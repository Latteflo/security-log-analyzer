import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from datetime import datetime, timedelta

class AnomalyDetector:
    """
    Class for detecting anomalies in security logs using machine learning
    """
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination=0.05, random_state=42)
        self.scaler = StandardScaler()
        self.vectorizer = TfidfVectorizer(max_features=100, stop_words='english')
        
    def detect_time_based_anomalies(self, df):
        """
        Detect anomalies based on unusual activity timing
        """
        if len(df) < 10:  # Need minimum data points
            return df.assign(time_anomaly=False)
            
        # Group by hour and count events
        hourly_counts = df.groupby(['hour']).size().reset_index(name='count')
        
        # Find hours with unusually high activity
        mean_count = hourly_counts['count'].mean()
        std_count = hourly_counts['count'].std()
        threshold = mean_count + 2 * std_count  # 2 standard deviations
        
        anomalous_hours = hourly_counts[hourly_counts['count'] > threshold]['hour'].tolist()
        
        # Mark anomalies in the original dataframe
        df['time_anomaly'] = df['hour'].isin(anomalous_hours)
        
        return df
    
    def detect_ml_anomalies(self, df):
        """
        Use Isolation Forest to detect anomalies in log patterns
        """
        if len(df) < 10:  # Need minimum data points
            return df.assign(ml_anomaly=False)
            
        # We need numeric features for ML
        numeric_features = df.select_dtypes(include=[np.number])
        
        if numeric_features.empty or numeric_features.shape[1] < 2:
            # Not enough numeric features, create some from text data
            if 'message' in df.columns:
                # Use TF-IDF to create features from messages
                message_features = self.vectorizer.fit_transform(df['message'].fillna(''))
                
                # Convert to DataFrame
                feature_names = [f'tfidf_{i}' for i in range(message_features.shape[1])]
                message_df = pd.DataFrame(message_features.toarray(), columns=feature_names)
                
                # Add hour as a feature if available
                if 'hour' in df.columns:
                    message_df['hour'] = df['hour']
                
                # Scale features
                X = self.scaler.fit_transform(message_df)
            else:
                # Not enough features to perform anomaly detection
                return df.assign(ml_anomaly=False)
        else:
            # Use available numeric features
            X = self.scaler.fit_transform(numeric_features)
        
        # Train and predict
        self.isolation_forest.fit(X)
        predictions = self.isolation_forest.predict(X)
        
        # In Isolation Forest, -1 indicates anomalies
        df['ml_anomaly'] = predictions == -1
        
        return df
    
    def detect_frequency_anomalies(self, df, time_window_minutes=5):
        """
        Detect anomalies based on unusual frequency of events
        """
        if 'timestamp' not in df.columns or len(df) < 10:
            return df.assign(frequency_anomaly=False)
            
        # Ensure timestamp is datetime
        if not pd.api.types.is_datetime64_dtype(df['timestamp']):
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            
        # Remove rows with invalid timestamps
        df = df.dropna(subset=['timestamp'])
        
        if len(df) < 10:  # Check again after potential dropna
            return df.assign(frequency_anomaly=False)
        
        # Sort by timestamp
        df = df.sort_values('timestamp')
        
        # Calculate time differences
        df['time_diff'] = df['timestamp'].diff().dt.total_seconds()
        
        # Fill NaN for first row
        df['time_diff'] = df['time_diff'].fillna(0)
        
        # Calculate event frequency per time window
        df['window'] = df['timestamp'].dt.floor(f'{time_window_minutes}min')
        window_counts = df.groupby('window').size().reset_index(name='event_count')
        
        # Find windows with unusually high activity
        mean_count = window_counts['event_count'].mean()
        std_count = window_counts['event_count'].std()
        
        # Use 3 standard deviations for anomaly threshold
        threshold = mean_count + 3 * std_count
        
        anomalous_windows = window_counts[window_counts['event_count'] > threshold]['window'].tolist()
        
        # Mark anomalies in the original dataframe
        df['frequency_anomaly'] = df['window'].isin(anomalous_windows)
        
        # Remove temporary columns
        df = df.drop(columns=['window'])
        
        return df
    
    def detect_source_anomalies(self, df):
        """
        Detect unusual activity from specific sources
        """
        if 'source' not in df.columns or len(df) < 10:
            return df.assign(source_anomaly=False)
            
        # Count events by source
        source_counts = df.groupby('source').size().reset_index(name='count')
        
        # Find sources with unusually high activity
        mean_count = source_counts['count'].mean()
        std_count = source_counts['count'].std()
        threshold = mean_count + 2.5 * std_count
        
        suspicious_sources = source_counts[source_counts['count'] > threshold]['source'].tolist()
        
        # Mark anomalies in the original dataframe
        df['source_anomaly'] = df['source'].isin(suspicious_sources)
        
        return df
    
    def combine_anomaly_scores(self, df):
        """
        Combine different anomaly detection methods into a single score
        """
        # Initialize anomaly score
        df['anomaly_score'] = 0
        
        # Add scores from different detection methods
        if 'time_anomaly' in df.columns:
            df['anomaly_score'] += df['time_anomaly'].astype(int)
            
        if 'ml_anomaly' in df.columns:
            df['anomaly_score'] += df['ml_anomaly'].astype(int) * 2  # Weight ML anomalies higher
            
        if 'frequency_anomaly' in df.columns:
            df['anomaly_score'] += df['frequency_anomaly'].astype(int) * 1.5
            
        if 'source_anomaly' in df.columns:
            df['anomaly_score'] += df['source_anomaly'].astype(int)
            
        # Also consider 'is_security_event' if it exists
        if 'is_security_event' in df.columns:
            df['anomaly_score'] += df['is_security_event'].astype(int) * 0.5
        
        # Mark as overall anomaly if score exceeds threshold
        df['is_anomaly'] = df['anomaly_score'] >= 1.5
        
        return df
    
    def analyze(self, df):
        """
        Run all anomaly detection methods and return results
        """
        # Run different anomaly detection methods
        df = self.detect_time_based_anomalies(df)
        df = self.detect_ml_anomalies(df)
        df = self.detect_frequency_anomalies(df)
        df = self.detect_source_anomalies(df)
        
        # Combine results
        df = self.combine_anomaly_scores(df)
        
        return df