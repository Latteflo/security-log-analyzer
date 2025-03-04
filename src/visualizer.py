import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.colors import LinearSegmentedColormap
import matplotlib.dates as mdates
from io import BytesIO
import base64

class Visualizer:
    """
    Class for visualizing security log analysis results
    """
    def __init__(self):
        # Set up the color scheme
        plt.style.use('seaborn-v0_8-darkgrid')
        self.colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', 
                       '#8c564b', '#e377c2', '#7f7f7f', '#bcbd22', '#17becf']
        self.anomaly_cmap = LinearSegmentedColormap.from_list(
            'anomaly_cmap', ['#4575b4', '#ffffbf', '#d73027']
        )
        
    def plot_time_distribution(self, df):
        """
        Plot the distribution of events over time
        """
        if 'timestamp' not in df.columns:
            return None
            
        # Ensure timestamp is datetime
        if not pd.api.types.is_datetime64_dtype(df['timestamp']):
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            
        # Remove rows with invalid timestamps
        df = df.dropna(subset=['timestamp'])
        
        if len(df) == 0:
            return None
            
        # Create the figure
        plt.figure(figsize=(12, 6))
        
        # Group by hour and count
        hourly_counts = df.groupby(df['timestamp'].dt.floor('H')).size()
        
        # Plot normal events in blue
        if 'is_anomaly' in df.columns:
            normal_df = df[~df['is_anomaly']]
            anomaly_df = df[df['is_anomaly']]
            
            # Group by hour
            normal_counts = normal_df.groupby(normal_df['timestamp'].dt.floor('H')).size()
            anomaly_counts = anomaly_df.groupby(anomaly_df['timestamp'].dt.floor('H')).size()
            
            plt.plot(normal_counts.index, normal_counts.values, color='#4575b4', 
                     linewidth=2, marker='o', markersize=4, label='Normal Events')
                     
            # Plot anomalies in red with different marker
            if not anomaly_counts.empty:
                plt.scatter(anomaly_counts.index, anomaly_counts.values, color='#d73027', 
                          marker='x', s=100, linewidth=2, label='Anomalies')
        else:
            # Just plot all events
            plt.plot(hourly_counts.index, hourly_counts.values, color='#4575b4', 
                     linewidth=2, marker='o', markersize=4)
        
        # Format the x-axis to show dates nicely
        plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%m-%d %H:%M'))
        plt.gca().xaxis.set_major_locator(mdates.AutoDateLocator())
        
        plt.title('Security Events Over Time', fontsize=14)
        plt.xlabel('Time', fontsize=12)
        plt.ylabel('Number of Events', fontsize=12)
        plt.xticks(rotation=45)
        plt.tight_layout()
        
        if 'is_anomaly' in df.columns:
            plt.legend()
            
        # Convert plot to base64 for HTML display
        img = BytesIO()
        plt.savefig(img, format='png')
        plt.close()
        img.seek(0)
        plot_url = base64.b64encode(img.getvalue()).decode('utf8')
        
        return plot_url
        
    def plot_severity_distribution(self, df):
        """
        Plot the distribution of events by severity
        """
        if 'severity' not in df.columns:
            return None
            
        # Create the figure
        plt.figure(figsize=(10, 6))
        
        # Count by severity
        severity_counts = df['severity'].value_counts()
        
        # Set order of severity levels if present
        severity_order = ['EMERGENCY', 'ALERT', 'CRITICAL', 'ERROR', 
                         'WARNING', 'NOTICE', 'INFO', 'DEBUG']
        
        # Filter to only include existing levels in our data
        ordered_severities = [s for s in severity_order if s in severity_counts.index]
        
        # If we have ordered severities, use those, otherwise use the counts directly
        if ordered_severities:
            severity_counts = severity_counts.reindex(ordered_severities)
        
        # Create color map based on severity
        colors = plt.cm.YlOrRd(np.linspace(0.2, 0.8, len(severity_counts)))
        
        # Create bar chart
        bars = plt.bar(severity_counts.index, severity_counts.values, color=colors)
        
        plt.title('Distribution of Events by Severity', fontsize=14)
        plt.xlabel('Severity Level', fontsize=12)
        plt.ylabel('Number of Events', fontsize=12)
        plt.xticks(rotation=45)
        
        # Add count labels on top of bars
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                    f'{int(height)}', ha='center', va='bottom')
        
        plt.tight_layout()
        
        # Convert plot to base64 for HTML display
        img = BytesIO()
        plt.savefig(img, format='png')
        plt.close()
        img.seek(0)
        plot_url = base64.b64encode(img.getvalue()).decode('utf8')
        
        return plot_url
        
    def plot_anomaly_distribution(self, df):
        """
        Plot the distribution of anomalies by type
        """
        if 'is_anomaly' not in df.columns:
            return None
            
        # Create the figure
        plt.figure(figsize=(10, 6))
        
        # Prepare data for plotting
        anomaly_types = []
        anomaly_counts = []
        
        # Check each type of anomaly
        for col in ['time_anomaly', 'ml_anomaly', 'frequency_anomaly', 'source_anomaly']:
            if col in df.columns:
                anomaly_types.append(col.replace('_anomaly', '').title())
                anomaly_counts.append(df[col].sum())
                
        # Create bar chart
        colors = plt.cm.Blues(np.linspace(0.4, 0.8, len(anomaly_types)))
        bars = plt.bar(anomaly_types, anomaly_counts, color=colors)
        
        plt.title('Distribution of Anomalies by Type', fontsize=14)
        plt.xlabel('Anomaly Type', fontsize=12)
        plt.ylabel('Number of Events', fontsize=12)
        
        # Add count labels on top of bars
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                    f'{int(height)}', ha='center', va='bottom')
        
        plt.tight_layout()
        
        # Convert plot to base64 for HTML display
        img = BytesIO()
        plt.savefig(img, format='png')
        plt.close()
        img.seek(0)
        plot_url = base64.b64encode(img.getvalue()).decode('utf8')
        
        return plot_url
        
    def plot_security_terms(self, df):
        """
        Plot a bar chart of the most common security terms
        """
        if 'security_terms' not in df.columns:
            return None
            
        # Flatten the list of security terms
        all_terms = [term for terms_list in df['security_terms'] for term in terms_list]
        
        if not all_terms:
            return None
            
        # Count term occurrences
        term_counter = pd.Series(all_terms).value_counts()
        
        # Take top 10 terms
        top_terms = term_counter.head(10)
        
        # Create the figure
        plt.figure(figsize=(12, 6))
        
        # Create horizontal bar chart
        bars = plt.barh(top_terms.index, top_terms.values, color=plt.cm.viridis(np.linspace(0.2, 0.8, len(top_terms))))
        
        plt.title('Most Common Security Terms', fontsize=14)
        plt.xlabel('Occurrences', fontsize=12)
        plt.ylabel('Term', fontsize=12)
        
        # Add count labels
        for bar in bars:
            width = bar.get_width()
            plt.text(width + 0.5, bar.get_y() + bar.get_height()/2.,
                    f'{int(width)}', ha='left', va='center')
        
        plt.tight_layout()
        
        # Convert plot to base64 for HTML display
        img = BytesIO()
        plt.savefig(img, format='png')
        plt.close()
        img.seek(0)
        plot_url = base64.b64encode(img.getvalue()).decode('utf8')
        
        return plot_url
        
    def plot_source_activity(self, df):
        """
        Plot a heatmap of activity by source and hour
        """
        if 'source' not in df.columns or 'timestamp' not in df.columns:
            return None
            
        # Ensure timestamp is datetime
        if not pd.api.types.is_datetime64_dtype(df['timestamp']):
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            
        # Remove rows with invalid timestamps
        df = df.dropna(subset=['timestamp'])
        
        if len(df) == 0:
            return None
            
        # Extract hour
        df['hour'] = df['timestamp'].dt.hour
        
        # Get top 10 sources by event count
        top_sources = df['source'].value_counts().head(10).index.tolist()
        
        # Filter to include only top sources
        filtered_df = df[df['source'].isin(top_sources)]
        
        # Create pivot table
        pivot_data = pd.pivot_table(
            filtered_df, 
            values='message',
            index='source',
            columns='hour',
            aggfunc='count',
            fill_value=0
        )
        
        # Create the figure
        plt.figure(figsize=(14, 8))
        
        # Create heatmap
        sns.heatmap(pivot_data, cmap='YlGnBu', annot=True, fmt='d', linewidths=.5)
        
        plt.title('Activity by Source and Hour of Day', fontsize=14)
        plt.ylabel('Source', fontsize=12)
        plt.xlabel('Hour of Day', fontsize=12)
        
        plt.tight_layout()
        
        # Convert plot to base64 for HTML display
        img = BytesIO()
        plt.savefig(img, format='png')
        plt.close()
        img.seek(0)
        plot_url = base64.b64encode(img.getvalue()).decode('utf8')
        
        return plot_url
        
    def generate_html_report(self, df, nlp_summary):
        """
        Generate an HTML report with visualizations
        """
        # Generate plots
        time_plot = self.plot_time_distribution(df)
        severity_plot = self.plot_severity_distribution(df)
        anomaly_plot = self.plot_anomaly_distribution(df)
        terms_plot = self.plot_security_terms(df)
        source_plot = self.plot_source_activity(df)
        
        # Start building HTML
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Log Analysis Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .container { max-width: 1200px; margin: 0 auto; }
                .header { background-color: #2c3e50; color: white; padding: 20px; margin-bottom: 20px; }
                .section { margin-bottom: 30px; padding: 20px; background-color: #f5f5f5; border-radius: 5px; }
                .plot { margin: 20px 0; text-align: center; }
                table { width: 100%; border-collapse: collapse; }
                th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
                th { background-color: #f2f2f2; }
                .anomaly { background-color: #ffecec; }
                h1, h2, h3 { margin-top: 0; }
                .summary-box { background-color: #e8f4fc; padding: 15px; border-radius: 5px; margin-top: 20px; }
                .stats { display: flex; flex-wrap: wrap; }
                .stat-item { flex: 1; min-width: 200px; margin: 10px; padding: 15px; background-color: white; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Security Log Analysis Report</h1>
                    <p>Generated on: """ + pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
                </div>
        """
        
        # Add summary section
        html += """
                <div class="section">
                    <h2>Summary</h2>
                    <div class="stats">
        """
        
        # Add statistics from NLP summary
        if nlp_summary:
            html += f"""
                        <div class="stat-item">
                            <h3>Total Logs</h3>
                            <p>{nlp_summary.get('total_logs', 'N/A')}</p>
                        </div>
            """
            
            if 'anomaly_count' in nlp_summary:
                html += f"""
                        <div class="stat-item">
                            <h3>Anomalies</h3>
                            <p>{nlp_summary.get('anomaly_count', 'N/A')} ({nlp_summary.get('anomaly_percentage', 0):.1f}%)</p>
                        </div>
                """
                
            if 'high_importance_count' in nlp_summary:
                html += f"""
                        <div class="stat-item">
                            <h3>High Importance Events</h3>
                            <p>{nlp_summary.get('high_importance_count', 'N/A')}</p>
                        </div>
                """
        
        html += """
                    </div>
                </div>
        """
        
        # Add time distribution plot
        if time_plot:
            html += """
                <div class="section">
                    <h2>Events Over Time</h2>
                    <div class="plot">
                        <img src="data:image/png;base64,""" + time_plot + """" width="100%">
                    </div>
                </div>
            """
            
        # Add severity distribution plot
        if severity_plot:
            html += """
                <div class="section">
                    <h2>Severity Distribution</h2>
                    <div class="plot">
                        <img src="data:image/png;base64,""" + severity_plot + """" width="100%">
                    </div>
                </div>
            """
            
        # Add anomaly distribution plot
        if anomaly_plot:
            html += """
                <div class="section">
                    <h2>Anomaly Distribution</h2>
                    <div class="plot">
                        <img src="data:image/png;base64,""" + anomaly_plot + """" width="100%">
                    </div>
                </div>
            """
            
        # Add security terms plot
        if terms_plot:
            html += """
                <div class="section">
                    <h2>Security Terms</h2>
                    <div class="plot">
                        <img src="data:image/png;base64,""" + terms_plot + """" width="100%">
                    </div>
                </div>
            """
            
        # Add source activity plot
        if source_plot:
            html += """
                <div class="section">
                    <h2>Source Activity</h2>
                    <div class="plot">
                        <img src="data:image/png;base64,""" + source_plot + """" width="100%">
                    </div>
                </div>
            """
            
        # Add detected anomalies table
        if 'is_anomaly' in df.columns and df['is_anomaly'].sum() > 0:
            anomalies = df[df['is_anomaly']].sort_values('anomaly_score', ascending=False).head(10)
            
            html += """
                <div class="section">
                    <h2>Top Detected Anomalies</h2>
                    <table>
                        <tr>
                            <th>Timestamp</th>
                            <th>Source</th>
                            <th>Severity</th>
                            <th>Message</th>
                            <th>Score</th>
                        </tr>
            """
            
            for _, row in anomalies.iterrows():
                html += f"""
                        <tr class="anomaly">
                            <td>{row.get('timestamp', 'N/A')}</td>
                            <td>{row.get('source', 'N/A')}</td>
                            <td>{row.get('severity', 'N/A')}</td>
                            <td>{row.get('message', 'N/A')}</td>
                            <td>{row.get('anomaly_score', 'N/A'):.2f}</td>
                        </tr>
                """
                
            html += """
                    </table>
                </div>
            """
            
        # Close HTML
        html += """
            </div>
        </body>
        </html>
        """
        
        return html