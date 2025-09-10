#!/usr/bin/env python3
"""
Advanced Threat Detection Model with Persistent Learning
Real-time threat classification with memory and continuous learning capabilities
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
from sklearn.feature_selection import SelectKBest, f_classif
import joblib
import json
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
import hashlib
import re
import ipaddress
import pickle
from pathlib import Path

@dataclass
class ThreatFeatures:
    """Comprehensive feature vector for threat classification"""
    # Network features
    packet_size: float
    connection_duration: float
    bytes_transferred: float
    packets_per_second: float
    unique_ports: int
    protocol_diversity: float
    
    # Behavioral features
    connection_frequency: float
    time_between_connections: float
    geographic_distance: float
    reputation_score: float
    
    # Content features
    payload_entropy: float
    suspicious_strings: int
    base64_content: bool
    encrypted_content: bool
    
    # Temporal features
    hour_of_day: int
    day_of_week: int
    is_weekend: bool
    
    # Source features
    source_ip_class: int
    is_tor_exit: bool
    is_vpn: bool
    country_risk_score: float
    
    # Advanced features
    tcp_flags_anomaly: float
    port_scan_indicator: float
    ddos_indicator: float
    malware_signature_count: int
    
    def to_vector(self) -> List[float]:
        """Convert features to numerical vector"""
        return [
            self.packet_size,
            self.connection_duration,
            self.bytes_transferred,
            self.packets_per_second,
            float(self.unique_ports),
            self.protocol_diversity,
            self.connection_frequency,
            self.time_between_connections,
            self.geographic_distance,
            self.reputation_score,
            self.payload_entropy,
            float(self.suspicious_strings),
            float(self.base64_content),
            float(self.encrypted_content),
            float(self.hour_of_day),
            float(self.day_of_week),
            float(self.is_weekend),
            float(self.source_ip_class),
            float(self.is_tor_exit),
            float(self.is_vpn),
            self.country_risk_score,
            self.tcp_flags_anomaly,
            self.port_scan_indicator,
            self.ddos_indicator,
            float(self.malware_signature_count)
        ]

@dataclass
class ModelMetrics:
    """Model performance metrics"""
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    auc_score: float
    training_samples: int
    test_samples: int
    feature_importance: Dict[str, float]
    confusion_matrix: List[List[int]]
    training_time: float
    last_trained: str

class ThreatDetectionModel:
    """Advanced ML-based threat detection with persistent learning"""
    
    def __init__(self, model_dir: str = "ml_models/saved_models/"):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        # Core models
        self.primary_classifier = None
        self.anomaly_detector = None
        self.feature_selector = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        
        # Model metadata
        self.feature_names = [
            "packet_size", "connection_duration", "bytes_transferred", "packets_per_second",
            "unique_ports", "protocol_diversity", "connection_frequency", "time_between_connections",
            "geographic_distance", "reputation_score", "payload_entropy", "suspicious_strings",
            "base64_content", "encrypted_content", "hour_of_day", "day_of_week", "is_weekend",
            "source_ip_class", "is_tor_exit", "is_vpn", "country_risk_score", "tcp_flags_anomaly",
            "port_scan_indicator", "ddos_indicator", "malware_signature_count"
        ]
        
        self.threat_categories = [
            'benign', 'malware', 'botnet', 'ddos', 'brute_force', 'sql_injection',
            'xss', 'phishing', 'ransomware', 'apt', 'port_scan', 'data_exfiltration', 'lateral_movement'
        ]
        
        # Performance tracking
        self.metrics: Optional[ModelMetrics] = None
        self.training_history = []
        self.prediction_cache = {}
        
        # Continuous learning
        self.new_training_data = []
        self.feedback_data = []
        self.retrain_threshold = 100  # Retrain after 100 new samples
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Initialize models
        self.load_or_initialize_models()
    
    def load_or_initialize_models(self):
        """Load existing models or initialize new ones"""
        try:
            self.load_models()
            self.logger.info("✅ Existing models loaded successfully")
        except Exception as e:
            self.logger.warning(f"Could not load existing models: {e}")
            self.logger.info("🔄 Initializing new models...")
            self.initialize_new_models()
    
    def initialize_new_models(self):
        """Initialize new ML models"""
        # Primary classifier with balanced class weights
        self.primary_classifier = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            max_features='sqrt',
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        )
        
        # Anomaly detector
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_jobs=-1
        )
        
        # Feature selector
        self.feature_selector = SelectKBest(
            score_func=f_classif,
            k=20  # Select top 20 features
        )
        
        # Initialize label encoder with threat categories
        self.label_encoder.fit(self.threat_categories)
        
        self.logger.info("🤖 New models initialized")
    
    def extract_features(self, event_data: Dict) -> ThreatFeatures:
        """Extract comprehensive features from network event"""
        # Network features
        packet_size = float(event_data.get('packet_size', 0))
        connection_duration = float(event_data.get('connection_duration', 0))
        bytes_transferred = float(event_data.get('bytes_transferred', packet_size))
        packets_per_second = float(event_data.get('packets_per_second', 1))
        unique_ports = int(event_data.get('unique_ports', 1))
        protocol_diversity = float(event_data.get('protocol_diversity', 0))
        
        # Behavioral features
        connection_frequency = float(event_data.get('connection_frequency', 0))
        time_between_connections = float(event_data.get('time_between_connections', 0))
        geographic_distance = float(event_data.get('geographic_distance', 0))
        reputation_score = float(event_data.get('reputation_score', 0.5))
        
        # Content analysis
        payload = event_data.get('payload', b'')
        if isinstance(payload, str):
            payload = payload.encode()
        
        payload_entropy = self.calculate_entropy(payload)
        suspicious_strings = self.count_suspicious_strings(payload)
        base64_content = self.detect_base64(payload)
        encrypted_content = self.detect_encryption(payload)
        
        # Temporal features
        timestamp = event_data.get('timestamp', datetime.now())
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except:
                timestamp = datetime.now()
        
        hour_of_day = timestamp.hour
        day_of_week = timestamp.weekday()
        is_weekend = day_of_week >= 5
        
        # Source analysis
        source_ip = event_data.get('source_ip', '0.0.0.0')
        source_ip_class = self.classify_ip(source_ip)
        is_tor_exit = event_data.get('is_tor_exit', False)
        is_vpn = event_data.get('is_vpn', False)
        country_risk_score = float(event_data.get('country_risk_score', 0.5))
        
        # Advanced features
        tcp_flags_anomaly = self.detect_tcp_flags_anomaly(event_data)
        port_scan_indicator = self.detect_port_scan_indicator(event_data)
        ddos_indicator = self.detect_ddos_indicator(event_data)
        malware_signature_count = self.count_malware_signatures(payload)
        
        return ThreatFeatures(
            packet_size=packet_size,
            connection_duration=connection_duration,
            bytes_transferred=bytes_transferred,
            packets_per_second=packets_per_second,
            unique_ports=unique_ports,
            protocol_diversity=protocol_diversity,
            connection_frequency=connection_frequency,
            time_between_connections=time_between_connections,
            geographic_distance=geographic_distance,
            reputation_score=reputation_score,
            payload_entropy=payload_entropy,
            suspicious_strings=suspicious_strings,
            base64_content=base64_content,
            encrypted_content=encrypted_content,
            hour_of_day=hour_of_day,
            day_of_week=day_of_week,
            is_weekend=is_weekend,
            source_ip_class=source_ip_class,
            is_tor_exit=is_tor_exit,
            is_vpn=is_vpn,
            country_risk_score=country_risk_score,
            tcp_flags_anomaly=tcp_flags_anomaly,
            port_scan_indicator=port_scan_indicator,
            ddos_indicator=ddos_indicator,
            malware_signature_count=malware_signature_count
        )
    
    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def count_suspicious_strings(self, payload: bytes) -> int:
        """Count suspicious strings in payload"""
        suspicious_patterns = [
            b'eval', b'exec', b'system', b'shell', b'cmd', b'script',
            b'union', b'select', b'drop', b'insert', b'update',
            b'<script>', b'javascript:', b'onerror', b'onload',
            b'../../../', b'passwd', b'shadow', b'trojan', b'backdoor'
        ]
        
        count = 0
        payload_lower = payload.lower()
        
        for pattern in suspicious_patterns:
            count += payload_lower.count(pattern)
        
        return count
    
    def detect_base64(self, payload: bytes) -> bool:
        """Detect base64 encoded content"""
        try:
            base64_pattern = re.compile(rb'[A-Za-z0-9+/]{20,}={0,2}')
            return bool(base64_pattern.search(payload))
        except:
            return False
    
    def detect_encryption(self, payload: bytes) -> bool:
        """Detect encrypted content based on entropy"""
        if not payload:
            return False
        entropy = self.calculate_entropy(payload)
        return entropy > 7.0
    
    def classify_ip(self, ip_str: str) -> int:
        """Classify IP address type"""
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_private:
                return 1
            elif ip.is_loopback:
                return 2
            elif ip.is_multicast:
                return 3
            elif ip.is_reserved:
                return 4
            else:
                return 5
        except:
            return 0
    
    def detect_tcp_flags_anomaly(self, event_data: Dict) -> float:
        """Detect TCP flags anomalies"""
        tcp_flags = event_data.get('tcp_flags', 0)
        if tcp_flags == 0:  # NULL scan
            return 1.0
        elif tcp_flags == 41:  # XMAS scan
            return 1.0
        elif tcp_flags == 1:  # FIN scan
            return 0.8
        return 0.0
    
    def detect_port_scan_indicator(self, event_data: Dict) -> float:
        """Detect port scanning indicators"""
        dst_port = event_data.get('destination_port', 0)
        src_port = event_data.get('source_port', 0)
        
        # Sequential port access
        if dst_port in range(20, 25) or dst_port in range(79, 84):
            return 0.8
        
        # High source port with low destination port
        if src_port > 32768 and dst_port < 1024:
            return 0.6
        
        return 0.0
    
    def detect_ddos_indicator(self, event_data: Dict) -> float:
        """Detect DDoS indicators"""
        packet_size = event_data.get('packet_size', 0)
        packets_per_second = event_data.get('packets_per_second', 0)
        
        # Small packets at high rate
        if packet_size < 100 and packets_per_second > 100:
            return 1.0
        elif packets_per_second > 50:
            return 0.7
        
        return 0.0
    
    def count_malware_signatures(self, payload: bytes) -> int:
        """Count malware signatures in payload"""
        malware_patterns = [
            b'metasploit', b'meterpreter', b'payload', b'shellcode',
            b'backdoor', b'trojan', b'keylogger', b'rootkit',
            b'ransomware', b'encrypt', b'bitcoin', b'monero'
        ]
        
        count = 0
        payload_lower = payload.lower()
        
        for pattern in malware_patterns:
            if pattern in payload_lower:
                count += 1
        
        return count
    
    def predict_threat(self, event_data: Dict) -> Dict[str, Any]:
        """Predict threat with comprehensive analysis"""
        try:
            # Extract features
            features = self.extract_features(event_data)
            feature_vector = features.to_vector()
            
            # Create cache key for prediction caching
            cache_key = hashlib.md5(str(feature_vector).encode()).hexdigest()
            if cache_key in self.prediction_cache:
                return self.prediction_cache[cache_key]
            
            results = {
                'timestamp': datetime.now().isoformat(),
                'model_version': '2.0',
                'features_used': len(feature_vector),
                'cache_hit': False
            }
            
            # Scale features if scaler is fitted
            if hasattr(self.scaler, 'mean_'):
                scaled_features = self.scaler.transform([feature_vector])
            else:
                scaled_features = [feature_vector]
            
            # Apply feature selection if available
            if self.feature_selector and hasattr(self.feature_selector, 'scores_'):
                scaled_features = self.feature_selector.transform(scaled_features)
            
            # Primary classification
            if self.primary_classifier and hasattr(self.primary_classifier, 'predict'):
                try:
                    prediction = self.primary_classifier.predict(scaled_features)[0]
                    probabilities = self.primary_classifier.predict_proba(scaled_features)[0]
                    
                    threat_type = self.label_encoder.inverse_transform([prediction])[0]
                    confidence = float(np.max(probabilities))
                    
                    results['primary_classification'] = {
                        'threat_type': threat_type,
                        'confidence': confidence,
                        'probabilities': {
                            category: float(prob) 
                            for category, prob in zip(self.threat_categories, probabilities)
                        }
                    }
                except Exception as e:
                    self.logger.warning(f"Primary classification failed: {e}")
                    results['primary_classification'] = self.fallback_classification(features)
            else:
                results['primary_classification'] = self.fallback_classification(features)
            
            # Anomaly detection
            if self.anomaly_detector and hasattr(self.anomaly_detector, 'predict'):
                try:
                    anomaly_score = self.anomaly_detector.decision_function(scaled_features)[0]
                    is_anomaly = self.anomaly_detector.predict(scaled_features)[0] == -1
                    
                    results['anomaly_detection'] = {
                        'is_anomaly': bool(is_anomaly),
                        'anomaly_score': float(anomaly_score),
                        'threshold': 0.0
                    }
                except Exception as e:
                    self.logger.warning(f"Anomaly detection failed: {e}")
                    results['anomaly_detection'] = {
                        'is_anomaly': False,
                        'anomaly_score': 0.0,
                        'threshold': 0.0
                    }
            
            # Rule-based classification
            rule_based = self.rule_based_classification(features)
            results['rule_based'] = rule_based
            
            # Combine results
            final_classification = self.combine_classifications(results)
            results['final_classification'] = final_classification
            
            # Cache result
            self.prediction_cache[cache_key] = results
            
            # Store for continuous learning
            self.store_prediction_for_learning(event_data, results)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Prediction error: {e}")
            return self.fallback_prediction(event_data)
    
    def fallback_classification(self, features: ThreatFeatures) -> Dict[str, Any]:
        """Rule-based fallback classification"""
        threat_type = 'benign'
        confidence = 0.5
        
        # High entropy suggests encryption/malware
        if features.payload_entropy > 7.5:
            threat_type = 'malware'
            confidence = 0.7
        elif features.suspicious_strings > 5:
            threat_type = 'malware'
            confidence = 0.8
        elif features.packets_per_second > 1000:
            threat_type = 'ddos'
            confidence = 0.9
        elif features.reputation_score < 0.3:
            threat_type = 'malware'
            confidence = 0.6
        elif features.port_scan_indicator > 0.5:
            threat_type = 'port_scan'
            confidence = 0.7
        
        return {
            'threat_type': threat_type,
            'confidence': confidence,
            'method': 'rule_based_fallback'
        }
    
    def rule_based_classification(self, features: ThreatFeatures) -> Dict[str, Any]:
        """Enhanced rule-based classification"""
        rules_triggered = []
        severity = 1
        
        # Network anomalies
        if features.packets_per_second > 500:
            rules_triggered.append('high_packet_rate')
            severity = max(severity, 7)
        
        if features.bytes_transferred > 100_000_000:
            rules_triggered.append('large_data_transfer')
            severity = max(severity, 6)
        
        # Content analysis
        if features.suspicious_strings > 3:
            rules_triggered.append('suspicious_content')
            severity = max(severity, 8)
        
        if features.payload_entropy > 7.0:
            rules_triggered.append('high_entropy_payload')
            severity = max(severity, 6)
        
        # Behavioral analysis
        if features.connection_frequency > 100:
            rules_triggered.append('rapid_connections')
            severity = max(severity, 7)
        
        # Advanced indicators
        if features.tcp_flags_anomaly > 0.5:
            rules_triggered.append('tcp_scan_detected')
            severity = max(severity, 6)
        
        if features.port_scan_indicator > 0.5:
            rules_triggered.append('port_scan_behavior')
            severity = max(severity, 7)
        
        if features.ddos_indicator > 0.5:
            rules_triggered.append('ddos_pattern')
            severity = max(severity, 8)
        
        if features.malware_signature_count > 0:
            rules_triggered.append('malware_signatures')
            severity = max(severity, 9)
        
        # Source reputation
        if features.reputation_score < 0.2:
            rules_triggered.append('poor_reputation')
            severity = max(severity, 8)
        
        return {
            'rules_triggered': rules_triggered,
            'severity': severity,
            'is_threat': len(rules_triggered) > 0
        }
    
    def combine_classifications(self, results: Dict) -> Dict[str, Any]:
        """Combine multiple classification results"""
        primary = results.get('primary_classification', {})
        anomaly = results.get('anomaly_detection', {})
        rule_based = results.get('rule_based', {})
        
        threat_type = primary.get('threat_type', 'benign')
        confidence = primary.get('confidence', 0.5)
        severity = rule_based.get('severity', 1)
        
        # Adjust based on anomaly detection
        if anomaly.get('is_anomaly', False):
            confidence = min(1.0, confidence + 0.2)
            severity = max(severity, 6)
        
        # Adjust based on rule-based results
        if rule_based.get('is_threat', False):
            if threat_type == 'benign':
                threat_type = 'malware'
            confidence = min(1.0, confidence + 0.1)
            severity = max(severity, rule_based.get('severity', 1))
        
        return {
            'threat_type': threat_type,
            'confidence': float(confidence),
            'severity': int(severity),
            'is_threat': threat_type != 'benign' or rule_based.get('is_threat', False),
            'classification_method': 'combined'
        }
    
    def fallback_prediction(self, event_data: Dict) -> Dict[str, Any]:
        """Complete fallback prediction"""
        return {
            'timestamp': datetime.now().isoformat(),
            'model_version': '2.0',
            'features_used': 0,
            'primary_classification': {
                'threat_type': 'unknown',
                'confidence': 0.1,
                'method': 'fallback'
            },
            'anomaly_detection': {
                'is_anomaly': False,
                'anomaly_score': 0.0
            },
            'rule_based': {
                'rules_triggered': [],
                'severity': 1,
                'is_threat': False
            },
            'final_classification': {
                'threat_type': 'unknown',
                'confidence': 0.1,
                'severity': 1,
                'is_threat': False,
                'classification_method': 'fallback'
            }
        }
    
    def train_model(self, training_events: List[Dict], labels: List[str]) -> ModelMetrics:
        """Train the model with persistent learning"""
        try:
            start_time = datetime.now()
            
            # Extract features
            feature_vectors = []
            for event in training_events:
                features = self.extract_features(event)
                feature_vectors.append(features.to_vector())
            
            X = np.array(feature_vectors)
            y = np.array(labels)
            
            # Encode labels
            y_encoded = self.label_encoder.transform(y)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
            )
            
            # Feature selection
            X_train_selected = self.feature_selector.fit_transform(X_train, y_train)
            X_test_selected = self.feature_selector.transform(X_test)
            
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train_selected)
            X_test_scaled = self.scaler.transform(X_test_selected)
            
            # Train primary classifier
            self.primary_classifier.fit(X_train_scaled, y_train)
            
            # Train anomaly detector
            self.anomaly_detector.fit(X_train_scaled)
            
            # Evaluate model
            y_pred = self.primary_classifier.predict(X_test_scaled)
            
            # Calculate metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
            recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
            f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
            
            # Feature importance
            feature_importance = {}
            if hasattr(self.primary_classifier, 'feature_importances_'):
                selected_features = self.feature_selector.get_support()
                for i, importance in enumerate(self.primary_classifier.feature_importances_):
                    feature_idx = np.where(selected_features)[0][i]
                    feature_importance[self.feature_names[feature_idx]] = float(importance)
            
            # Create metrics object
            training_time = (datetime.now() - start_time).total_seconds()
            self.metrics = ModelMetrics(
                accuracy=accuracy,
                precision=precision,
                recall=recall,
                f1_score=f1,
                auc_score=0.0,  # Would need probability predictions for AUC
                training_samples=len(X_train),
                test_samples=len(X_test),
                feature_importance=feature_importance,
                confusion_matrix=confusion_matrix(y_test, y_pred).tolist(),
                training_time=training_time,
                last_trained=datetime.now().isoformat()
            )
            
            # Save models and training history
            self.save_models()
            self.save_training_history(training_events, labels)
            
            self.logger.info(f"✅ Model trained successfully - Accuracy: {accuracy:.3f}")
            return self.metrics
            
        except Exception as e:
            self.logger.error(f"Training failed: {e}")
            raise e
    
    def retrain_with_new_data(self, new_events: List[Dict], new_labels: List[str]) -> ModelMetrics:
        """Retrain model with new data while preserving previous learning"""
        try:
            # Load previous training data
            previous_events, previous_labels = self.load_training_history()
            
            # Combine with new data
            all_events = previous_events + new_events
            all_labels = previous_labels + new_labels
            
            # Limit total training data to prevent memory issues
            max_samples = 10000
            if len(all_events) > max_samples:
                # Keep most recent samples
                all_events = all_events[-max_samples:]
                all_labels = all_labels[-max_samples:]
            
            self.logger.info(f"🔄 Retraining with {len(all_events)} total samples ({len(new_events)} new)")
            
            # Train with combined data
            metrics = self.train_model(all_events, all_labels)
            
            # Clear new training data buffer
            self.new_training_data = []
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Retraining failed: {e}")
            raise e
    
    def store_prediction_for_learning(self, event_data: Dict, prediction_result: Dict):
        """Store prediction for future learning"""
        learning_sample = {
            'event_data': event_data,
            'prediction': prediction_result,
            'timestamp': datetime.now().isoformat()
        }
        
        self.new_training_data.append(learning_sample)
        
        # Auto-retrain if we have enough new data
        if len(self.new_training_data) >= self.retrain_threshold:
            self.logger.info("🔄 Auto-retraining triggered")
            try:
                # Extract events and labels from new data
                new_events = [sample['event_data'] for sample in self.new_training_data]
                # Use predicted labels for unsupervised learning
                new_labels = [
                    sample['prediction']['final_classification']['threat_type'] 
                    for sample in self.new_training_data
                ]
                
                self.retrain_with_new_data(new_events, new_labels)
            except Exception as e:
                self.logger.error(f"Auto-retraining failed: {e}")
    
    def add_feedback(self, event_data: Dict, correct_label: str):
        """Add human feedback for supervised learning"""
        feedback_sample = {
            'event_data': event_data,
            'correct_label': correct_label,
            'timestamp': datetime.now().isoformat()
        }
        
        self.feedback_data.append(feedback_sample)
        
        # Retrain with feedback data
        if len(self.feedback_data) >= 10:  # Retrain with smaller feedback batches
            try:
                feedback_events = [sample['event_data'] for sample in self.feedback_data]
                feedback_labels = [sample['correct_label'] for sample in self.feedback_data]
                
                self.retrain_with_new_data(feedback_events, feedback_labels)
                self.feedback_data = []  # Clear feedback buffer
                
                self.logger.info("✅ Model updated with human feedback")
            except Exception as e:
                self.logger.error(f"Feedback learning failed: {e}")
    
    def save_models(self):
        """Save all models and metadata"""
        try:
            # Save models
            if self.primary_classifier:
                joblib.dump(self.primary_classifier, self.model_dir / 'random_forest_classifier.pkl')
            
            if self.anomaly_detector:
                joblib.dump(self.anomaly_detector, self.model_dir / 'isolation_forest.pkl')
            
            if self.feature_selector:
                joblib.dump(self.feature_selector, self.model_dir / 'feature_selector.pkl')
            
            joblib.dump(self.scaler, self.model_dir / 'feature_scaler.pkl')
            joblib.dump(self.label_encoder, self.model_dir / 'label_encoder.pkl')
            
            # Save metadata
            metadata = {
                'feature_names': self.feature_names,
                'threat_categories': self.threat_categories,
                'model_config': {
                    'random_forest': {
                        'n_estimators': 200,
                        'max_depth': 20,
                        'min_samples_split': 5,
                        'min_samples_leaf': 2,
                        'max_features': 'sqrt',
                        'random_state': 42,
                        'n_jobs': -1,
                        'class_weight': 'balanced'
                    },
                    'isolation_forest': {
                        'contamination': 0.1,
                        'random_state': 42,
                        'n_jobs': -1
                    }
                },
                'metrics': asdict(self.metrics) if self.metrics else None,
                'saved_at': datetime.now().isoformat()
            }
            
            with open(self.model_dir / 'model_metadata.json', 'w') as f:
                json.dump(metadata, f, indent=2)
            
            self.logger.info("💾 Models saved successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to save models: {e}")
    
    def load_models(self):
        """Load existing models and metadata"""
        # Load models
        model_files = {
            'primary_classifier': 'random_forest_classifier.pkl',
            'anomaly_detector': 'isolation_forest.pkl',
            'feature_selector': 'feature_selector.pkl',
            'scaler': 'feature_scaler.pkl',
            'label_encoder': 'label_encoder.pkl'
        }
        
        for attr_name, filename in model_files.items():
            file_path = self.model_dir / filename
            if file_path.exists():
                setattr(self, attr_name, joblib.load(file_path))
        
        # Load metadata
        metadata_file = self.model_dir / 'model_metadata.json'
        if metadata_file.exists():
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
                
                if 'metrics' in metadata and metadata['metrics']:
                    metrics_data = metadata['metrics']
                    self.metrics = ModelMetrics(**metrics_data)
                
                if 'feature_names' in metadata:
                    self.feature_names = metadata['feature_names']
                
                if 'threat_categories' in metadata:
                    self.threat_categories = metadata['threat_categories']
        
        self.logger.info("📂 Models loaded from disk")
    
    def save_training_history(self, events: List[Dict], labels: List[str]):
        """Save training history for persistent learning"""
        training_data = {
            'events': events,
            'labels': labels,
            'timestamp': datetime.now().isoformat(),
            'sample_count': len(events)
        }
        
        # Save to file
        history_file = self.model_dir / 'training_history.json'
        
        # Load existing history
        existing_history = []
        if history_file.exists():
            try:
                with open(history_file, 'r') as f:
                    existing_data = json.load(f)
                    if isinstance(existing_data, list):
                        existing_history = existing_data
                    else:
                        existing_history = [existing_data]
            except:
                existing_history = []
        
        # Add new training session
        existing_history.append(training_data)
        
        # Keep only last 10 training sessions
        existing_history = existing_history[-10:]
        
        # Save updated history
        with open(history_file, 'w') as f:
            json.dump(existing_history, f, indent=2, default=str)
        
        self.logger.info(f"📚 Training history saved: {len(events)} samples")
    
    def load_training_history(self) -> Tuple[List[Dict], List[str]]:
        """Load training history for retraining"""
        history_file = self.model_dir / 'training_history.json'
        
        if not history_file.exists():
            return [], []
        
        try:
            with open(history_file, 'r') as f:
                history = json.load(f)
                
                all_events = []
                all_labels = []
                
                # Handle both old and new format
                if isinstance(history, list):
                    for session in history:
                        if 'events' in session and 'labels' in session:
                            all_events.extend(session['events'])
                            all_labels.extend(session['labels'])
                else:
                    # Old format
                    if 'events' in history and 'labels' in history:
                        all_events = history['events']
                        all_labels = history['labels']
                
                return all_events, all_labels
                
        except Exception as e:
            self.logger.error(f"Failed to load training history: {e}")
            return [], []
    
    def generate_synthetic_training_data(self, num_samples: int = 1000) -> Tuple[np.ndarray, np.ndarray]:
        """Generate synthetic training data for initial model training"""
        X = []
        y = []
        
        for _ in range(num_samples):
            # Generate random features based on threat type
            threat_type = np.random.choice(self.threat_categories)
            
            if threat_type == 'benign':
                features = self.generate_benign_features()
            elif threat_type == 'ddos':
                features = self.generate_ddos_features()
            elif threat_type == 'port_scan':
                features = self.generate_port_scan_features()
            elif threat_type == 'malware':
                features = self.generate_malware_features()
            else:
                features = self.generate_generic_threat_features()
            
            X.append(features)
            y.append(threat_type)
        
        return np.array(X), np.array(y)
    
    def generate_benign_features(self) -> List[float]:
        """Generate features for benign traffic"""
        return [
            np.random.normal(500, 200),  # packet_size
            np.random.exponential(2),    # connection_duration
            np.random.normal(1000, 500), # bytes_transferred
            np.random.normal(5, 2),      # packets_per_second
            np.random.randint(1, 5),     # unique_ports
            np.random.uniform(0, 0.3),   # protocol_diversity
            np.random.normal(2, 1),      # connection_frequency
            np.random.exponential(10),   # time_between_connections
            np.random.uniform(0, 1000),  # geographic_distance
            np.random.uniform(0.7, 1.0), # reputation_score (high for benign)
            np.random.uniform(3, 6),     # payload_entropy (normal)
            np.random.randint(0, 2),     # suspicious_strings (low)
            0,                           # base64_content (false)
            0,                           # encrypted_content (false)
            np.random.randint(0, 24),    # hour_of_day
            np.random.randint(0, 7),     # day_of_week
            np.random.choice([0, 1]),    # is_weekend
            np.random.randint(1, 5),     # source_ip_class
            0,                           # is_tor_exit (false)
            0,                           # is_vpn (false)
            np.random.uniform(0.3, 0.7), # country_risk_score
            0,                           # tcp_flags_anomaly (none)
            0,                           # port_scan_indicator (none)
            0,                           # ddos_indicator (none)
            0                            # malware_signature_count (none)
        ]
    
    def generate_ddos_features(self) -> List[float]:
        """Generate features for DDoS attacks"""
        return [
            np.random.normal(64, 20),    # packet_size (small)
            np.random.uniform(0, 0.1),   # connection_duration (short)
            np.random.normal(100, 50),   # bytes_transferred (small)
            np.random.normal(1000, 300), # packets_per_second (high)
            np.random.randint(1, 3),     # unique_ports (few)
            np.random.uniform(0, 0.2),   # protocol_diversity (low)
            np.random.normal(500, 100),  # connection_frequency (very high)
            np.random.uniform(0, 0.01),  # time_between_connections (very short)
            np.random.uniform(0, 5000),  # geographic_distance
            np.random.uniform(0.1, 0.4), # reputation_score (low)
            np.random.uniform(2, 5),     # payload_entropy (low)
            np.random.randint(0, 3),     # suspicious_strings
            0,                           # base64_content
            0,                           # encrypted_content
            np.random.randint(0, 24),    # hour_of_day
            np.random.randint(0, 7),     # day_of_week
            np.random.choice([0, 1]),    # is_weekend
            np.random.randint(1, 5),     # source_ip_class
            np.random.choice([0, 1]),    # is_tor_exit
            np.random.choice([0, 1]),    # is_vpn
            np.random.uniform(0.6, 0.9), # country_risk_score (high)
            np.random.uniform(0, 0.3),   # tcp_flags_anomaly
            np.random.uniform(0, 0.3),   # port_scan_indicator
            np.random.uniform(0.7, 1.0), # ddos_indicator (high)
            np.random.randint(0, 2)      # malware_signature_count
        ]
    
    def generate_port_scan_features(self) -> List[float]:
        """Generate features for port scanning"""
        return [
            np.random.normal(40, 10),    # packet_size (very small)
            np.random.uniform(0, 0.05),  # connection_duration (very short)
            np.random.normal(50, 20),    # bytes_transferred (minimal)
            np.random.normal(50, 20),    # packets_per_second (moderate)
            np.random.randint(10, 50),   # unique_ports (many)
            np.random.uniform(0.5, 1.0), # protocol_diversity (high)
            np.random.normal(100, 30),   # connection_frequency (high)
            np.random.uniform(0, 0.1),   # time_between_connections (short)
            np.random.uniform(0, 2000),  # geographic_distance
            np.random.uniform(0.2, 0.5), # reputation_score (medium-low)
            np.random.uniform(1, 4),     # payload_entropy (low)
            np.random.randint(0, 2),     # suspicious_strings
            0,                           # base64_content
            0,                           # encrypted_content
            np.random.randint(0, 24),    # hour_of_day
            np.random.randint(0, 7),     # day_of_week
            np.random.choice([0, 1]),    # is_weekend
            np.random.randint(1, 5),     # source_ip_class
            np.random.choice([0, 1]),    # is_tor_exit
            np.random.choice([0, 1]),    # is_vpn
            np.random.uniform(0.4, 0.8), # country_risk_score
            np.random.uniform(0.3, 0.8), # tcp_flags_anomaly (moderate)
            np.random.uniform(0.8, 1.0), # port_scan_indicator (high)
            np.random.uniform(0, 0.3),   # ddos_indicator (low)
            np.random.randint(0, 1)      # malware_signature_count
        ]
    
    def generate_malware_features(self) -> List[float]:
        """Generate features for malware"""
        return [
            np.random.normal(1200, 400),  # packet_size (larger)
            np.random.normal(5, 3),       # connection_duration (moderate)
            np.random.normal(5000, 2000), # bytes_transferred (larger)
            np.random.normal(20, 10),     # packets_per_second (moderate)
            np.random.randint(3, 10),     # unique_ports (moderate)
            np.random.uniform(0.2, 0.6),  # protocol_diversity (moderate)
            np.random.normal(10, 5),      # connection_frequency (moderate)
            np.random.normal(30, 15),     # time_between_connections (moderate)
            np.random.uniform(0, 3000),   # geographic_distance
            np.random.uniform(0.1, 0.3),  # reputation_score (low)
            np.random.uniform(6, 8),      # payload_entropy (high)
            np.random.randint(3, 10),     # suspicious_strings (high)
            np.random.choice([0, 1]),     # base64_content
            np.random.choice([0, 1]),     # encrypted_content
            np.random.randint(0, 24),     # hour_of_day
            np.random.randint(0, 7),      # day_of_week
            np.random.choice([0, 1]),     # is_weekend
            np.random.randint(1, 5),      # source_ip_class
            np.random.choice([0, 1]),     # is_tor_exit
            np.random.choice([0, 1]),     # is_vpn
            np.random.uniform(0.6, 0.9),  # country_risk_score (high)
            np.random.uniform(0, 0.5),    # tcp_flags_anomaly
            np.random.uniform(0, 0.4),    # port_scan_indicator
            np.random.uniform(0, 0.4),    # ddos_indicator
            np.random.randint(1, 5)       # malware_signature_count (high)
        ]
    
    def generate_generic_threat_features(self) -> List[float]:
        """Generate features for generic threats"""
        return [
            np.random.normal(800, 300),   # packet_size
            np.random.normal(3, 2),       # connection_duration
            np.random.normal(2000, 1000), # bytes_transferred
            np.random.normal(30, 15),     # packets_per_second
            np.random.randint(2, 8),      # unique_ports
            np.random.uniform(0.3, 0.7),  # protocol_diversity
            np.random.normal(20, 10),     # connection_frequency
            np.random.normal(15, 8),      # time_between_connections
            np.random.uniform(0, 2000),   # geographic_distance
            np.random.uniform(0.2, 0.6),  # reputation_score
            np.random.uniform(4, 7),      # payload_entropy
            np.random.randint(1, 5),      # suspicious_strings
            np.random.choice([0, 1]),     # base64_content
            np.random.choice([0, 1]),     # encrypted_content
            np.random.randint(0, 24),     # hour_of_day
            np.random.randint(0, 7),      # day_of_week
            np.random.choice([0, 1]),     # is_weekend
            np.random.randint(1, 5),      # source_ip_class
            np.random.choice([0, 1]),     # is_tor_exit
            np.random.choice([0, 1]),     # is_vpn
            np.random.uniform(0.4, 0.8),  # country_risk_score
            np.random.uniform(0, 0.6),    # tcp_flags_anomaly
            np.random.uniform(0, 0.6),    # port_scan_indicator
            np.random.uniform(0, 0.6),    # ddos_indicator
            np.random.randint(0, 3)       # malware_signature_count
        ]
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get comprehensive model information"""
        return {
            'model_status': 'trained' if self.primary_classifier else 'not_trained',
            'feature_count': len(self.feature_names),
            'threat_categories': self.threat_categories,
            'models_loaded': {
                'primary_classifier': self.primary_classifier is not None,
                'anomaly_detector': self.anomaly_detector is not None,
                'feature_selector': self.feature_selector is not None,
                'scaler_fitted': hasattr(self.scaler, 'mean_'),
                'label_encoder_fitted': hasattr(self.label_encoder, 'classes_')
            },
            'training_data_available': len(self.new_training_data),
            'feedback_data_available': len(self.feedback_data),
            'performance': asdict(self.metrics) if self.metrics else None,
            'cache_size': len(self.prediction_cache)
        }

# Global model instance with persistent learning
threat_model = ThreatDetectionModel()

if __name__ == "__main__":
    # Test the model
    test_event = {
        'source_ip': '192.168.1.100',
        'destination_ip': '10.0.0.5',
        'packet_size': 1024,
        'protocol': 'TCP',
        'payload': b'GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n',
        'timestamp': datetime.now().isoformat()
    }
    
    result = threat_model.predict_threat(test_event)
    print(json.dumps(result, indent=2, default=str))