import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Any
import pickle
import os
from datetime import datetime, timedelta

from database.db_manager import Event
from utils.helpers import logger, db, signals

class AnomalyDetector:
    """ML-based anomaly detection for SOC events"""
    
    FEATURE_FEATURES = [
        'login_frequency_hourly',
        'failed_login_rate',
        'sudo_frequency',
        'session_duration',
        'ip_reputation_score',
        'file_change_rate',
        'process_spawn_rate',
        'port_activity_score',
        'timestamp_hour_sin',  # Cyclical time
        'timestamp_hour_cos'
    ]
    
    def __init__(self, db_manager):
        self.db = db_manager
        self.model = None
        self.scaler = StandardScaler()
        self.model_path = "soc_anomaly_model.pkl"
        self.is_fitted = False
        self.load_or_train_model()
    
    def load_or_train_model(self):
        """Load existing model or train new"""
        if os.path.exists(self.model_path):
            self._load_model()
        else:
            self._train_model()
    
    def _load_model(self):
        """Load pickled model"""
        try:
            with open(self.model_path, 'rb') as f:
                model_data = pickle.load(f)
                self.model = model_data['model']
                self.scaler = model_data['scaler']
                self.is_fitted = True
            logger.info("Anomaly model loaded")
        except Exception as e:
            logger.error(f"Model load failed: {e}")
            self._train_model()
    
    def _train_model(self):
        """Train IsolationForest on synthetic + real data"""
        logger.info("Training new anomaly detection model...")
        
        # Generate synthetic training data (normal + anomalous)
        X_train = self._generate_synthetic_data(n_samples=10000)
        
        # Fit model
        self.scaler.fit(X_train)
        X_scaled = self.scaler.transform(X_train)
        
        self.model = IsolationForest(
            contamination=0.1,  # 10% anomalies
            random_state=42,
            n_estimators=100
        )
        self.model.fit(X_scaled)
        
        self.is_fitted = True
        self._save_model()
        logger.info("Anomaly model trained and saved")
    
    def _generate_synthetic_data(self, n_samples: int) -> np.ndarray:
        """Generate realistic feature vectors"""
        np.random.seed(42)
        
        # Normal traffic (80%)
        normal = np.random.normal(loc=[10, 0.05, 1, 300, 0.8, 2, 5, 3, 0, 1],
                                 scale=[5, 0.03, 0.5, 100, 0.2, 1, 2, 1, 0.5, 0.5],
                                 size=(int(n_samples*0.8), len(self.FEATURE_FEATURES)))
        
        # Anomalous traffic (20%)
        anomalous = np.random.normal(loc=[50, 0.8, 10, 60, 0.1, 20, 50, 20, 0, 1],
                                    scale=[20, 0.15, 5, 30, 0.1, 10, 20, 10, 0.5, 0.5],
                                    size=(int(n_samples*0.2), len(self.FEATURE_FEATURES)))
        
        # Cyclical time features
        hours = np.linspace(0, 23, n_samples)
        normal = np.column_stack([
            normal[:, :-2],
            np.sin(2 * np.pi * hours / 24),
            np.cos(2 * np.pi * hours / 24)
        ])
        
        anomalous = np.column_stack([
            anomalous[:, :-2],
            np.sin(2 * np.pi * hours / 24),
            np.cos(2 * np.pi * hours / 24)
        ])
        
        X = np.vstack([normal, anomalous])
        return X
    
    def score_event(self, event_features: Dict[str, float]) -> Dict[str, float]:
        """Score single event anomaly"""
        if not self.is_fitted:
            return {"anomaly_score": 0.0, "is_anomaly": False, "confidence": 0.0}
        
        # Prepare feature vector
        feature_vector = np.array([event_features.get(f, 0.0) for f in self.FEATURE_FEATURES])
        feature_scaled = self.scaler.transform(feature_vector.reshape(1, -1))
        
        anomaly_score = self.model.decision_function(feature_scaled)[0]
        is_anomaly = self.model.predict(feature_scaled)[0] == -1
        
        # Convert to 0-1 probability
        prob = (1.0 - anomaly_score) * 0.5  # Normalize
        
        result = {
            "anomaly_score": anomaly_score,
            "anomaly_probability": prob,
            "is_anomaly": is_anomaly,
            "confidence": abs(anomaly_score)
        }
        
        if prob > 0.6:  # Threshold
            logger.warning(f"🤖 ML ANOMALY DETECTED: score={prob:.3f}")
            signals.new_anomaly.emit(result)
        
        return result
    
    def score_recent_events(self, hours: int = 1) -> List[Dict]:
        """Batch score recent events for dashboard"""
        recent_events = self.db.get_recent_events(limit=1000)
        scores = []
        
        for event in recent_events:
            # Extract features (simplified)
            features = self._event_to_features(event)
            score = self.score_event(features)
            scores.append({"event_id": event.id, **score})
        
        return scores
    
    def _event_to_features(self, event: Event) -> Dict[str, float]:
        """Map event to ML features"""
        parsed = event.parsed_data
        
        return {
            'login_frequency_hourly': parsed.get('login_count', 1.0),
            'failed_login_rate': parsed.get('failed_attempts', 0.0),
            'sudo_frequency': parsed.get('sudo_count', 0.0),
            'session_duration': parsed.get('duration', 300.0),
            'ip_reputation_score': self._ip_score(parsed.get('ip_address')),
            'file_change_rate': parsed.get('file_ops', 1.0),
            'process_spawn_rate': parsed.get('processes', 1.0),
            'port_activity_score': parsed.get('ports', 1.0),
            'timestamp_hour_sin': 0.0,  # From real time
            'timestamp_hour_cos': 1.0
        }
    
    def _ip_score(self, ip: str) -> float:
        """Simple IP reputation (expandable)"""
        if ip and '192.168' not in ip:  # External IPs suspicious
            return 0.2
        return 0.8
    
    def _save_model(self):
        """Persist model"""
        model_data = {'model': self.model, 'scaler': self.scaler}
        with open(self.model_path, 'wb') as f:
            pickle.dump(model_data, f)

# Global detector
detector = None

def get_anomaly_detector(db_manager) -> AnomalyDetector:
    global detector
    if detector is None:
        detector = AnomalyDetector(db_manager)
    return detector

if __name__ == "__main__":
    from database.db_manager import DBManager
    db = DBManager()
    detector = get_anomaly_detector(db)
    
    # Test scoring
    test_features = {
        'login_frequency_hourly': 50,
        'failed_login_rate': 0.9,
        'sudo_frequency': 15,
        # ... fill all
    }
    print(detector.score_event(test_features))

