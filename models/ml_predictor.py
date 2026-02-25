"""
Binary ML prediction pipeline for the 21-feature CICIDS2017 XGBoost model.
Loads model assets (model, scaler, feature list, thresholds) and provides
thread-safe prediction with threshold handling.

21 FEATURES FROM CICIDS2017:
- Flow Duration, Flow Bytes/s, Flow Packets/s, Destination Port
- Total Fwd Packets, Total Length of Fwd Packets, Fwd Packet Length Mean/Max/Std, Fwd Packets/s
- Bwd Packet Length Mean/Max, Bwd Packets/s
- Flow IAT Mean, Fwd IAT Mean
- PSH Flag Count, ACK Flag Count, FIN Flag Count
- Init_Win_bytes_forward, Init_Win_bytes_backward
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Dict, List

import joblib
import numpy as np
import pandas as pd

import logging
logger = logging.getLogger(__name__)


# The 21 CICIDS2017 features
CICIDS2017_FEATURES = [
    'Flow Duration',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Destination Port',
    'Total Fwd Packets',
    'Total Length of Fwd Packets',
    'Fwd Packet Length Mean',
    'Fwd Packet Length Max',
    'Fwd Packet Length Std',
    'Fwd Packets/s',
    'Bwd Packet Length Mean',
    'Bwd Packet Length Max',
    'Bwd Packets/s',
    'Flow IAT Mean',
    'Fwd IAT Mean',
    'PSH Flag Count',
    'ACK Flag Count',
    'FIN Flag Count',
    'Init_Win_bytes_forward',
    'Init_Win_bytes_backward',
]


# Default configuration
class Config:
    MODEL_DIR = Path(__file__).parent / "models_file"
    MODEL_PATH = MODEL_DIR / "xgboost_model.pkl"
    SCALER_PATH = MODEL_DIR / "scaler.pkl"
    FEATURES_PATH = MODEL_DIR / "features.pkl"
    DEFAULT_THRESHOLD = 0.5
    FLOW_TIMEOUT_SECONDS = 2.0
    MAX_TRACKED_FLOWS = 100000
    PACKET_QUEUE_SIZE = 10000
    FLOW_CLEAN_INTERVAL = 1.0


class MLPredictor:
    """
    XGBoost-only predictor for real-time monitoring.
    Uses 21 CICIDS2017 features for binary classification (Normal vs Malicious).
    """
    
    def __init__(
        self,
        model_path: Path | None = None,
        scaler_path: Path | None = None,
        features_path: Path | None = None,
    ):
        self.model_path = Path(model_path or Config.MODEL_PATH)
        self.scaler_path = Path(scaler_path or Config.SCALER_PATH)
        self.features_path = Path(features_path or Config.FEATURES_PATH)

        self.model = None
        self.scaler = None
        self.feature_names: List[str] = CICIDS2017_FEATURES.copy()
        self.current_threshold: float = Config.DEFAULT_THRESHOLD * 100  # Store as percentage (0-100)
        self._threshold = 50.0  # Alias property for compatibility
        self.is_loaded = False
        self.lock = threading.Lock()
        
        # For compatibility with multi_model_predictor
        self.models = {}
        self.attack_type_map = {
            0: 'Normal Traffic',
            1: 'Malicious'
        }
    
    @property
    def threshold(self) -> float:
        """Get threshold as percentage (0-100) for scapy_capture_engine compatibility."""
        return self._threshold
    
    @threshold.setter
    def threshold(self, value: float) -> None:
        """Set threshold as percentage (0-100)."""
        self._threshold = max(0.0, min(100.0, float(value)))
        self.current_threshold = self._threshold
        logger.info(f"Threshold updated to: {self._threshold}%")

    def load_models(self) -> bool:
        """Load XGBoost model and scaler."""
        try:
            logger.info(f"Loading XGBoost model from: {self.model_path.parent}")
            
            # Load model
            if self.model_path.exists():
                self.model = joblib.load(self.model_path)
                self.models['XGBoost'] = self.model
                logger.info(f"✓ XGBoost model loaded from {self.model_path}")
            else:
                raise FileNotFoundError(f"Model not found: {self.model_path}")
            
            # Load scaler
            if self.scaler_path.exists():
                self.scaler = joblib.load(self.scaler_path)
                logger.info(f"✓ Scaler loaded from {self.scaler_path}")
            else:
                raise FileNotFoundError(f"Scaler not found: {self.scaler_path}")
            
            # Load feature names (or use default 21 features)
            if self.features_path.exists():
                loaded_features = joblib.load(self.features_path)
                if isinstance(loaded_features, list) and len(loaded_features) > 0:
                    self.feature_names = loaded_features
                    logger.info(f"✓ Loaded {len(self.feature_names)} features from {self.features_path}")
            else:
                logger.info(f"Using default 21 CICIDS2017 features")

            self.is_loaded = True
            logger.info(f"✅ ML predictor loaded successfully ({len(self.feature_names)} features)")
            return True
            
        except Exception as exc:
            logger.error(f"Failed to load model assets: {exc}", exc_info=True)
            self.is_loaded = False
            return False

    def predict(self, features_dict: Dict[str, Any]) -> Dict[str, Any] | None:
        """
        Make prediction using XGBoost model.
        
        Input: feature dict keyed by feature_names.
        Output keys:
            - is_attack (bool): True for malicious, False for normal
            - classification ('Normal Traffic' | 'Malicious')
            - status ('SAFE' | 'ALERT')
            - confidence_score (percentage, 0-100)
            - threshold_used (float)
            - model_name: 'XGBoost'
        """
        if not self.is_loaded and not self.load_models():
            return None

        try:
            with self.lock:
                # Build feature vector in correct order
                vector = np.array([
                    float(features_dict.get(name, 0)) 
                    for name in self.feature_names
                ]).reshape(1, -1)
                
                # Create DataFrame to avoid sklearn warnings
                feature_df = pd.DataFrame(vector, columns=self.feature_names)
                
                # Scale features
                scaled = self.scaler.transform(feature_df)
                
                # Get prediction probabilities
                proba = self.model.predict_proba(scaled)[0]

            # Get attack probability (class 1) for threshold comparison
            attack_probability = float(proba[1]) if len(proba) > 1 else float(proba[0])
            is_attack = attack_probability >= self.current_threshold
            
            # Determine status
            status = "ALERT" if is_attack else "SAFE"
            classification = "Malicious" if is_attack else "Normal Traffic"
            
            # Confidence score = certainty of the classification
            # For Normal Traffic: show probability of being safe (proba[0])
            # For Malicious: show probability of being attack (proba[1])
            if is_attack:
                confidence_score = attack_probability * 100.0
            else:
                safe_probability = float(proba[0]) if len(proba) > 1 else 1 - float(proba[0])
                confidence_score = safe_probability * 100.0

            return {
                "is_attack": is_attack,
                "classification": classification,
                "status": status,
                "attack_type": classification,  # Legacy compatibility
                "class_3": 1 if is_attack else 0,
                "confidence_score": round(confidence_score, 2),
                "threshold_used": self.current_threshold,
                "model_name": "XGBoost",
                "severity": self._calculate_severity(attack_probability) if is_attack else "SAFE",
                "probabilities": {
                    "Normal Traffic": float(proba[0]) if len(proba) > 1 else 1 - float(proba[0]),
                    "Malicious": attack_probability
                },
            }
        except Exception as exc:
            logger.error(f"Inference failure: {exc}", exc_info=True)
            return None

    def set_threshold(self, threshold: float) -> None:
        """Set the prediction threshold for XGBoost."""
        with self.lock:
            self.current_threshold = max(0.0, min(1.0, threshold))
            logger.info(f"Threshold updated to: {self.current_threshold}")

    def get_threshold(self) -> float:
        """Get current prediction threshold."""
        return self.current_threshold

    def get_threshold_presets(self) -> Dict[str, float]:
        """Get predefined threshold presets."""
        return {
            "high_sensitivity": 0.3,  # More alerts, catch more attacks
            "balanced": 0.5,          # Default balanced
            "low_sensitivity": 0.7,   # Fewer alerts, fewer false positives
            "conservative": 0.9,      # Very few alerts, high confidence only
        }

    @staticmethod
    def _calculate_severity(confidence: float) -> str:
        """Calculate severity based on confidence score."""
        if confidence >= 0.9:
            return "CRITICAL"
        if confidence >= 0.7:
            return "HIGH"
        if confidence >= 0.5:
            return "MEDIUM"
        if confidence >= 0.3:
            return "LOW"
        return "INFO"

    def _get_severity(self, confidence: float) -> str:
        """Alias for compatibility."""
        return self._calculate_severity(confidence / 100.0)

