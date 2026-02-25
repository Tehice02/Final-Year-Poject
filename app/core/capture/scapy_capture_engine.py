"""
Scapy-based capture engine for real-time network monitoring.
Uses custom flow aggregator to extract 21 CICIDS2017 features for ML prediction.
Uses ONLY XGBoost model for real-time predictions.
NO NFSTREAM DEPENDENCIES - Pure Scapy implementation!
"""

import logging
import threading
import time
import warnings

# Suppress sklearn warnings about feature names (we use numpy arrays, not DataFrames)
warnings.filterwarnings('ignore', message='X does not have valid feature names')
from pathlib import Path
from typing import Callable, Dict, Optional
from queue import Queue, Empty
import sys

# Add models directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / 'models'))

from scapy.all import AsyncSniffer, IP, TCP, UDP
 
from collections import deque
from datetime import datetime
# Import our custom flow aggregator and ML predictor from /models
from flow_aggregator import FlowAggregator
from ml_predictor import MLPredictor as ScapyMLPredictor


logger = logging.getLogger(__name__)


class ScapyCaptureEngine:
    """
    Real-time network capture using Scapy ONLY.
    Provides 21 CICIDS2017 features for binary classification (Normal vs Malicious).
    Uses ONLY XGBoost model for real-time predictions.
    """

    def __init__(
        self,
        interface: str,
        on_flow_callback: Optional[Callable[[Dict], None]] = None,
        predictor=None
    ):
        """
        Initialize Scapy capture engine.

        Args:
            interface: Network interface to capture from (e.g., 'eth0', 'wlan0')
            on_flow_callback: Callback function to handle completed flows with predictions
            predictor: ML predictor instance (MultiModelPredictor from Flask app)
        """
        self.interface = interface
        self.on_flow_callback = on_flow_callback
        self.predictor = predictor
        # Application context for DB updates (optional)
        self.app_context = None

        # Initialize flow aggregator (21 CICIDS2017 features)
        self.flow_aggregator = FlowAggregator(
            flow_timeout=2.0,  # 2 seconds timeout for flows
            max_flows=100000
        )

        # Scapy sniffer
        self.sniffer = None
        self.capture_thread = None
        self.timeout_thread = None
        self.stop_event = threading.Event()
        self._running = False
        self.last_error: Optional[str] = None
        self.started_event = threading.Event()

        # Statistics
        self.total_flows = 0
        self.total_packets = 0
        self.start_time = None
        # PPS smoothing and windowing
        self._packet_counter_current = 0
        self._pps_lock = threading.Lock()
        self.pps_window_seconds = 5  # sliding window length in seconds (configurable)
        self.pps_alpha = 0.2  # EMA alpha (configurable)
        self._pps_counts = deque(maxlen=60)  # store per-second raw counts up to 60s
        self.ema_pps = 0.0
        self.packet_rate_series = []  # list of {t: ms_since_epoch, v: smoothed_pps}
        self.pps_thread = None

    @property
    def is_running(self):
        """Check if capture is currently running."""
        return self._running

    def start_capture(self):
        """Start real-time packet capture using Scapy."""
        if self._running:
            logger.warning("Capture already running")
            return

        logger.info(f"Starting Scapy capture on interface: {self.interface}")

        # Ensure ML predictor is loaded
        if self.predictor and hasattr(self.predictor, 'is_loaded') and not self.predictor.is_loaded:
            logger.info("Loading ML models...")
            if hasattr(self.predictor, 'load_models'):
                self.predictor.load_models()
            elif hasattr(self.predictor, 'load_all_models'):
                self.predictor.load_all_models()

        # Log which model will be used
        if self.predictor and hasattr(self.predictor, 'models') and 'XGBoost' in self.predictor.models:
            logger.info("🎯 REALTIME MODE: Using XGBoost model ONLY for fast predictions")
        elif self.predictor:
            logger.info("Using available ML predictor for predictions")

        self.stop_event.clear()
        self.started_event.clear()
        self.last_error = None
        self._running = True
        self.start_time = time.time()

        try:
            # Start timeout worker thread (checks for expired flows)
            self.timeout_thread = threading.Thread(target=self._timeout_worker, daemon=True)
            self.timeout_thread.start()

            # Start PPS worker thread (aggregates packets/sec, applies EMA, emits via Socket.IO)
            self.pps_thread = threading.Thread(target=self._pps_worker, daemon=True)
            self.pps_thread.start()

            # Start capture thread
            self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
            self.capture_thread.start()

            logger.info("Scapy capture started successfully")
            self.started_event.set()

        except Exception as e:
            logger.error(f"Failed to start Scapy capture: {e}", exc_info=True)
            self.last_error = str(e)
            self._running = False

    def stop_capture(self):
        """Stop packet capture."""
        if not self._running:
            logger.warning("Capture not running")
            return

        logger.info("Stopping Scapy capture...")
        self._running = False
        self.stop_event.set()

        # Stop sniffer
        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception as e:
                logger.error(f"Error stopping sniffer: {e}")

        # Wait for threads to finish
        for thread in [self.capture_thread, self.timeout_thread]:
            if thread and thread.is_alive():
                thread.join(timeout=3)
        if self.pps_thread and self.pps_thread.is_alive():
            self.pps_thread.join(timeout=3)

        # Flush remaining flows
        remaining_flows = self.flow_aggregator.cleanup_all_flows()
        if remaining_flows:
            logger.info(f"Flushing {len(remaining_flows)} remaining flows")
            self._predict_flows(remaining_flows)

        logger.info("Scapy capture stopped")

    def _capture_loop(self):
        """Main capture loop - sniffs packets using Scapy."""
        try:
            logger.info(f"Initializing Scapy sniffer on interface: {self.interface}")

            # Start Scapy async sniffer
            self.sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self._process_packet,
                store=False,  # Don't store packets in memory
                filter="ip"   # Only capture IP packets
            )

            self.sniffer.start()
            logger.info("Scapy sniffer initialized successfully, waiting for packets...")

            # Keep thread alive
            while not self.stop_event.is_set():
                time.sleep(0.5)

        except Exception as e:
            logger.error(f"Scapy capture error: {e}", exc_info=True)
            self.last_error = str(e)
            self._running = False
        finally:
            if self.sniffer:
                try:
                    self.sniffer.stop()
                except:
                    pass

    def _process_packet(self, packet):
        """Process a single packet (called by Scapy for each packet)."""
        if self.stop_event.is_set():
            return

        try:
            # Only process IP packets
            if IP not in packet:
                return

            # Add packet to flow aggregator
            self.flow_aggregator.add_packet(packet)
            self.total_packets += 1
            # Count packet for PPS calculation (thread-safe)
            try:
                with self._pps_lock:
                    self._packet_counter_current += 1
            except Exception:
                pass

            # Log every 1000 packets
            if self.total_packets % 1000 == 0:
                logger.debug(f"Processed {self.total_packets} packets")

        except Exception as e:
            logger.error(f"Error processing packet: {e}", exc_info=True)

    def _timeout_worker(self):
        """Worker thread that checks for expired flows and triggers predictions."""
        while not self.stop_event.is_set():
            try:
                # Check for expired flows every 1 second
                time.sleep(1)

                expired_flows = self.flow_aggregator.get_expired_flows()
                if expired_flows:
                    logger.debug(f"Found {len(expired_flows)} expired flows")
                    self._predict_flows(expired_flows)

            except Exception as e:
                logger.error(f"Error in timeout worker: {e}", exc_info=True)

    def _pps_worker(self):
        """
        Worker that runs every 1 second to compute packets-per-second (PPS)
        using a sliding window and applies an exponential moving average (EMA).
        Emits only the smoothed PPS via Socket.IO to the frontend.
        """
        # Lazy import socketio to avoid circular imports at module load
        try:
            from app import socketio
        except Exception:
            socketio = None

        while not self.stop_event.is_set():
            try:
                time.sleep(1)

                # Move current second counter into window
                with self._pps_lock:
                    count = self._packet_counter_current
                    self._packet_counter_current = 0

                self._pps_counts.append(count)

                # Use sliding window average (last N seconds). If window shorter than configured, use available samples
                window_len = min(len(self._pps_counts), max(1, self.pps_window_seconds))
                if window_len > 0:
                    raw_pps = sum(list(self._pps_counts)[-window_len:]) / float(window_len)
                else:
                    raw_pps = 0.0

                # EMA smoothing
                self.ema_pps = (self.pps_alpha * raw_pps) + ((1.0 - self.pps_alpha) * self.ema_pps)

                # Timestamp in ms
                ts_ms = int(datetime.utcnow().timestamp() * 1000)

                # Append to internal packet_rate_series (cap to 120 samples)
                try:
                    self.packet_rate_series.append({"t": ts_ms, "v": float(self.ema_pps)})
                    if len(self.packet_rate_series) > 120:
                        self.packet_rate_series = self.packet_rate_series[-120:]
                except Exception:
                    pass

                # Emit smoothed PPS to frontend via Socket.IO (if available)
                try:
                    if socketio:
                        socketio.emit('packet_rate', { 'pps': round(self.ema_pps, 3), 'timestamp': ts_ms }, namespace='/')
                except Exception:
                    logger.debug('Failed to emit packet_rate via Socket.IO', exc_info=True)

                # Persist daily aggregates (packets/flows/alerts) if app context provided
                try:
                    if self.app_context:
                        with self.app_context:
                            from app import db
                            from app.models import TrafficDaily

                            today = datetime.utcnow().date()
                            # Upsert today's row using SQLAlchemy
                            row = TrafficDaily.query.filter_by(date=today).first()
                            if not row:
                                row = TrafficDaily(date=today, packets=self.total_packets, flows=self.total_flows, alerts=0)
                                db.session.add(row)
                            else:
                                row.packets = self.total_packets
                                row.flows = self.total_flows
                            db.session.commit()
                except Exception:
                    logger.debug('Failed to persist daily traffic', exc_info=True)

            except Exception as e:
                logger.error(f"Error in PPS worker: {e}", exc_info=True)

    def _predict_flows(self, flows):
        """
        Make predictions for completed flows using XGBOOST ONLY for real-time speed.
        Uses 20 CICIDS2017 features and binary classification (Normal vs Malicious).
        """
        for flow_data in flows:
            try:
                # Extract 20 CICIDS2017 features from flow
                features = self.flow_aggregator.extract_features(flow_data)

                prediction = None
                if self.predictor:
                    # REALTIME MONITORING: Use ONLY XGBoost for speed
                    if hasattr(self.predictor, 'models') and 'XGBoost' in self.predictor.models:
                        # Direct XGBoost prediction (fast) using the new binary classification
                        import numpy as np
                        
                        # Get feature names from predictor and build ordered feature array
                        feature_names = self.predictor.feature_names
                        ordered_features = np.array([[features.get(fname, 0.0) for fname in feature_names]])
                        
                        # Apply scaling if a valid scaler is available
                        if self.predictor.scaler is not None and hasattr(self.predictor.scaler, 'transform'):
                            scaled_features = self.predictor.scaler.transform(ordered_features)
                        else:
                            # No scaler or invalid scaler - use raw features
                            scaled_features = ordered_features

                        # Predict with XGBoost only
                        xgb_model = self.predictor.models['XGBoost']
                        pred_class = xgb_model.predict(scaled_features)[0]
                        pred_proba = xgb_model.predict_proba(scaled_features)[0]

                        # Binary classification: 0 = Normal, 1 = Malicious
                        # Get threshold from predictor if available (0-100 scale)
                        threshold = getattr(self.predictor, 'threshold', 50.0)
                        malicious_prob = float(pred_proba[1]) * 100.0  # Probability of malicious class (0-100)
                        safe_prob = float(pred_proba[0]) * 100.0  # Probability of normal class (0-100)
                        
                        # Apply threshold for final decision
                        # If malicious probability >= threshold, classify as attack
                        is_attack = malicious_prob >= threshold
                        
                        # Log threshold comparison for debugging (every 100th flow)
                        if self.total_flows % 100 == 0:
                            logger.debug(f"Threshold check: malicious_prob={malicious_prob:.2f}% >= threshold={threshold}% -> is_attack={is_attack}")
                        
                        # Classification label
                        classification = "Malicious" if is_attack else "Normal Traffic"
                        
                        # Status: SAFE or ALERT
                        status = "ALERT" if is_attack else "SAFE"
                        
                        # Confidence = certainty of the classification
                        # For Normal Traffic: show safe probability
                        # For Malicious: show malicious probability
                        confidence_score = malicious_prob if is_attack else safe_prob

                        prediction = {
                            'model_name': 'XGBoost',
                            'is_attack': is_attack,
                            'classification': classification,
                            'status': status,
                            'confidence_score': round(confidence_score, 2),
                            'threshold_used': threshold
                        }
                    elif hasattr(self.predictor, 'predict'):
                        # Fallback for single-model predictors (ml_predictor.py)
                        prediction = self.predictor.predict(features)

                if prediction and isinstance(prediction, dict) and 'is_attack' in prediction:
                    self.total_flows += 1

                    # Enrich prediction with flow metadata
                    flow_duration_ms = int(max(flow_data.last_seen - flow_data.start_time, 0) * 1000)

                    prediction.update({
                        'src_ip': flow_data.src_ip,
                        'dst_ip': flow_data.dst_ip,
                        'src_port': flow_data.src_port,
                        'dst_port': flow_data.dst_port,
                        'protocol': self._get_protocol_name(flow_data.protocol),
                        'protocol_num': flow_data.protocol,
                        'in_bytes': flow_data.fwd_bytes,
                        'out_bytes': flow_data.bwd_bytes,
                        'in_pkts': flow_data.fwd_packets,
                        'out_pkts': flow_data.bwd_packets,
                        'flow_duration_ms': flow_duration_ms,
                        'timestamp': flow_data.last_seen
                    })

                    # Log prediction with new format
                    status = prediction.get('status', 'UNKNOWN')
                    classification = prediction.get('classification', 'Unknown')
                    model_name = prediction.get('model_name', 'XGBoost')
                    logger.debug(
                        f"[{model_name}] Flow: {status} - {classification} - "
                        f"{prediction.get('src_ip')}:{prediction.get('src_port')} → "
                        f"{prediction.get('dst_ip')}:{prediction.get('dst_port')} "
                        f"(confidence: {prediction.get('confidence_score')}%)"
                    )

                    # Call callback with prediction
                    if self.on_flow_callback:
                        self.on_flow_callback(prediction)

            except Exception as e:
                logger.error(f"Error predicting flow: {e}", exc_info=True)

    def _get_protocol_name(self, protocol_num):
        """Convert protocol number to name."""
        protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
        }
        return protocol_map.get(protocol_num, f'PROTO-{protocol_num}')

    def get_statistics(self) -> Dict:
        """Get current capture statistics."""
        uptime = (time.time() - self.start_time) if self.start_time else 0
        # Use EMA-based packets/sec when available
        packet_rate = float(self.ema_pps) if hasattr(self, 'ema_pps') else (self.total_packets / uptime if uptime > 0 else 0)

        flow_stats = self.flow_aggregator.get_statistics()

        return {
            'total_packets': self.total_packets,
            'total_flows': self.total_flows,
            'active_flows': flow_stats['active_flows'],
            'packets_per_second': packet_rate,
            'packet_rate_series': list(self.packet_rate_series) if hasattr(self, 'packet_rate_series') else [],
            'dropped_packets': 0,  # Scapy handles this internally
            'uptime_seconds': int(uptime)
        }
