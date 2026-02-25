"""
PCAP file analysis using Scapy and custom flow aggregator.
Analyzes uploaded PCAP files and generates threat reports.
NO NFSTREAM DEPENDENCIES - Pure Scapy implementation!
"""

import logging
import time
import warnings
import gc

# Suppress sklearn warnings about feature names
warnings.filterwarnings('ignore', message='X does not have valid feature names')

from pathlib import Path
from typing import Dict, List
import sys

# Add models directory to path (now relative to app/core/capture/)
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / 'models'))

from scapy.all import rdpcap, PcapReader, IP, TCP, UDP

# Import our custom flow aggregator from /models
from flow_aggregator import FlowAggregator
from ml_predictor import MLPredictor as ScapyMLPredictor


logger = logging.getLogger(__name__)


class ScapyPcapAnalyzer:
    """
    Analyze PCAP files using Scapy and custom flow aggregation.
    Supports both single model and multi-model prediction.
    """

    def __init__(self, predictor=None, multi_predictor=None):
        """
        Initialize PCAP analyzer.

        Args:
            predictor: Single model predictor for basic analysis
            multi_predictor: Multi-model predictor for comparison (optional)
        """
        self.predictor = predictor
        self.multi_predictor = multi_predictor

    def analyze_pcap(self, pcap_path: Path, use_multi_model: bool = False) -> Dict:
        """
        Analyze PCAP file and return detailed results.

        Args:
            pcap_path: Path to PCAP file
            use_multi_model: If True, compare predictions from multiple models

        Returns:
            Dictionary containing analysis results
        """
        logger.info(f"Analyzing PCAP file: {pcap_path}")

        # Ensure predictors are loaded (support both single + multi model objects)
        if self.predictor and hasattr(self.predictor, 'is_loaded') and not self.predictor.is_loaded:
            logger.info("Loading ML models...")
            if hasattr(self.predictor, 'load_all_models'):
                self.predictor.load_all_models()
            elif hasattr(self.predictor, 'load_models'):
                self.predictor.load_models()

        if self.multi_predictor and hasattr(self.multi_predictor, 'is_loaded') and not self.multi_predictor.is_loaded:
            logger.info("Loading multi-model predictors...")
            self.multi_predictor.load_all_models()

        try:
            # Initialize flow aggregator
            flow_aggregator = FlowAggregator(
                flow_timeout=120.0,  # 2 minute timeout for PCAP analysis
                max_flows=1000000    # Allow more flows for PCAP analysis
            )

            # Read and process PCAP file using streaming for efficiency
            logger.info(f"Reading and processing PCAP file...")
            start_read = time.time()
            total_packet_count = 0
            ip_packet_count = 0
            
            # Use PcapReader for streaming (more memory efficient)
            try:
                with PcapReader(str(pcap_path)) as reader:
                    for packet in reader:
                        total_packet_count += 1
                        if IP in packet:
                            flow_aggregator.add_packet(packet)
                            ip_packet_count += 1
                        # Log progress every 10000 packets
                        if total_packet_count % 10000 == 0:
                            logger.debug(f"Processed {total_packet_count} packets...")
            except Exception as e:
                # Fallback to rdpcap for small files or if streaming fails
                logger.debug(f"Streaming failed, using rdpcap: {e}")
                packets = rdpcap(str(pcap_path))
                total_packet_count = len(packets)
                for packet in packets:
                    if IP in packet:
                        flow_aggregator.add_packet(packet)
                        ip_packet_count += 1
                del packets
                gc.collect()
            
            read_time = time.time() - start_read
            logger.info(f"Processed {total_packet_count} packets in {read_time:.2f} seconds")

            # Get all flows (flush everything)
            all_flows = flow_aggregator.cleanup_all_flows()
            logger.info(f"Aggregated {len(all_flows)} flows from {ip_packet_count} IP packets")

            # Initialize results structure
            results = {
                'file_name': pcap_path.name,
                'file_size': f"{pcap_path.stat().st_size / (1024*1024):.2f} MB",
                'total_flows': len(all_flows),
                'total_packets': total_packet_count,
                'ip_packets': ip_packet_count,
                'benign_count': 0,
                'attack_count': 0,
                'total_bytes': 0,
                'duration_seconds': 0,
                'attacks': [],
                'benign_flows': [],
                'attack_summary': {},
                'top_sources': {},
                'top_destinations': {},
                'protocol_distribution': {},
                'read_time_seconds': round(read_time, 2),
                'analysis_start': time.time()
            }

            # Track first and last timestamps
            first_seen = None
            last_seen = None

            # For multi-model comparison
            if use_multi_model and self.multi_predictor:
                results['models'] = {}
                model_agg = {}
                for name in ['XGBoost', 'RandomForest', 'KNN']:
                    model_agg[name] = {
                        'model_name': name,
                        'attack_count': 0,
                        'benign_count': 0,
                        'total_flows': 0,
                        'confidence_sum': 0.0
                    }

            # OPTIMIZED: Extract all features first, then batch predict
            logger.info("Extracting features from all flows...")
            features_list = []
            flow_metadata = []  # Store flow data for later processing
            
            for idx, flow_data in enumerate(all_flows):
                try:
                    # Update duration tracking
                    if first_seen is None or flow_data.start_time < first_seen:
                        first_seen = flow_data.start_time
                    if last_seen is None or flow_data.last_seen > last_seen:
                        last_seen = flow_data.last_seen
                    
                    # Extract features
                    features = flow_aggregator.extract_features(flow_data)
                    features_list.append(features)
                    
                    # Store metadata for later
                    protocol_name = self._get_protocol_name(flow_data.protocol)
                    flow_metadata.append({
                        'idx': idx,
                        'flow_data': flow_data,
                        'protocol_name': protocol_name
                    })
                    
                    # Update stats
                    results['total_bytes'] += flow_data.in_bytes + flow_data.out_bytes
                    results['protocol_distribution'][protocol_name] = \
                        results['protocol_distribution'].get(protocol_name, 0) + 1
                        
                except Exception as e:
                    logger.error(f"Error extracting features for flow {idx}: {e}")
                    continue
            
            # BATCH PREDICTION - Much faster than individual predictions
            logger.info(f"Making batch predictions for {len(features_list)} flows...")
            predictor_to_use = self.multi_predictor or self.predictor
            all_predictions_batch = []
            
            if predictor_to_use and hasattr(predictor_to_use, 'predict_batch'):
                # Use fast batch prediction
                batch_size = 1000  # Process in chunks to manage memory
                for i in range(0, len(features_list), batch_size):
                    batch = features_list[i:i+batch_size]
                    batch_results = predictor_to_use.predict_batch(batch)
                    all_predictions_batch.extend(batch_results)
                    if (i + batch_size) % 5000 == 0:
                        logger.debug(f"Batch predicted {min(i + batch_size, len(features_list))}/{len(features_list)} flows")
            elif predictor_to_use and hasattr(predictor_to_use, 'predict_all_models'):
                # Fallback to individual predictions (slower)
                logger.warning("Using individual predictions (slower). Consider updating predictor.")
                for features in features_list:
                    all_predictions_batch.append(predictor_to_use.predict_all_models(features))
            else:
                all_predictions_batch = [{} for _ in features_list]
            
            # Process prediction results
            logger.info("Processing prediction results...")
            for i, (meta, all_predictions) in enumerate(zip(flow_metadata, all_predictions_batch)):
                try:
                    idx = meta['idx']
                    flow_data = meta['flow_data']
                    protocol_name = meta['protocol_name']
                    
                    # Track stats for each model
                    if use_multi_model:
                        for model_name, pred in all_predictions.items():
                            if 'error' not in pred:
                                stats = model_agg[model_name]
                                stats['total_flows'] += 1
                                if pred['is_attack']:
                                    stats['attack_count'] += 1
                                else:
                                    stats['benign_count'] += 1
                                stats['confidence_sum'] += pred['confidence_score']

                    # Use XGBoost prediction as primary
                    prediction = all_predictions.get('XGBoost', {})
                    if not prediction:
                        for pred in all_predictions.values():
                            if isinstance(pred, dict) and pred.get('is_attack') is not None:
                                prediction = pred
                                break

                    if not prediction or 'is_attack' not in prediction:
                        continue

                    # Build flow record
                    flow_record = {
                        'flow_id': idx + 1,
                        'src_ip': flow_data.src_ip,
                        'dst_ip': flow_data.dst_ip,
                        'src_port': flow_data.src_port,
                        'dst_port': flow_data.dst_port,
                        'protocol': protocol_name,
                        'in_bytes': flow_data.in_bytes,
                        'out_bytes': flow_data.out_bytes,
                        'in_pkts': flow_data.in_pkts,
                        'out_pkts': flow_data.out_pkts,
                        'duration': max(flow_data.last_seen - flow_data.start_time, 0),
                        'timestamp': flow_data.start_time,
                        'is_attack': prediction['is_attack'],
                        'attack_type': prediction.get('attack_type', 'Unknown'),
                        'confidence': prediction.get('confidence_score', 0),
                        'severity': prediction.get('severity', 'UNKNOWN')
                    }

                    # Categorize flow
                    if prediction['is_attack']:
                        results['attack_count'] += 1
                        results['attacks'].append(flow_record)

                        # Update attack summary
                        attack_type = prediction.get('attack_type', 'Unknown')
                        if attack_type not in results['attack_summary']:
                            results['attack_summary'][attack_type] = {
                                'count': 0,
                                'total_bytes': 0,
                                'sources': set(),
                                'destinations': set()
                            }

                        summary = results['attack_summary'][attack_type]
                        summary['count'] += 1
                        summary['total_bytes'] += flow_data.in_bytes + flow_data.out_bytes
                        summary['sources'].add(flow_data.src_ip)
                        summary['destinations'].add(flow_data.dst_ip)

                        # Track top sources/destinations for attacks
                        results['top_sources'][flow_data.src_ip] = \
                            results['top_sources'].get(flow_data.src_ip, 0) + 1
                        results['top_destinations'][flow_data.dst_ip] = \
                            results['top_destinations'].get(flow_data.dst_ip, 0) + 1

                    else:
                        results['benign_count'] += 1
                        # Only store first 100 benign flows to save memory
                        if len(results['benign_flows']) < 100:
                            results['benign_flows'].append(flow_record)

                except Exception as e:
                    logger.error(f"Error processing prediction result {i}: {e}")
                    continue

            # Finalize duration
            if first_seen and last_seen:
                results['duration_seconds'] = round(last_seen - first_seen, 2)

            # Convert attack summary sets to counts
            for attack_type in results['attack_summary']:
                summary = results['attack_summary'][attack_type]
                summary['unique_sources'] = len(summary['sources'])
                summary['unique_destinations'] = len(summary['destinations'])
                del summary['sources']
                del summary['destinations']

            # Sort top sources and destinations
            results['top_sources'] = dict(
                sorted(results['top_sources'].items(), key=lambda x: x[1], reverse=True)[:10]
            )
            results['top_destinations'] = dict(
                sorted(results['top_destinations'].items(), key=lambda x: x[1], reverse=True)[:10]
            )

            # Add multi-model comparison if enabled
            if use_multi_model and self.multi_predictor:
                for model_name, stats in model_agg.items():
                    if stats['total_flows'] > 0:
                        avg_confidence = stats['confidence_sum'] / stats['total_flows']
                        detection_rate = (stats['attack_count'] / stats['total_flows'] * 100)

                        results['models'][model_name] = {
                            'model_name': model_name,
                            'attacks_detected': stats['attack_count'],
                            'benign_detected': stats['benign_count'],
                            'total_flows': stats['total_flows'],
                            'detection_rate': round(detection_rate, 2),
                            'avg_confidence': round(avg_confidence, 2)
                        }

            # Calculate analysis time
            analysis_time = time.time() - results['analysis_start']
            results['analysis_time_seconds'] = round(analysis_time, 2)
            del results['analysis_start']

            logger.info(
                f"PCAP analysis complete: {results['total_flows']} flows, "
                f"{results['attack_count']} attacks, {results['benign_count']} benign "
                f"(analyzed in {results['analysis_time_seconds']}s)"
            )

            # Clean up flow data from memory
            del all_flows
            import gc
            gc.collect()

            return results

        except Exception as e:
            logger.error(f"PCAP analysis failed: {e}", exc_info=True)
            return {
                'error': str(e),
                'file_name': pcap_path.name,
                'status': 'failed'
            }

    def _get_protocol_name(self, protocol_num):
        """Convert protocol number to name."""
        protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
        }
        return protocol_map.get(protocol_num, f'PROTO-{protocol_num}')
