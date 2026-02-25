"""
Flow aggregation for the 21-feature CICIDS2017 binary classification pipeline.
Tracks bidirectional flows with normalized 5-tuples and maintains
per-direction statistics for the new feature set.

NEW 21 FEATURES FROM CICIDS2017:
- Flow-based: Flow Duration, Flow Bytes/s, Flow Packets/s, Destination Port
- Forward packet: Total Fwd Packets, Total Length of Fwd Packets, Fwd Packet Length Mean/Max/Std, Fwd Packets/s
- Backward packet: Bwd Packet Length Mean/Max, Bwd Packets/s
- Timing: Flow IAT Mean, Fwd IAT Mean
- TCP Flags: PSH Flag Count, ACK Flag Count, FIN Flag Count
- Window: Init_Win_bytes_forward, Init_Win_bytes_backward
"""

from __future__ import annotations

import math
import time
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from scapy.layers.inet import IP, TCP, UDP, ICMP

import logging
logger = logging.getLogger(__name__)

FlowKey = Tuple[str, str, int, int, int]


class RunningStats:
    """Incremental mean/stddev tracker for packet lengths and inter-arrival times."""

    def __init__(self) -> None:
        self.count = 0
        self.mean = 0.0
        self.m2 = 0.0
        self.min: Optional[float] = None
        self.max: Optional[float] = None
        self.total = 0.0

    def update(self, value: float) -> None:
        if value is None:
            return
        self.count += 1
        self.total += value
        if self.min is None or value < self.min:
            self.min = value
        if self.max is None or value > self.max:
            self.max = value

        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2

    def get_mean(self) -> float:
        return self.mean if self.count > 0 else 0.0

    def get_max(self) -> float:
        return float(self.max) if self.max is not None else 0.0

    def get_std(self) -> float:
        if self.count < 2:
            return 0.0
        variance = self.m2 / (self.count - 1)
        return math.sqrt(variance) if variance > 0 else 0.0

    def get_total(self) -> float:
        return self.total

    def stats(self) -> Tuple[float, float, float, float]:
        """Legacy compatibility method."""
        return (
            float(self.min) if self.min is not None else 0.0,
            self.get_max(),
            self.get_mean(),
            self.get_std(),
        )


@dataclass
class FlowData:
    """Data structure for a single network flow with 21-feature support."""
    key: FlowKey
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    start_time: float
    last_seen: float
    packet_count: int = 0
    
    # Forward (src -> dst) metrics
    fwd_packets: int = 0
    fwd_bytes: int = 0
    fwd_packet_lengths: RunningStats = field(default_factory=RunningStats)
    fwd_iat: RunningStats = field(default_factory=RunningStats)
    last_fwd_time: Optional[float] = None
    init_win_fwd: Optional[int] = None
    
    # Backward (dst -> src) metrics
    bwd_packets: int = 0
    bwd_bytes: int = 0
    bwd_packet_lengths: RunningStats = field(default_factory=RunningStats)
    bwd_iat: RunningStats = field(default_factory=RunningStats)
    last_bwd_time: Optional[float] = None
    init_win_bwd: Optional[int] = None
    
    # Flow-level IAT tracking
    flow_iat: RunningStats = field(default_factory=RunningStats)
    last_packet_time: Optional[float] = None
    
    # TCP flag counts
    psh_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    
    # Convenience attributes for compatibility
    in_bytes: int = 0
    out_bytes: int = 0
    in_pkts: int = 0
    out_pkts: int = 0

    def __getitem__(self, item: str):
        return getattr(self, item)

    def get(self, item: str, default=None):
        return getattr(self, item, default)

    def to_dict(self) -> Dict[str, object]:
        duration = max(self.last_seen - self.start_time, 0.0)
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "packet_count": self.packet_count,
            "flow_duration": duration,
            "in_bytes": self.in_bytes,
            "out_bytes": self.out_bytes,
            "in_pkts": self.in_pkts,
            "out_pkts": self.out_pkts,
            "timestamp": self.last_seen,
        }


class FlowAggregator:
    """
    Maintains active bidirectional flows keyed by normalized 5-tuples.
    Extracts 21 CICIDS2017 features for ML prediction.
    """

    # The 21 features expected by the model
    FEATURE_NAMES = [
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

    def __init__(self, flow_timeout: float = 2.0, max_flows: int = 100000):
        self.flow_timeout = flow_timeout
        self.max_flows = max_flows
        self.flows: Dict[FlowKey, FlowData] = {}
        self.lock = threading.Lock()
        self.total_packets = 0
        self.total_flows = 0

    def get_flow_key(
        self, packet
    ) -> Optional[Tuple[FlowKey, str, str, int, int, int]]:
        """Create normalized 5-tuple for bidirectional flows."""
        try:
            if IP not in packet:
                return None

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = int(packet[IP].proto)

            src_port = (
                int(packet[TCP].sport)
                if TCP in packet
                else int(packet[UDP].sport)
                if UDP in packet
                else 0
            )
            dst_port = (
                int(packet[TCP].dport)
                if TCP in packet
                else int(packet[UDP].dport)
                if UDP in packet
                else 0
            )

            # Normalize flow key for bidirectional matching
            if (src_ip, src_port) <= (dst_ip, dst_port):
                flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
            else:
                flow_key = (dst_ip, src_ip, dst_port, src_port, protocol)

            return flow_key, src_ip, dst_ip, src_port, dst_port, protocol
        except Exception as exc:
            logger.error(f"Failed to build flow key: {exc}")
            return None

    def add_packet(self, packet) -> None:
        """Add packet to a flow and update all tracked metrics."""
        key_info = self.get_flow_key(packet)
        if key_info is None:
            return

        flow_key, src_ip, dst_ip, src_port, dst_port, protocol = key_info
        now = float(getattr(packet, "time", time.time()))

        with self.lock:
            flow = self.flows.get(flow_key)

            if flow is None:
                if len(self.flows) >= self.max_flows:
                    self._evict_oldest()

                flow = FlowData(
                    key=flow_key,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    start_time=now,
                    last_seen=now,
                )
                self.flows[flow_key] = flow
                self.total_flows += 1

            self._update_flow(flow, packet, now, src_ip, dst_ip, src_port, dst_port)
            self.total_packets += 1

    def _update_flow(
        self,
        flow: FlowData,
        packet,
        now: float,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
    ) -> None:
        """Update per-packet metrics for a tracked flow."""
        flow.packet_count += 1
        flow.last_seen = now

        pkt_len = int(len(packet[IP]))

        # Update flow-level IAT
        if flow.last_packet_time is not None:
            iat = (now - flow.last_packet_time) * 1000000  # microseconds
            flow.flow_iat.update(iat)
        flow.last_packet_time = now

        # Determine direction: forward = original src->dst, backward = reverse
        is_forward = (src_ip == flow.src_ip and src_port == flow.src_port)

        if is_forward:
            # Forward packet
            flow.fwd_packets += 1
            flow.fwd_bytes += pkt_len
            flow.out_pkts += 1
            flow.out_bytes += pkt_len
            flow.fwd_packet_lengths.update(pkt_len)
            
            # Fwd IAT
            if flow.last_fwd_time is not None:
                fwd_iat = (now - flow.last_fwd_time) * 1000000  # microseconds
                flow.fwd_iat.update(fwd_iat)
            flow.last_fwd_time = now
            
            # Capture initial window size (first forward packet with TCP)
            if TCP in packet and flow.init_win_fwd is None:
                try:
                    flow.init_win_fwd = int(packet[TCP].window)
                except:
                    flow.init_win_fwd = 0
        else:
            # Backward packet
            flow.bwd_packets += 1
            flow.bwd_bytes += pkt_len
            flow.in_pkts += 1
            flow.in_bytes += pkt_len
            flow.bwd_packet_lengths.update(pkt_len)
            
            # Bwd IAT
            if flow.last_bwd_time is not None:
                bwd_iat = (now - flow.last_bwd_time) * 1000000  # microseconds
                flow.bwd_iat.update(bwd_iat)
            flow.last_bwd_time = now
            
            # Capture initial window size (first backward packet with TCP)
            if TCP in packet and flow.init_win_bwd is None:
                try:
                    flow.init_win_bwd = int(packet[TCP].window)
                except:
                    flow.init_win_bwd = 0

        # TCP flag counting
        if TCP in packet:
            flags = int(packet[TCP].flags)
            # PSH flag = 0x08
            if flags & 0x08:
                flow.psh_count += 1
            # ACK flag = 0x10
            if flags & 0x10:
                flow.ack_count += 1
            # FIN flag = 0x01
            if flags & 0x01:
                flow.fin_count += 1

    def extract_features(self, flow_data: FlowData) -> Dict[str, float]:
        """
        Convert FlowData into the 21-feature dict expected by the CICIDS2017 model.
        
        Feature names match exactly what the model was trained on.
        """
        # Calculate flow duration in microseconds
        flow_duration_us = max(flow_data.last_seen - flow_data.start_time, 0.0) * 1000000
        flow_duration_s = flow_duration_us / 1000000 if flow_duration_us > 0 else 0.001

        # Total bytes and packets
        total_bytes = flow_data.fwd_bytes + flow_data.bwd_bytes
        total_packets = flow_data.fwd_packets + flow_data.bwd_packets

        # Calculate rates (per second)
        flow_bytes_per_s = total_bytes / flow_duration_s if flow_duration_s > 0 else 0.0
        flow_packets_per_s = total_packets / flow_duration_s if flow_duration_s > 0 else 0.0
        fwd_packets_per_s = flow_data.fwd_packets / flow_duration_s if flow_duration_s > 0 else 0.0
        bwd_packets_per_s = flow_data.bwd_packets / flow_duration_s if flow_duration_s > 0 else 0.0

        return {
            'Flow Duration': float(flow_duration_us),
            'Flow Bytes/s': float(flow_bytes_per_s),
            'Flow Packets/s': float(flow_packets_per_s),
            'Destination Port': float(flow_data.dst_port),
            'Total Fwd Packets': float(flow_data.fwd_packets),
            'Total Length of Fwd Packets': float(flow_data.fwd_bytes),
            'Fwd Packet Length Mean': float(flow_data.fwd_packet_lengths.get_mean()),
            'Fwd Packet Length Max': float(flow_data.fwd_packet_lengths.get_max()),
            'Fwd Packet Length Std': float(flow_data.fwd_packet_lengths.get_std()),
            'Fwd Packets/s': float(fwd_packets_per_s),
            'Bwd Packet Length Mean': float(flow_data.bwd_packet_lengths.get_mean()),
            'Bwd Packet Length Max': float(flow_data.bwd_packet_lengths.get_max()),
            'Bwd Packets/s': float(bwd_packets_per_s),
            'Flow IAT Mean': float(flow_data.flow_iat.get_mean()),
            'Fwd IAT Mean': float(flow_data.fwd_iat.get_mean()),
            'PSH Flag Count': float(flow_data.psh_count),
            'ACK Flag Count': float(flow_data.ack_count),
            'FIN Flag Count': float(flow_data.fin_count),
            'Init_Win_bytes_forward': float(flow_data.init_win_fwd or 0),
            'Init_Win_bytes_backward': float(flow_data.init_win_bwd or 0),
        }

    def get_expired_flows(self) -> List[FlowData]:
        """Return and remove flows that have exceeded the timeout."""
        now = time.time()
        expired: List[FlowData] = []

        with self.lock:
            keys_to_remove = [
                k for k, f in self.flows.items() if (now - f.last_seen) >= self.flow_timeout
            ]
            for key in keys_to_remove:
                expired.append(self.flows[key])
                del self.flows[key]

        return expired

    def cleanup_all_flows(self) -> List[FlowData]:
        """Flush and return all tracked flows (e.g., graceful shutdown)."""
        with self.lock:
            remaining = list(self.flows.values())
            self.flows.clear()
        return remaining

    def get_statistics(self) -> Dict[str, int]:
        with self.lock:
            active = len(self.flows)
        return {
            "active_flows": active,
            "total_flows": self.total_flows,
            "total_packets": self.total_packets,
        }

    # Backward compatibility wrappers
    def process_packet(self, packet) -> None:
        """Alias for legacy callers."""
        self.add_packet(packet)

    def pop_expired(self) -> List[FlowData]:
        """Alias for legacy callers."""
        return self.get_expired_flows()

    def flush_all(self) -> List[FlowData]:
        """Alias for legacy callers."""
        return self.cleanup_all_flows()

    def _evict_oldest(self) -> None:
        """Prevent unbounded growth by evicting the stalest flow."""
        if not self.flows:
            return
        oldest_key = min(self.flows.items(), key=lambda item: item[1].last_seen)[0]
        del self.flows[oldest_key]
