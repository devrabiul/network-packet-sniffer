from typing import List, Dict
from models import Packet
import ml_model

class PacketAnalyzer:
    """Maintains state and statistics of captured packets, including ML predictions."""

    def __init__(self):
        self.packets: List[Packet] = []
        self.protocol_counts: Dict[str, int] = {
            "TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0
        }
        self.prediction_counts: Dict[str, int] = {
            "Normal": 0, "Suspicious": 0
        }
        self.total_packets: int = 0

        # Load ML model at startup
        print("[Analyzer] Loading ML model …")
        self.clf = ml_model.load_model()
        print("[Analyzer] ML model ready.")

    def add_packet(self, packet: Packet):
        """Adds a packet, runs ML prediction, and updates statistics."""
        # ── ML Prediction ──────────────────────────────────────────────────────
        result = ml_model.predict_packet(self.clf, packet)
        packet.prediction = result["prediction"]
        packet.prediction_reason = result["reason"]

        # ── Store and count ────────────────────────────────────────────────────
        self.packets.append(packet)
        self.total_packets += 1

        protocol = packet.protocol
        if protocol in self.protocol_counts:
            self.protocol_counts[protocol] += 1
        else:
            self.protocol_counts["Other"] += 1

        if packet.prediction in self.prediction_counts:
            self.prediction_counts[packet.prediction] += 1

    def get_stats(self) -> dict:
        """Returns current packet and ML statistics."""
        return {
            "total_packets": self.total_packets,
            "protocols": self.protocol_counts,
            "predictions": self.prediction_counts,
        }

    def clear(self):
        """Clears all stored packets and resets all stats."""
        self.packets.clear()
        self.protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        self.prediction_counts = {"Normal": 0, "Suspicious": 0}
        self.total_packets = 0
