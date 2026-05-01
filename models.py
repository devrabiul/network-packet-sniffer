from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class Packet:
    """Data model representing a captured network packet."""
    src_ip: str
    dst_ip: str
    protocol: str
    size: int
    timestamp: float
    prediction: str = "Unknown"
    prediction_reason: str = ""

    def to_dict(self):
        """Converts packet to a dictionary for JSON serialization."""
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "size": self.size,
            "timestamp": datetime.fromtimestamp(self.timestamp).strftime('%Y-%m-%d %H:%M:%S'),
            "prediction": self.prediction,
            "prediction_reason": self.prediction_reason,
        }
