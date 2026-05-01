from typing import List
from models import Packet

class PacketFilter:
    """Handles filtering of packets based on protocol, IP, and ML prediction."""

    @staticmethod
    def filter_packets(
        packets: List[Packet],
        protocol_filter: str = None,
        ip_filter: str = None,
        prediction_filter: str = None
    ) -> List[Packet]:
        """
        Filters packets by protocol, IP address, and/or ML prediction label.
        """
        filtered = packets

        if protocol_filter and protocol_filter.upper() != "ALL":
            filtered = [p for p in filtered if p.protocol.upper() == protocol_filter.upper()]

        if ip_filter:
            filtered = [p for p in filtered if ip_filter in p.src_ip or ip_filter in p.dst_ip]

        if prediction_filter and prediction_filter.upper() != "ALL":
            filtered = [p for p in filtered if p.prediction == prediction_filter]

        return filtered
