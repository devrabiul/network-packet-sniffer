import pandas as pd
from typing import List
from models import Packet
import os

class PacketExporter:
    """Handles exporting packet data to CSV using Pandas."""
    
    def __init__(self, export_dir: str = "data", filename: str = "packets_log.csv"):
        self.export_dir = export_dir
        self.filename = filename
        self.filepath = os.path.join(self.export_dir, self.filename)

        if not os.path.exists(self.export_dir):
            os.makedirs(self.export_dir)

    def export_to_csv(self, packets: List[Packet]) -> str:
        """
        Exports the list of packets to a CSV file using pandas.
        Returns the absolute filepath of the exported file, or None if no packets.
        """
        if not packets:
            return None

        # Convert packets to a list of dictionaries
        data = [p.to_dict() for p in packets]
        
        # Create a DataFrame and save to CSV
        df = pd.DataFrame(data)
        df.to_csv(self.filepath, index=False)
        
        return os.path.abspath(self.filepath)
