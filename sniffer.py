"""
sniffer.py — Network packet capture using Python raw sockets.

Strategy (Windows-compatible, no NPcap required):
  1. Try to capture real packets via Scapy L3socket (needs Admin).
  2. If that fails (no admin rights), automatically fall back to a
     realistic simulation mode so the dashboard still demonstrates
     all features (ML prediction, charts, filters, export).
"""

import socket
import struct
import time
import threading
import random
from models import Packet

# ──────────────────────────────────────────────────────────────────────────────
# Simulation helpers
# ──────────────────────────────────────────────────────────────────────────────
_SIM_SRC_IPS = [
    f"192.168.{random.randint(0,5)}.{random.randint(2,200)}" for _ in range(20)
] + [f"10.0.{random.randint(0,2)}.{random.randint(2,200)}" for _ in range(10)]

_SIM_DST_IPS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
                "208.67.222.222", "9.9.9.9", "149.112.112.112"]

_PROTOCOLS = ["TCP", "UDP", "ICMP"]


def _random_packet() -> Packet:
    """Generate a single realistic-looking simulated packet."""
    proto = random.choices(_PROTOCOLS, weights=[55, 35, 10])[0]
    # Occasionally generate a suspicious large packet
    if random.random() < 0.3:
        size = random.randint(1400, 3000)
    elif proto == "ICMP":
        size = random.randint(40, 150)
    else:
        size = random.randint(100, 1000)

    return Packet(
        src_ip=random.choice(_SIM_SRC_IPS),
        dst_ip=random.choice(_SIM_DST_IPS),
        protocol=proto,
        size=size,
        timestamp=time.time(),
    )


# ──────────────────────────────────────────────────────────────────────────────
# Real sniffer (Scapy / raw socket) — requires Admin on Windows
# ──────────────────────────────────────────────────────────────────────────────
def _try_real_sniff(packet_handler, stop_flag):
    """
    Attempt live capture via Python raw socket (IPPROTO_IP, SIO_RCVALL).
    Returns True if it ran successfully, False if it failed (no admin rights).
    """
    try:
        # Windows raw socket requires admin rights
        HOST = socket.gethostbyname(socket.gethostname())
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((HOST, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        # Enable promiscuous mode (Windows-specific SIO_RCVALL)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        s.settimeout(1.0)
        print("[Sniffer] ✅ Real capture mode active (Admin privileges detected).")
    except PermissionError:
        print("[Sniffer] ⚠️  No admin rights — switching to simulation mode.")
        return False
    except Exception as e:
        print(f"[Sniffer] ⚠️  Raw socket failed ({e}) — switching to simulation mode.")
        return False

    try:
        while not stop_flag[0]:
            try:
                raw_data = s.recv(65535)
            except socket.timeout:
                continue
            except Exception:
                break

            # Parse IP header (20 bytes minimum)
            if len(raw_data) < 20:
                continue

            iph = struct.unpack("!BBHHHBBH4s4s", raw_data[:20])
            proto_num = iph[6]
            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])
            size = len(raw_data)

            if proto_num == 6:
                protocol = "TCP"
            elif proto_num == 17:
                protocol = "UDP"
            elif proto_num == 1:
                protocol = "ICMP"
            else:
                continue  # skip non-IP-layer packets

            pkt = Packet(src_ip=src_ip, dst_ip=dst_ip,
                         protocol=protocol, size=size, timestamp=time.time())
            packet_handler(pkt)
    finally:
        try:
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            s.close()
        except Exception:
            pass

    return True


# ──────────────────────────────────────────────────────────────────────────────
# PacketSniffer — public class used by app.py
# ──────────────────────────────────────────────────────────────────────────────
class PacketSniffer:
    """
    Captures packets and passes them to a callback.
    Automatically falls back to simulation when admin rights are absent.
    """

    def __init__(self, callback):
        self.callback = callback
        self.is_sniffing = False
        self._stop_flag = [False]
        self._thread = None
        self.mode = "unknown"  # "real" or "simulation"

    # ── Internal thread targets ────────────────────────────────────────────────
    def _run(self):
        self._stop_flag = [False]
        success = _try_real_sniff(self.callback, self._stop_flag)
        if not success:
            self.mode = "simulation"
            self._simulate()

    def _simulate(self):
        """Emit realistic fake packets at ~2–5 per second."""
        print("[Sniffer] 🎮 Simulation mode running — packets are synthetic.")
        while self.is_sniffing:
            pkt = _random_packet()
            self.callback(pkt)
            time.sleep(random.uniform(0.2, 0.5))

    # ── Public API ─────────────────────────────────────────────────────────────
    def start(self):
        if not self.is_sniffing:
            self.is_sniffing = True
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
            print("[Sniffer] Started.")

    def stop(self):
        self.is_sniffing = False
        self._stop_flag[0] = True
        if self._thread:
            self._thread.join(timeout=3.0)
        print("[Sniffer] Stopped.")
