from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO
from sniffer import PacketSniffer
from analyzer import PacketAnalyzer
from filters import PacketFilter
from exporter import PacketExporter

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='threading',
    allowUpgrades=False,          # stay on HTTP long-polling, no WebSocket upgrade
    transports=['polling']        # disable WebSocket, use only xhr-polling
)

analyzer = PacketAnalyzer()          # ML model is loaded inside here
exporter = PacketExporter(export_dir="data")

# ──────────────────────────────────────────────────────────────────────────────
# Packet callback — called by the sniffer thread for each captured packet
# ──────────────────────────────────────────────────────────────────────────────
def on_packet_captured(packet):
    """Adds packet to analyzer (runs ML prediction) then emits to frontend."""
    analyzer.add_packet(packet)
    socketio.emit('new_packet',   packet.to_dict())
    socketio.emit('stats_update', analyzer.get_stats())

sniffer = PacketSniffer(callback=on_packet_captured)

# ──────────────────────────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/start', methods=['POST'])
def start_capture():
    sniffer.start()
    return jsonify({"status": "success", "message": "Capture started"})

@app.route('/api/status', methods=['GET'])
def get_status():
    """Returns the current sniffer mode (real or simulation)."""
    return jsonify({
        "status": "success",
        "mode": sniffer.mode,
        "is_sniffing": sniffer.is_sniffing
    })


@app.route('/api/stop', methods=['POST'])
def stop_capture():
    sniffer.stop()
    return jsonify({"status": "success", "message": "Capture stopped"})

@app.route('/api/clear', methods=['POST'])
def clear_data():
    analyzer.clear()
    socketio.emit('stats_update', analyzer.get_stats())
    return jsonify({"status": "success", "message": "Data cleared"})

@app.route('/api/export', methods=['POST'])
def export_data():
    filepath = exporter.export_to_csv(analyzer.packets)
    if filepath:
        return jsonify({"status": "success", "message": f"Exported to {filepath}"})
    return jsonify({"status": "error", "message": "No packets to export"}), 400

@app.route('/api/filter', methods=['POST'])
def filter_data():
    data       = request.json
    protocol   = data.get('protocol')
    ip         = data.get('ip')
    prediction = data.get('prediction')   # NEW: filter by ML label

    filtered = PacketFilter.filter_packets(
        analyzer.packets,
        protocol_filter=protocol,
        ip_filter=ip,
        prediction_filter=prediction
    )
    return jsonify([p.to_dict() for p in filtered])

# ──────────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    socketio.run(app, host='127.0.0.1', port=5000, debug=False, allow_unsafe_werkzeug=True)
