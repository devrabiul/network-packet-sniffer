You are a senior full-stack developer.

Build a project called "Network Packet Sniffer Web Dashboard" that captures and visualizes network packets in real time using a web-based interface.

⚠️ Tech Stack:

* Backend: Python (Flask)
* Packet Capture: scapy
* Frontend: HTML, CSS, JavaScript
* Real-time updates: WebSockets (Flask-SocketIO)
* Charts: Chart.js
* Data export: pandas (CSV)

📁 Project Structure:

NetworkPacketSnifferWeb/
│
├── app.py                # Flask app (entry point)
├── sniffer.py            # Packet capture logic
├── analyzer.py           # Packet analysis & stats
├── filters.py            # Filtering logic
├── exporter.py           # CSV export
├── models.py             # Packet data model
│
├── templates/
│   └── index.html        # Main dashboard UI
│
├── static/
│   ├── style.css
│   └── script.js
│
├── requirements.txt
└── data/packets_log.csv

---

🔹 Features:

1. Real-time packet capture using scapy
2. Backend sends packet data via WebSockets
3. Frontend dashboard shows:

   * Live packet table
   * Protocol distribution chart (Chart.js)
   * Packet count stats
4. Filter packets by:

   * Protocol (TCP, UDP, ICMP)
   * IP address
5. Buttons:

   * Start capture
   * Stop capture
   * Export CSV
6. Export packet data using pandas

---

⚙️ Behavior:

* Use threading for packet sniffing
* Emit live packet data via Socket.IO
* Update frontend dynamically without page reload
* Keep UI responsive and clean

---

📦 requirements.txt:

* flask
* flask-socketio
* scapy
* pandas

---

🎯 Output:

* Generate complete working backend + frontend
* Include HTML, CSS, JS
* No pseudo-code
* Ensure project runs with: python app.py

---

💡 Bonus:

* Add colored protocol labels (TCP=blue, UDP=green, ICMP=red)
* Auto-scroll packet table
* Show live packet counter
