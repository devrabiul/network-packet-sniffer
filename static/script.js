/**
 * script.js — Frontend logic for the Network Packet Sniffer ML Dashboard.
 * Handles WebSocket events, real-time table updates, filtering, and Chart.js charts.
 */

document.addEventListener('DOMContentLoaded', () => {
    // ── Socket.IO ─────────────────────────────────────────────────────────────
    // Force polling transport — Werkzeug doesn't support WebSocket upgrades
    const socket = io({ transports: ['polling'] });

    // ── DOM Elements ─────────────────────────────────────────────────────────
    const btnStart      = document.getElementById('btn-start');
    const btnStop       = document.getElementById('btn-stop');
    const btnClear      = document.getElementById('btn-clear');
    const btnExport     = document.getElementById('btn-export');
    const btnFilter     = document.getElementById('btn-apply-filter');
    const statusMsg     = document.getElementById('status-msg');

    const filterProto  = document.getElementById('filter-protocol');
    const filterIp     = document.getElementById('filter-ip');
    const filterPred   = document.getElementById('filter-prediction');

    const tableBody      = document.getElementById('packets-tbody');
    const tableScroll    = document.getElementById('table-scroll');

    const totalEl        = document.getElementById('total-packets');
    const normalEl       = document.getElementById('normal-count');
    const suspiciousEl   = document.getElementById('suspicious-count');

    let autoScroll = true;

    // ── Chart.js — Protocol Doughnut ─────────────────────────────────────────
    const protocolChart = new Chart(
        document.getElementById('protocolChart').getContext('2d'),
        {
            type: 'doughnut',
            data: {
                labels: ['TCP', 'UDP', 'ICMP', 'Other'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: ['#3b82f6', '#22c55e', '#f97316', '#6b7280'],
                    borderWidth: 1,
                    borderColor: '#22263a'
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { labels: { color: '#e2e8f0', boxWidth: 12, padding: 8 } },
                    title: { display: false }
                }
            }
        }
    );

    // ── Chart.js — Threat Ratio Pie ──────────────────────────────────────────
    const threatChart = new Chart(
        document.getElementById('threatChart').getContext('2d'),
        {
            type: 'pie',
            data: {
                labels: ['Normal', 'Suspicious'],
                datasets: [{
                    data: [0, 0],
                    backgroundColor: ['#22c55e', '#ef4444'],
                    borderWidth: 1,
                    borderColor: '#22263a'
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { labels: { color: '#e2e8f0', boxWidth: 12, padding: 8 } },
                    title: { display: false }
                }
            }
        }
    );

    // ── Helpers ───────────────────────────────────────────────────────────────
    /**
     * Builds one table row from a packet data object and appends it to tbody.
     */
    function addPacketRow(p) {
        const protoBadge = `badge-${p.protocol.toLowerCase()}`;
        const predBadge  = p.prediction === 'Suspicious' ? 'badge-suspicious' : 'badge-normal';
        const rowClass   = p.prediction === 'Suspicious' ? 'row-suspicious' : '';

        const tr = document.createElement('tr');
        if (rowClass) tr.classList.add(rowClass);

        tr.innerHTML = `
            <td>${p.timestamp}</td>
            <td>${p.src_ip}</td>
            <td>${p.dst_ip}</td>
            <td><span class="badge ${protoBadge}">${p.protocol}</span></td>
            <td>${p.size}</td>
            <td>
                <span class="badge ${predBadge}"
                      title="${p.prediction_reason || p.prediction}">
                    ${p.prediction}
                </span>
            </td>`;

        tableBody.appendChild(tr);

        if (autoScroll) {
            tableScroll.scrollTop = tableScroll.scrollHeight;
        }
    }

    /** Update both charts and all stat counters. */
    function updateStats(stats) {
        totalEl.textContent      = stats.total_packets;
        normalEl.textContent     = stats.predictions?.Normal     ?? 0;
        suspiciousEl.textContent = stats.predictions?.Suspicious ?? 0;

        protocolChart.data.datasets[0].data = [
            stats.protocols.TCP   || 0,
            stats.protocols.UDP   || 0,
            stats.protocols.ICMP  || 0,
            stats.protocols.Other || 0,
        ];
        protocolChart.update();

        threatChart.data.datasets[0].data = [
            stats.predictions?.Normal     || 0,
            stats.predictions?.Suspicious || 0,
        ];
        threatChart.update();
    }

    // ── Auto-scroll pause when user scrolls up ────────────────────────────────
    tableScroll.addEventListener('scroll', () => {
        const atBottom = tableScroll.scrollHeight - tableScroll.scrollTop
                         <= tableScroll.clientHeight + 15;
        autoScroll = atBottom;
    });

    // ── Socket Events ─────────────────────────────────────────────────────────
    socket.on('new_packet', (packet) => {
        const protoF = filterProto.value;
        const ipF    = filterIp.value.trim().toLowerCase();
        const predF  = filterPred.value;

        // Apply live filter
        if (protoF !== 'ALL' && packet.protocol !== protoF) return;
        if (ipF && !packet.src_ip.includes(ipF) && !packet.dst_ip.includes(ipF)) return;
        if (predF !== 'ALL' && packet.prediction !== predF) return;

        addPacketRow(packet);
    });

    socket.on('stats_update', updateStats);

    // ── Button Actions ────────────────────────────────────────────────────────
    const modeBadge = document.getElementById('mode-badge');

    function updateModeBadge() {
        fetch('/api/status').then(r => r.json()).then(d => {
            modeBadge.className = 'mode-badge';
            if (d.mode === 'real') {
                modeBadge.textContent = '🟢 Live Capture';
                modeBadge.classList.add('real');
            } else if (d.mode === 'simulation') {
                modeBadge.textContent = '🟡 Simulation Mode';
                modeBadge.classList.add('simulation');
            }
        });
    }

    btnStart.addEventListener('click', () => {
        fetch('/api/start', { method: 'POST' }).then(r => r.json()).then(d => {
            if (d.status === 'success') {
                btnStart.disabled = true;
                btnStop.disabled  = false;
                statusMsg.textContent = '● Capturing…';
                statusMsg.style.color = '#22c55e';
                // Poll mode after short delay (sniffer needs a moment to detect admin rights)
                setTimeout(updateModeBadge, 1200);
            }
        });
    });

    btnStop.addEventListener('click', () => {
        fetch('/api/stop', { method: 'POST' }).then(r => r.json()).then(d => {
            if (d.status === 'success') {
                btnStart.disabled = false;
                btnStop.disabled  = true;
                statusMsg.textContent = 'Stopped';
                statusMsg.style.color = '#ef4444';
            }
        });
    });

    btnClear.addEventListener('click', () => {
        fetch('/api/clear', { method: 'POST' }).then(r => r.json()).then(d => {
            if (d.status === 'success') {
                tableBody.innerHTML = '';
                statusMsg.textContent = 'Data cleared';
                statusMsg.style.color = '#f59e0b';
            }
        });
    });

    btnExport.addEventListener('click', () => {
        fetch('/api/export', { method: 'POST' })
            .then(r => r.json())
            .then(d => {
                if (d.status === 'success') {
                    alert('✅ Export successful!\n' + d.message);
                } else {
                    alert('⚠️ Nothing to export yet.\nPlease click "▶ Start Capture" first and wait for packets to appear.');
                }
            })
            .catch(() => alert('❌ Export request failed.'));
    });

    btnFilter.addEventListener('click', () => {
        fetch('/api/filter', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                protocol:   filterProto.value,
                ip:         filterIp.value,
                prediction: filterPred.value,
            })
        })
        .then(r => r.json())
        .then(packets => {
            tableBody.innerHTML = '';
            packets.forEach(addPacketRow);
        });
    });
});
