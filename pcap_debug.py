import sys
import os
import dpkt
import socket
import webbrowser

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton,
    QFileDialog, QVBoxLayout, QWidget, QLabel
)

# -----------------------------
# GEOIP (SAFE OPTIONAL)
# -----------------------------
try:
    import geoip2.database
    MMDB_PATH = os.path.join("data", "GeoLite2-City.mmdb")
    geo = geoip2.database.Reader(MMDB_PATH)
    print("[INFO] GeoLite2 loaded")
except:
    geo = None
    print("[WARN] GeoIP disabled")


def ip_to_geo(ip):
    if not geo:
        return None
    try:
        r = geo.city(ip)
        return (r.location.latitude, r.location.longitude)
    except:
        return None


# -----------------------------
# DEBUG PCAP PARSER
# -----------------------------
def parse_pcap_debug(file):
    nodes = {}
    links = []

    stats = {
        "total_packets": 0,
        "ip_packets": 0,
        "geo_hits": 0,
        "valid_links": 0
    }

    with open(file, "rb") as f:
        pcap = dpkt.pcap.Reader(f)

        for _, buf in pcap:
            stats["total_packets"] += 1

            try:
                eth = dpkt.ethernet.Ethernet(buf)

                if not isinstance(eth.data, dpkt.ip.IP):
                    continue

                ip = eth.data
                stats["ip_packets"] += 1

                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)

                src_geo = ip_to_geo(src)
                dst_geo = ip_to_geo(dst)

                print(f"[IP] {src} -> {dst}")
                print(f"   SRC GEO: {src_geo}")
                print(f"   DST GEO: {dst_geo}")

                # node tracking
                nodes[src] = src_geo
                nodes[dst] = dst_geo

                # link validation
                if src_geo or dst_geo:
                    stats["valid_links"] += 1
                    links.append((src, dst, src_geo, dst_geo))

                if src_geo:
                    stats["geo_hits"] += 1
                if dst_geo:
                    stats["geo_hits"] += 1

            except:
                continue

    print("\n========== DEBUG SUMMARY ==========")
    print("Total packets:", stats["total_packets"])
    print("IP packets:", stats["ip_packets"])
    print("Geo hits:", stats["geo_hits"])
    print("Valid drawable links:", stats["valid_links"])
    print("Nodes:", len(nodes))
    print("Links:", len(links))
    print("===================================\n")

    return nodes, links, stats


# -----------------------------
# HTML MAP GENERATOR (DEBUG VIEW)
# -----------------------------
def build_map(nodes, links, stats):

    import json

    node_list = []
    link_list = []

    # fallback positions for private IPs
    base_lat = 20
    base_lon = 0

    for ip, geo in nodes.items():
        if geo:
            lat, lon = geo
        else:
            lat = base_lat + (hash(ip) % 50) * 0.2
            lon = base_lon + (hash(ip[::-1]) % 50) * 0.2

        node_list.append({
            "ip": ip,
            "lat": lat,
            "lon": lon
        })

    for src, dst, s_geo, d_geo in links:

        if not s_geo:
            s_geo = (base_lat, base_lon)
        if not d_geo:
            d_geo = (base_lat + 1, base_lon + 1)

        link_list.append({
            "src": src,
            "dst": dst,
            "s_lat": s_geo[0],
            "s_lon": s_geo[1],
            "d_lat": d_geo[0],
            "d_lon": d_geo[1]
        })

    html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>PCAP DEBUG MAP</title>

<link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>

<style>
#map {{ height: 100vh; }}
.info {{
    position: absolute;
    top: 10px;
    left: 10px;
    background: white;
    padding: 10px;
    z-index: 999;
}}
</style>
</head>

<body>

<div class="info">
<b>DEBUG INFO</b><br>
Packets: {stats['total_packets']}<br>
IP: {stats['ip_packets']}<br>
Nodes: {len(nodes)}<br>
Links: {len(links)}<br>
Geo hits: {stats['geo_hits']}<br>
Drawable links: {stats['valid_links']}
</div>

<div id="map"></div>

<script>
var map = L.map('map').setView([20,0], 2);

L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
    maxZoom: 18
}}).addTo(map);

var nodes = {json.dumps(node_list)};
var links = {json.dumps(link_list)};

// draw nodes
nodes.forEach(n => {{
    L.circleMarker([n.lat, n.lon], {{
        radius: 5
    }}).addTo(map).bindPopup(n.ip);
}});

// draw links
links.forEach(l => {{
    L.polyline([
        [l.s_lat, l.s_lon],
        [l.d_lat, l.d_lon]
    ], {{
        color: 'red',
        weight: 2
    }}).addTo(map);
}});

</script>

</body>
</html>
"""

    out = os.path.abspath("debug_map.html")

    with open(out, "w", encoding="utf-8") as f:
        f.write(html)

    return out


# -----------------------------
# UI
# -----------------------------
class App(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("PCAP DEBUG VISUALIZER")
        self.setGeometry(300, 300, 400, 200)

        self.label = QLabel("Load PCAP for debugging")

        self.btn = QPushButton("Open PCAP")
        self.btn.clicked.connect(self.load)

        layout = QVBoxLayout()
        layout.addWidget(self.label)
        layout.addWidget(self.btn)

        c = QWidget()
        c.setLayout(layout)
        self.setCentralWidget(c)

    def load(self):
        file, _ = QFileDialog.getOpenFileName(self, "PCAP", "", "PCAP (*.pcap *.cap)")
        if not file:
            return

        self.label.setText("Processing...")

        nodes, links, stats = parse_pcap_debug(file)

        html = build_map(nodes, links, stats)

        webbrowser.open("file://" + html)

        self.label.setText("Done")


# -----------------------------
# RUN
# -----------------------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = App()
    w.show()
    sys.exit(app.exec_())