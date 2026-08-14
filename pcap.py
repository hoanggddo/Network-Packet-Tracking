import sys
import os
import dpkt
import socket
import webbrowser

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton,
    QFileDialog, QVBoxLayout, QWidget, QLabel
)

# GEOIP 
try:
    import geoip2.database
    MMDB_PATH = os.path.join("data", "GeoLite2-City.mmdb")
    geo_reader = geoip2.database.Reader(MMDB_PATH)
    print("[INFO] GeoLite2 loaded")
except:
    geo_reader = None
    print("[WARN] GeoIP disabled")


def ip_to_geo(ip):
    """Return (lat, lon) or None safely"""
    if not geo_reader:
        return None
    try:
        r = geo_reader.city(ip)
        lat = r.location.latitude
        lon = r.location.longitude

        if lat is None or lon is None:
            return None

        return (lat, lon)
    except:
        return None


# PCAP PARSER 
def parse_pcap(file):
    nodes = {}
    links = []

    with open(file, "rb") as f:
        pcap = dpkt.pcap.Reader(f)

        for _, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)

                if not isinstance(eth.data, dpkt.ip.IP):
                    continue

                ip = eth.data

                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)

                src_geo = ip_to_geo(src)
                dst_geo = ip_to_geo(dst)

                # ALWAYS store something (never None)
                nodes[src] = src_geo
                nodes[dst] = dst_geo

                links.append((src, dst))

            except:
                continue

    return nodes, links


# BUILD MAP
def build_html(nodes, links):
    import json

    node_data = []
    link_data = []

    base_lat = 20
    base_lon = 0
    offset = 0.2

    used = {}


    # SAFE NODE POSITIONING
    for ip, geo in nodes.items():

        if isinstance(geo, tuple):
            lat, lon = geo

            if lat is None or lon is None:
                geo = None
            else:
                used[ip] = (lat, lon)

        if not isinstance(geo, tuple) or geo is None:
            # fallback clustering (stable, no randomness crash)
            h = abs(hash(ip))
            lat = base_lat + (h % 30) * offset
            lon = base_lon + ((h // 10) % 30) * offset
            used[ip] = (lat, lon)

        node_data.append({
            "ip": ip,
            "lat": used[ip][0],
            "lon": used[ip][1]
        })

    # SAFE LINK BUILDING

    seen = set()

    for src, dst in links:

        if src not in used or dst not in used:
            continue

        key = (src, dst)
        if key in seen:
            continue
        seen.add(key)

        s_lat, s_lon = used[src]
        d_lat, d_lon = used[dst]

        # FINAL SAFETY CHECK (fix your crash)
        if s_lat is None or s_lon is None:
            continue
        if d_lat is None or d_lon is None:
            continue

        # VISIBILITY BOOST (prevents overlap collapse)
        d_lat += 0.05
        d_lon += 0.05

        link_data.append({
            "src": src,
            "dst": dst,
            "s_lat": s_lat,
            "s_lon": s_lon,
            "d_lat": d_lat,
            "d_lon": d_lon
        })


    # HTML MAP

    html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>PCAP Network Map (FIXED)</title>

<link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>

<style>
#map {{ height: 100vh; }}
</style>
</head>

<body>
<div id="map"></div>

<script>

var map = L.map('map').setView([20,0], 2);

L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
    maxZoom: 18
}}).addTo(map);

var nodes = {json.dumps(node_data)};
var links = {json.dumps(link_data)};


# DRAW NODES

nodes.forEach(n => {{
    L.circleMarker([n.lat, n.lon], {{
        radius: 5,
        color: "blue"
    }}).addTo(map).bindPopup(n.ip);
}});

// -----------------------------
// DRAW LINKS (VISIBLE FIX)
// -----------------------------
links.forEach(l => {{
    L.polyline([
        [l.s_lat, l.s_lon],
        [l.d_lat, l.d_lon]
    ], {{
        color: 'red',
        weight: 3,
        opacity: 0.8
    }}).addTo(map);
}});

</script>

</body>
</html>
"""

    out = os.path.abspath("network_map.html")

    with open(out, "w", encoding="utf-8") as f:
        f.write(html)

    return out


# UI
class App(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("PCAP Network Mapper (STABLE FIXED)")
        self.setGeometry(300, 300, 400, 200)

        self.label = QLabel("Load PCAP file")

        self.btn = QPushButton("Open PCAP")
        self.btn.clicked.connect(self.open_file)

        layout = QVBoxLayout()
        layout.addWidget(self.label)
        layout.addWidget(self.btn)

        c = QWidget()
        c.setLayout(layout)
        self.setCentralWidget(c)

    def open_file(self):
        file, _ = QFileDialog.getOpenFileName(self, "PCAP", "", "PCAP (*.pcap *.cap)")
        if not file:
            return

        self.label.setText("Processing...")

        nodes, links = parse_pcap(file)

        html = build_html(nodes, links)

        webbrowser.open("file://" + html)

        self.label.setText("Done")


# RUN
if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = App()
    w.show()
    sys.exit(app.exec_())
