import sys
import os
import dpkt
import socket
import webbrowser

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton,
    QFileDialog, QVBoxLayout, QWidget, QLabel
)

import geoip2.database

# GEOIP (local DB)
try:
    reader = geoip2.database.Reader("GeoLite2-City.mmdb")
except:
    reader = None


def ip_to_geo(ip):
    try:
        if not reader:
            return None
        res = reader.city(ip)
        return (res.location.longitude, res.location.latitude)
    except:
        return None


# PCAP → KML
def build_kml(pcap_file, limit=300):
    seen = set()
    placemarks = []

    with open(pcap_file, "rb") as f:
        pcap = dpkt.pcap.Reader(f)

        for i, (_, buf) in enumerate(pcap):
            if i > limit:
                break

            try:
                eth = dpkt.ethernet.Ethernet(buf)

                if not isinstance(eth.data, dpkt.ip.IP):
                    continue

                ip = eth.data

                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)

                if (src, dst) in seen:
                    continue
                seen.add((src, dst))

                src_geo = ip_to_geo(src)
                dst_geo = ip_to_geo(dst)

                if not src_geo or not dst_geo:
                    continue

                placemarks.append(f"""
<Placemark>
    <name>{src} → {dst}</name>
    <Style>
        <LineStyle>
            <color>ff0000ff</color>
            <width>2</width>
        </LineStyle>
    </Style>
    <LineString>
        <coordinates>
            {src_geo[0]},{src_geo[1]},0
            {dst_geo[0]},{dst_geo[1]},0
        </coordinates>
    </LineString>
</Placemark>
""")

            except:
                continue

    kml = f"""<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
<Document>
<name>PCAP Network Map</name>

{"".join(placemarks)}

</Document>
</kml>
"""

    output = os.path.abspath("output.kml")

    with open(output, "w", encoding="utf-8") as f:
        f.write(kml)

    return output


# UI APP
class App(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("PCAP → Google Earth Mapper")
        self.setGeometry(300, 300, 450, 180)

        self.label = QLabel("Load a PCAP file to visualize network paths")

        self.btn = QPushButton("Load PCAP & Open in Google Earth")
        self.btn.clicked.connect(self.load_pcap)

        layout = QVBoxLayout()
        layout.addWidget(self.label)
        layout.addWidget(self.btn)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def load_pcap(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select PCAP File",
            "",
            "PCAP Files (*.pcap *.cap)"
        )

        if not file_path:
            return

        self.label.setText("Processing PCAP...")

        kml_file = build_kml(file_path)

        self.label.setText("Opening Google Earth...")

        # Try opening in Google Earth
        webbrowser.open("file://" + kml_file)

        self.label.setText("Done!")


# RUN
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = App()
    window.show()
    sys.exit(app.exec_())
