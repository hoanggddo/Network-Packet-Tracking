import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QFileDialog, QPushButton, QVBoxLayout, QWidget
from PyQt6.QtWebEngineWidgets import QWebEngineView

from backend.main import process_pcap
from frontend.map_view import build_map

import config


class PCAPMapApp(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("PCAP Network Path Mapper")
        self.setGeometry(200, 200, 1200, 800)

        self.browser = QWebEngineView()
        self.button = QPushButton("Load PCAP File")

        self.button.clicked.connect(self.load_pcap)

        layout = QVBoxLayout()
        layout.addWidget(self.button)
        layout.addWidget(self.browser)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def load_pcap(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open PCAP File",
            "",
            "PCAP Files (*.pcap *.pcapng)"
        )

        if not file_path:
            return

        data = process_pcap(file_path, config.GEO_DB)
        html = build_map(data)

        self.browser.setHtml(html)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PCAPMapApp()
    window.show()
    sys.exit(app.exec())