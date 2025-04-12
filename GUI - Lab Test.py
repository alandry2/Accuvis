import sys
import hashlib
import os
import json
from tkinter import filedialog
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QWidget, 
    QPushButton, QPlainTextEdit, QLabel, QGridLayout, QInputDialog
)
from PyQt6.QtCore import QProcess, Qt
from PyQt6.QtGui import QPixmap
from scapy.all import sniff
import threading
import ipaddress

class IDS_GUI(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Network IDS GUI")
        self.setGeometry(200, 200, 1000, 700)

        layout = QGridLayout()

        self.terminal_output = QPlainTextEdit(self)
        self.terminal_output.setReadOnly(True)
        self.terminal_output.setPlaceholderText("Terminal output will appear here...")
        self.terminal_output.setStyleSheet("""
            background-color: black;
            color: lime;
            font-family: Consolas, monospace;
            font-size: 12px;
        """)
        layout.addWidget(self.terminal_output, 0, 0, 3, 2)

        button_layout = QVBoxLayout()

        self.start_button = QPushButton("Start Scan")
        self.start_button.setStyleSheet("background-color: #4CAF50; color: white; padding: 10px;")
        self.start_button.clicked.connect(self.start_scan)

        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.setStyleSheet("background-color: #f44336; color: white; padding: 10px;")
        self.stop_button.clicked.connect(self.stop_scan)

        self.monitor_button = QPushButton("Monitor Files")
        self.monitor_button.setStyleSheet("background-color: #2196F3; color: white; padding: 10px;")
        self.monitor_button.clicked.connect(self.monitor_files)

        self.sniff_button = QPushButton("Start Packet Sniffer")
        self.sniff_button.setStyleSheet("background-color: orange; color: white; padding: 10px;")
        self.sniff_button.clicked.connect(self.run_sniffer)

        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        button_layout.addWidget(self.monitor_button)
        button_layout.addWidget(self.sniff_button)

        button_container = QWidget()
        button_container.setLayout(button_layout)
        layout.addWidget(button_container, 1, 2, 2, 1)

        self.logo = QLabel(self)
        pixmap = QPixmap("bird_logo.png")
        if not pixmap.isNull():
            self.logo.setPixmap(pixmap.scaled(150, 150, Qt.AspectRatioMode.KeepAspectRatio))
        else:
            self.logo.setText("[Logo not found]")
        self.logo.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop)
        layout.addWidget(self.logo, 0, 2)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.process = QProcess(self)
        self.process.readyReadStandardOutput.connect(self.display_output)
        self.process.readyReadStandardError.connect(self.display_output)

    def start_scan(self):
        command = "ping -c 4 8.8.8.8"
        self.process.start(command)

    def stop_scan(self):
        if self.process.state() == QProcess.ProcessState.Running:
            self.process.kill()
            self.terminal_output.appendPlainText("\nScan stopped.")

    def display_output(self):
        output = self.process.readAllStandardOutput().data().decode()
        error = self.process.readAllStandardError().data().decode()
        if output:
            self.terminal_output.appendPlainText(output)
        if error:
            self.terminal_output.appendPlainText(error)

    def calculate_hash(self, file_path):
        hasher = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(4096):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except FileNotFoundError:
            return None

    def save_hashes(self, hashes, filename="file_hashes.json"):
        with open(filename, 'w') as f:
            json.dump(hashes, f, indent=4)

    def load_hashes(self, filename="file_hashes.json"):
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                return json.load(f)
        return {}

    def monitor_files(self):
        file_list = filedialog.askopenfilenames(title="Select files to monitor")
        if not file_list:
            return

        hashes = self.load_hashes()
        for file in file_list:
            new_hash = self.calculate_hash(file)
            if new_hash is None:
                self.terminal_output.appendPlainText(f"[WARNING] {file} not found!")
                continue

            if file in hashes:
                if hashes[file] != new_hash:
                    self.terminal_output.appendPlainText(f"[ALERT] {file} has been modified!")
                else:
                    self.terminal_output.appendPlainText(f"[OK] {file} is unchanged.")
            else:
                self.terminal_output.appendPlainText(f"[NEW] Tracking new file: {file}")

            hashes[file] = new_hash

        self.save_hashes(hashes)
        self.terminal_output.appendPlainText("[INFO] Hash monitoring complete.")

    def run_sniffer(self):
        ip, ok = QInputDialog.getText(self, "Target IP/Network", "Enter IP or network (e.g. 192.168.1.0/24):")
        if not ok:
            return

        ip = ip.strip()
        count, ok = QInputDialog.getInt(self, "Packet Count", "Enter number of packets to sniff:", 10, 1)
        if not ok:
            return

        self.terminal_output.appendPlainText(f"[INFO] Starting sniffer on: {ip or 'default'} for {count} packets...")

        def packet_sniffer(packet):
            summary = "\n" + packet.summary()
            if packet.haslayer("IP"):
                summary += f"\n Source IP: {packet['IP'].src}"
                summary += f"\n Destination IP: {packet['IP'].dst}"
            if packet.haslayer("TCP") or packet.haslayer("UDP"):
                protocol = "TCP" if packet.haslayer("TCP") else "UDP"
                summary += f"\n Protocol: {protocol}"
                summary += f"\n Source Port: {packet.sport}"
                summary += f"\n Destination Port: {packet.dport}\n"
            self.terminal_output.appendPlainText(summary)

        def sniff_thread():
            try:
                sniff(filter=f"ip and net {ip}" if ip else "ip", prn=packet_sniffer, count=count, iface="Ethernet", store=False)
                self.terminal_output.appendPlainText("[INFO] Packet sniffing completed.")
            except Exception as e:
                self.terminal_output.appendPlainText(f"[ERROR] {str(e)}")

        thread = threading.Thread(target=sniff_thread, daemon=True)
        thread.start()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = IDS_GUI()
    window.show()
    sys.exit(app.exec())
