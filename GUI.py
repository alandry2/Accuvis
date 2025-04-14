#ThreadPoolExecutor does asynchronous execution with threads.
from concurrent.futures import ThreadPoolExecutor
#Socket library that will be used to attempt to form a TCP connection.
import socket
#To measure time it takes
import time
#To check pattern of IP address
import re

import sys
import hashlib
import os
import json
from tkinter import Tk, filedialog
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QWidget, 
    QPushButton, QTextEdit, QHBoxLayout, QLabel,
    QGridLayout, QInputDialog, QStackedLayout, QMessageBox
)
from PyQt6.QtCore import QProcess, Qt
from PyQt6.QtGui import QPixmap
from scapy.all import sniff
import threading
import ipaddress
from pathlib import Path

class IDS_GUI(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Network IDS GUI")
        self.setGeometry(200, 200, 8000, 600)

        # Main layout
        layout = QGridLayout()
        self.setStyleSheet("""
            QMainWindow {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                                            stop:0 #1e3c72, stop:1 #2a5298);
            }
        """)
        # Terminal-like display area (top left)
        self.terminal_output = QTextEdit(self)
        self.terminal_output.setReadOnly(True)
        self.terminal_output.setPlaceholderText("Terminal output will appear here...")
        self.terminal_output.setStyleSheet("""
            background-color: black;
            color: lime;
            font-family: Consolas, monospace;
            font-size: 12px;
        """)
        layout.addWidget(self.terminal_output, 0, 0, 2, 2)  # Terminal spans 2 rows, 2 cols

        # Bird logo (top right)
        currentDirectory = Path(__file__).parent
        logoPath = currentDirectory / "bird_logo.png"
        pixmap = QPixmap(str(logoPath))
        self.logo = QLabel(self)
        self.logo.setPixmap(pixmap)
        self.logo.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop)
        layout.addWidget(self.logo, 0, 2) #Logo spans 1 row, 1 col





        # Dynamic input Buttons (bottom right)
        self.stackLayout = QStackedLayout()

        #Button Layout 1 - Packet Scanner
        button_layout1 = QVBoxLayout() #QHBoxLayout displays them horizontally and QVBoxLayout displays them Vertically
        
        self.sniff_button = QPushButton("Start Packet Sniffer")
        self.sniff_button.setStyleSheet("background-color: orange; color: white; padding: 10px;")
        self.sniff_button.clicked.connect(self.run_sniffer)

        button_layout1.addWidget(self.sniff_button)

        # Button layout positioned bottom right
        button_container1 = QWidget()
        button_container1.setLayout(button_layout1)
        self.stackLayout.addWidget(button_container1) 

        #Button Layout 2 - Port Scanner
        button_layout2 = QVBoxLayout() #QHBoxLayout displays them horizontally and QVBoxLayout displays them Vertically
        
        self.targetIpAddress = QTextEdit()
        self.targetIpAddress.setPlaceholderText("Input Target IP Address")
        self.targetIpAddress.setStyleSheet("background-color: black; color: white; padding: 10px;")

        self.startPortNum = QTextEdit()
        self.startPortNum.setPlaceholderText(" Start Port Number")
        self.startPortNum.setStyleSheet("background-color: black; color: white; padding: 10px;")

        self.endPortNum = QTextEdit()
        self.endPortNum.setPlaceholderText("Input End Port Number")
        self.endPortNum.setStyleSheet("background-color: black; color: white; padding: 10px;")

        self.start_port_scan = QPushButton("Start Port Scan")
        self.start_port_scan.setStyleSheet("background-color: black; color: white; padding: 10px;")
        self.start_port_scan.clicked.connect(self.prePortScan)

        button_layout2.addWidget(self.targetIpAddress)
        button_layout2.addWidget(self.startPortNum)
        button_layout2.addWidget(self.endPortNum)
        button_layout2.addWidget(self.start_port_scan)

        # Button layout positioned bottom right
        button_container2 = QWidget()
        button_container2.setLayout(button_layout2)
        self.stackLayout.addWidget(button_container2)

        #Button Layout 3 - File Integrity Monitor
        button_layout3 = QVBoxLayout() #QHBoxLayout displays them horizontally and QVBoxLayout displays them Vertically
        
        self.monitor_button3 = QPushButton("FILE INTEGRITY BUTTON 3")
        self.monitor_button3.setStyleSheet("background-color: blue; color: white; padding: 10px;")
        self.monitor_button3.clicked.connect(self.monitor_files)

        button_layout3.addWidget(self.monitor_button3)

        # Button layout positioned bottom right
        button_container3 = QWidget()
        button_container3.setLayout(button_layout3)
        self.stackLayout.addWidget(button_container3)

        #Button Layout 4 - Accuvis LIVE
        button_layout4 = QVBoxLayout() #QHBoxLayout displays them horizontally and QVBoxLayout displays them Vertically
        
        self.start_button4 = QPushButton("ACCUVIS LIVE BUTTON 1")
        self.start_button4.setStyleSheet("background-color: #4CAF40; color: white; padding: 10px;")
        self.start_button4.clicked.connect(self.start_scan)

        self.stop_button4 = QPushButton("ACCUVIS LIVE BUTTON 2")
        self.stop_button4.setStyleSheet("background-color: #f44236; color: white; padding: 10px;")
        self.stop_button4.clicked.connect(self.stop_scan)

        self.monitor_button4 = QPushButton("ACCUVIS LIVE BUTTON 3")
        self.monitor_button4.setStyleSheet("background-color: blue; color: white; padding: 10px;")
        self.monitor_button4.clicked.connect(self.monitor_files)

        self.sniff_button4 = QPushButton("ACCUVIS LIVE BUTTON 4")
        self.sniff_button4.setStyleSheet("background-color: orange; color: white; padding: 10px;")
        self.sniff_button4.clicked.connect(self.run_sniffer)

        button_layout4.addWidget(self.start_button4)
        button_layout4.addWidget(self.stop_button4)
        button_layout4.addWidget(self.monitor_button4)
        button_layout4.addWidget(self.sniff_button4)

        # Button layout positioned bottom right
        button_container4 = QWidget()
        button_container4.setLayout(button_layout4)
        self.stackLayout.addWidget(button_container4)

        #adding stackedwiget into layout of page
        self.stackedContainer = QWidget()
        self.stackedContainer.setLayout(self.stackLayout)
        layout.addWidget(self.stackedContainer, 1, 2,) #this value was previously 1, 2 for horizontal buttons




        # Function Buttons (bottom)
        button_layout2 = QHBoxLayout()

        self.function_PacketScanner = QPushButton("Packet Scanner")
        self.function_PacketScanner.clicked.connect(lambda: self.stackLayout.setCurrentIndex(0))#lambda is a helper method; makes function into 1 line

        self.function_PortScanner = QPushButton("Port Scanner")
        self.function_PortScanner.clicked.connect(lambda: self.stackLayout.setCurrentIndex(1))

        self.function_FileIntegritMon = QPushButton("File Integrity Monitor")
        self.function_FileIntegritMon.clicked.connect(lambda: self.stackLayout.setCurrentIndex(2))

        self.function_AccuvisActive = QPushButton("Accuvis LIVE")
        self.function_AccuvisActive.clicked.connect(lambda: self.stackLayout.setCurrentIndex(3))

        button_layout2.addWidget(self.function_PacketScanner)
        button_layout2.addWidget(self.function_PortScanner)
        button_layout2.addWidget(self.function_FileIntegritMon)
        button_layout2.addWidget(self.function_AccuvisActive)

        button_container2 = QWidget()
        button_container2.setLayout(button_layout2)
        layout.addWidget(button_container2, 3, 0, 1, 3)        
        
        #stretches terminal to fill gaps
        layout.setColumnStretch(0, 3)


        # Set main layout
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        # Terminal process
        self.process = QProcess(self)
        self.process.readyReadStandardOutput.connect(self.display_output)
        self.process.readyReadStandardError.connect(self.display_output)




    #------------ Packet Scanner function ------------------------

    #Dyanmic Button Layout

    def start_scan(self):
        """Start a Scapy scan or network command"""
        command = "ping -c 4 8.8.8.8"  
        self.process.start(command)

    def stop_scan(self):
        """Stop the scan process"""
        if self.process.state() == QProcess.ProcessState.Running:
            self.process.kill()
            self.terminal_output.append("\nScan stopped.")

    def display_output(self):
        """Display terminal output in the GUI"""
        output = self.process.readAllStandardOutput().data().decode()
        error = self.process.readAllStandardError().data().decode()

        if output:
            self.terminal_output.append(output)
        if error:
            self.terminal_output.append(error)

    def run_sniffer(self):
        ip, ok = QInputDialog.getText(self, "Target IP/Network", "Enter IP or network (e.g. 192.168.1.0/24):")
        if not ok:
            return

        ip = ip.strip()
        count, ok = QInputDialog.getInt(self, "Packet Count", "Enter number of packets to sniff:", 10, 1)
        if not ok:
            return

        self.terminal_output.append(f"[INFO] Starting sniffer on: {ip or 'default'} for {count} packets...")

        def packet_sniffer(packet):
            summary = f"<br><span style='color:white;'>{packet.summary()}</span>"

            if packet.haslayer("IP"):
                summary += f"<br> Source IP: {packet['IP'].src}"
                summary += f"<br> Destination IP: {packet['IP'].dst}"

            if packet.haslayer("TCP") or packet.haslayer("UDP"):
                protocol = "TCP" if packet.haslayer("TCP") else "UDP"
                color = "cyan"

                # Define unsafe ports
                insecurePorts = [23, 21, 445, 135, 139, 3389] #this includes unsafe protocols such as 23 Telnet 21 FTP 445 SMB and more!

                def format_port(port):
                    if port in insecurePorts:
                        return f"<span style='color:red;font-weight:bold;'>{port}</span>"
                    return f"<span style='color:blue;'>{port}</span>"

                summary += f"<br> Protocol: <span style='color:{color}; font-weight:bold;'>{protocol}</span>"
                summary += f"<br> Source Port: {format_port(packet.sport)}"
                summary += f"<br> Destination Port: {format_port(packet.dport)}<br>"

            self.terminal_output.append(summary)


        def sniff_thread():
            try:
                sniff(filter=f"ip and net {ip}" if ip else "ip", prn=packet_sniffer, count=count, iface="Ethernet", store=False)
                self.terminal_output.append("[INFO] Packet sniffing completed.")
            except Exception as e:
                self.terminal_output.append(f"[ERROR] {str(e)}")

        thread = threading.Thread(target=sniff_thread, daemon=True)
        thread.start()

    #------------ END of Packet Scanner Function ------------------------


    #------------file integrity monitoring function ------------------------
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
                self.terminal_output.append(f"[WARNING] {file} not found!")
                continue
            
            if file in hashes:
                if hashes[file] != new_hash:
                    self.terminal_output.append(f"[ALERT] {file} has been modified!")
                else:
                    self.terminal_output.append(f"[OK] {file} is unchanged.")
            else:
                self.terminal_output.append(f"[NEW] Tracking new file: {file}")
            
            hashes[file] = new_hash
        
        self.save_hashes(hashes)
        self.terminal_output.append("[INFO] Hash monitoring complete.")

    # ----------- END OF file hash functions -----------------      
        

    # ----------- START OF port scanner functions -----------------

    def prePortScan(self):
        #preconditions before going to Port Scanner
        target_ip_addr = self.targetIpAddress.toPlainText().strip()
        start_port_num = self.startPortNum.toPlainText().strip()
        end_port_num = self.endPortNum.toPlainText().strip()

        target_ip_addr = target_ip_addr.strip()
        noInputDialog = QMessageBox()
        noInputDialog.setWindowTitle("Error Has Occurred")
        noInputDialog.setText("Please make sure you have input inside the boxes")

        portNumsError = QMessageBox()
        portNumsError.setWindowTitle("Error Has Occurred")
        portNumsError.setText("Please make sure you have input integers for start and end port boxes")

        if not (target_ip_addr and start_port_num and end_port_num):
            noInputDialog.exec()
            return

        try:
            #portScan function need int values as args
            start_port_num = int(start_port_num)
            end_port_num = int(end_port_num)
        
        except ValueError:
            portNumsError.exec()
            return
        
        self.portScan(target_ip_addr, start_port_num,end_port_num)
            

    #given the port range, it will divide the port range evenly into a list to be assigned to a worker
    def assign_thread_ports(self, port_range):

        #Defines how many threads are used
        MAX_WORKERS = 20
        port_chunks = []

        #Divides ports even for every worker (in this case 20)
        chunk_size = int((int(port_range[1]) - int(port_range[0])) / MAX_WORKERS)

        for i in range(MAX_WORKERS):
            start = int(port_range[0]) + (chunk_size * i)
            end = start + chunk_size
            port_chunks.append([start, end])
        return port_chunks

    def scan(self, target_ip_address, port_chunk):
        self.terminal_output.append(f"Now scanning {target_ip_address} from {port_chunk[0]} to {port_chunk[1]}.")

        #every port will be checked, if SYN/ACK is received, port is open, otherwise (no response or error) it will return nothing
        for port in range(int(port_chunk[0]),int(port_chunk[1])):
            try:
                socket_scan = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket_scan.settimeout(1)

                socket_scan.connect_ex((target_ip_address,port))
                self.terminal_output.append(f"[!] Port {port} is open!", sep="")
            except: 
                None

        #input from user - target IP addr, start port, end port
    def portScan(self, target_ip_addr, start_port, end_port):

        MAX_WORKERS = 20

        invalidPortsDialog = QMessageBox()
        invalidPortsDialog.setWindowTitle("Error Has Occurred")
        invalidPortsDialog.setText("Start Port Must Begin Earlier Than End Port. Ex. 1-10")
    
        if (start_port < end_port):

            port_range = [start_port,end_port]

            #parameter to divide port range evenly
            port_chunks = self.assign_thread_ports(port_range)

            start_time = time.time()

            #executing scan function to a thread to asynchronously run.
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                executor.map(self.scan, [target_ip_addr] * len(port_chunks),port_chunks)
                
            end_time = time.time()
    
            self.terminal_output.append(f"Scanned {int(port_range[1])-int(port_range[0])} ports in {end_time-start_time} seconds")

        else:
            invalidPortsDialog.exec()
    # ----------- END OF port scanner functions -----------------

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = IDS_GUI()
    window.show()
    sys.exit(app.exec())