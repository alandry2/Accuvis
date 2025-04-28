#Main Interface

#-------------------- Packet Scanner ----------------------
from scapy.all import sniff
import threading
from pathlib import Path
from collections import deque
from queue import Queue

#-------------------- Port Scanner ----------------------
#ThreadPoolExecutor does asynchronous execution with threads.
from concurrent.futures import ThreadPoolExecutor
#Socket library that will be used to attempt to form a TCP connection.
import socket
#To measure time it takes
import time
#To check pattern of IP address
import requests

#Scan sctructure : [PORT] | [SERVICE] | [CVES]
scan_results = []

#NVD API KEY {ELEO PER MAPUTE}
api_key = "1f28c9fe-e679-472e-abc5-fd363f0a06eb"

#-------------------- File Integrity Monitor ----------------------
import hashlib
import os
import json

#-------------------- GUI ----------------------
import sys
import pyfiglet
from tkinter import Tk, filedialog
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QWidget, 
    QPushButton, QTextEdit, QHBoxLayout, QLabel, 
    QGridLayout, QInputDialog, QStackedLayout, QMessageBox 
)
from PyQt6.QtCore import QProcess, Qt, QTimer
from PyQt6.QtGui import QPixmap, QTextCursor, QIcon



class IDS_GUI(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Network IDS GUI")
        self.setGeometry(100, 100, 725, 500)
        self.packet_queue = deque()
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.flush_packets)
        self.update_timer.start(100) 

    #the deque above is for safe packet scanner output
    # this queue is developed for the safe and timely output of the ACCUVIS LIVE function
        self.message_queue = Queue()

        self.message_timer = QTimer()
        self.message_timer.timeout.connect(self.process_message_queue)
        self.message_timer.start(100)

        #Ascii Art : Accuvis
        figlet = pyfiglet.Figlet()
        logo ="-_ Accuvis _-"
        rendered_text = figlet.renderText(logo)

        # Main layout
        layout = QGridLayout()
        self.setStyleSheet("""
            QMainWindow {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,stop:0 #1e3c72, stop:1 #2a5298);
            }
        """)
        # Terminal-like display area (top left) the stylesheet is going to customize how it looks below
        self.terminal_output = QTextEdit(self)
        self.terminal_output.setReadOnly(True)
        self.terminal_output.append(rendered_text)
        self.terminal_output.append("Welcome to the Accuvis, your very own host-based IDS!!\n ")
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
        iconPath = currentDirectory / "IDS_icon.png"
        self.setWindowIcon(QIcon(str(iconPath)))
        pixmap = QPixmap(str(logoPath))
        self.logo = QLabel(self)
        self.logo.setPixmap(pixmap)
        self.logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.logo, 0, 2) #Logo spans 1 row, 1 col


        # Dynamic input Buttons (bottom right buttons are going here)
        self.stackLayout = QStackedLayout()

        #Button Layout 1 - Packet Scanner
        button_layout1 = QVBoxLayout() 
        
        self.sniff_button = QPushButton("Start Packet Sniff: Ethernet")
        self.sniff_button.setStyleSheet("background-color: orange; color: white; padding: 10px;")
        self.sniff_button.clicked.connect(lambda: self.run_sniffer("Ethernet"))

        self.sniff_button2 = QPushButton("Start Packet Sniff: Wi-Fi")
        self.sniff_button2.setStyleSheet("background-color: #4CAF40; color: white; padding: 10px;")
        self.sniff_button2.clicked.connect(lambda: self.run_sniffer("Wi-Fi"))

        button_layout1.addWidget(self.sniff_button)
        button_layout1.addWidget(self.sniff_button2)

        # Button layout positioned bottom right
        button_container1 = QWidget()
        button_container1.setLayout(button_layout1)
        self.stackLayout.addWidget(button_container1) 

        #Button Layout 2 - Port Scanner
        button_layout2 = QVBoxLayout() 
        
        self.targetIpAddress = QTextEdit()
        self.targetIpAddress.setPlaceholderText("Input Target IP Address")
        self.targetIpAddress.setStyleSheet("""
            QTextEdit {
                background-color: #000;
                color: #fff;
                padding: 6px;
                font-size: 12px;
                border: 1px solid #222;
                border-radius: 5px;
            }
        """)

        self.startPortNum = QTextEdit()
        self.startPortNum.setPlaceholderText(" Start Port Number")
        self.startPortNum.setStyleSheet("""
            QTextEdit {
                background-color: #000;
                color: #fff;
                padding: 6px;
                font-size: 12px;
                border: 1px solid #222;
                border-radius: 5px;
            }
        """)

        self.endPortNum = QTextEdit()
        self.endPortNum.setPlaceholderText("Input End Port Number")
        self.endPortNum.setStyleSheet("""
            QTextEdit {
                background-color: #000;
                color: #fff;
                padding: 6px;
                font-size: 12px;
                border: 1px solid #222;
                border-radius: 5px;
            }
        """)

        self.start_port_scan = QPushButton("Start Port Scan")
        self.start_port_scan.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                padding: 8px;
                font-size: 13px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #fcf24f;
                color: black;
            }
        """)
        self.start_port_scan.clicked.connect(self.prePortScan)

        button_layout2.addWidget(self.targetIpAddress)
        button_layout2.addWidget(self.startPortNum)
        button_layout2.addWidget(self.endPortNum)
        button_layout2.addWidget(self.start_port_scan)

        button_container2 = QWidget()
        button_container2.setLayout(button_layout2)
        self.stackLayout.addWidget(button_container2)


        #Button Layout 3 - File Integrity Monitor
        button_layout3 = QVBoxLayout() #QHBoxLayout displays them horizontally and QVBoxLayout displays them Vertically
        
        self.monitor_button3 = QPushButton("File Integrity Scan")
        self.monitor_button3.setStyleSheet("background-color: blue; color: white; padding: 10px;")
        self.monitor_button3.clicked.connect(self.monitor_files)

        button_layout3.addWidget(self.monitor_button3)

        button_container3 = QWidget()
        button_container3.setLayout(button_layout3)
        self.stackLayout.addWidget(button_container3)


        #Button Layout 4 - Accuvis LIVE this will eventually run as the main IDS function
        button_layout4 = QVBoxLayout() #QHBoxLayout displays them horizontally and QVBoxLayout displays them Vertically
        
        self.start_button4 = QPushButton("Start ACCUVIS LIVE")
        self.start_button4.setStyleSheet("background-color: #4CAF40; color: white; padding: 10px;")
        self.start_button4.clicked.connect(self.start_accuvis_live)

        self.stop_button4 = QPushButton("Stop ACCUVIS LIVE")
        self.stop_button4.setStyleSheet("background-color: #fc694f; color: white; padding: 10px;")
        self.stop_button4.clicked.connect(self.stop_accuvis_live)

        button_layout4.addWidget(self.start_button4)
        button_layout4.addWidget(self.stop_button4)

        # Button layout positioned bottom right
        button_container4 = QWidget()
        button_container4.setLayout(button_layout4)
        self.stackLayout.addWidget(button_container4)

        #adding stackedwiget into layout of page
        self.stackedContainer = QWidget()
        self.stackedContainer.setLayout(self.stackLayout)
        layout.addWidget(self.stackedContainer, 1, 2,)




        # Function Buttons (bottom)
        button_layout2 = QHBoxLayout()

        self.function_PacketScanner = QPushButton("Packet Scanner")
        self.function_PacketScanner.clicked.connect(lambda: self.stackLayout.setCurrentIndex(0))
        self.function_PacketScanner.setStyleSheet("""
                QPushButton {
                    background-color: #f44ffc; 
                    color: white; 
                    border-radius: 8px; 
                    padding: 10px; 
                    font-size: 14px;
                }
                QPushButton:hover {
                    background-color: #858585;
                }
            """)

        self.function_PortScanner = QPushButton("Port Scanner")
        self.function_PortScanner.clicked.connect(lambda: self.stackLayout.setCurrentIndex(1))
        self.function_PortScanner.setStyleSheet("""
                QPushButton {
                    background-color: #4aee56; 
                    color: white; 
                    border-radius: 8px; 
                    padding: 10px; 
                    font-size: 14px;
                }
                QPushButton:hover {
                    background-color: #858585;
                }
            """)

        self.function_FileIntegritMon = QPushButton("File Integrity Monitor")
        self.function_FileIntegritMon.clicked.connect(lambda: self.stackLayout.setCurrentIndex(2))
        self.function_FileIntegritMon.setStyleSheet("""
                QPushButton {
                    background-color: #fc694f; 
                    color: white;
                    border-radius: 8px; 
                    padding: 10px;
                    font-size: 14px;
                }
                QPushButton:hover {
                    background-color: #858585;
                }
            """)

        self.function_AccuvisActive = QPushButton("Accuvis LIVE")
        self.function_AccuvisActive.clicked.connect(lambda: self.stackLayout.setCurrentIndex(3))
        self.function_AccuvisActive.setStyleSheet("""
                QPushButton {
                    background-color: #4f6efc; 
                    color: white; 
                    border-radius: 8px; 
                    padding: 10px; 
                    font-size: 14px;
                }
                QPushButton:hover {
                    background-color: #858585;
                }
            """)

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

    #had to set a queue for scanning packets that way they are not all shoved to the GUI at once to prevent crashing
    def start_accuvis_live(self):
        self.message_queue.put(("cyan", "[LIVE] Accuvis Live Monitoring Started..."))
        self.live_monitoring = True

        packet_thread = threading.Thread(target=self.accuvis_live_sniff, daemon=True)
        packet_thread.start()

        file_thread = threading.Thread(target=self.accuvis_file_monitor, daemon=True)
        file_thread.start()

    def stop_accuvis_live(self):
        self.live_monitoring = False
        self.message_queue.put(("cyan", "[LIVE] Accuvis Live Monitoring Stopped."))

    def process_message_queue(self):
        while not self.message_queue.empty():
            color, message = self.message_queue.get()
            self.editColors(message, color)

    def display_output(self):
        #Display terminal output in the GUI
        output = self.process.readAllStandardOutput().data().decode()
        error = self.process.readAllStandardError().data().decode()

        if output:
            self.terminal_output.append(output)
        if error:
            self.terminal_output.append(error)

    def accuvis_live_sniff(self):
        insecure_ports = [21, 23, 445, 135, 139, 3389]  # these are the ports that are commonly unsafe, and are the ones that will be searched for for accuvis live exceptions

        def filter_packet(packet):
            if packet.haslayer('TCP') or packet.haslayer('UDP'):
                sport = packet.sport
                dport = packet.dport
                if sport in insecure_ports or dport in insecure_ports:
                    self.message_queue.put(("red", f"[!] Suspicious packet: {packet.summary()}"))

        try:
            while self.live_monitoring:
                sniff(
                    prn=filter_packet,
                    store=False,
                    count=500,  # the message for showing progress of Accuvis live will ONLY show up after this amount of packets are scanned
                )
                # this just keeps the user knowing that things are going on 
                self.message_queue.put(("green", "[+] Accuvis live monitoring is still running..."))
        except Exception as e:
            self.message_queue.put(("red", f"[ERROR] Accuvis live sniffer failed: {e}"))

    def accuvis_file_monitor(self):
        hashes = self.load_hashes()

        while self.live_monitoring:
            for file, old_hash in hashes.items():
                new_hash = self.calculate_hash(file)
                if new_hash is None:
                    self.message_queue.put(("orange", f"[WARNING] {file} not found!"))
                    continue
                if new_hash != old_hash:
                    self.message_queue.put(("red", f"[ALERT!!] {file} has been modified!"))
                    hashes[file] = new_hash  # update with new hash

            self.save_hashes(hashes)
            for _ in range(10):  # Instead of sleeping 10 sec straight
                if not self.live_monitoring:
                    break
                time.sleep(1)  # sleep 1 second, check every second


    def run_sniffer(self, interface_name):
        ip, ok = QInputDialog.getText(self, "Target IP/Network", "Enter IP or network (e.g. 192.168.1.0/24):")
        if not ok:
            return

        ip = ip.strip()
        count, ok = QInputDialog.getInt(self, "Packet Count", "Enter number of packets to sniff:", 10, 1)
        if not ok:
            return

        self.terminal_output.append(f"[INFO] Starting sniffer on: {ip or 'default'} for {count} packets...")

        def packet_sniffer(packet):
            try:
                summary = f"<br><span style='color:white;'>{packet.summary()}</span>"

                if packet.haslayer("IP"):
                    summary += f"<br> Source IP: {packet['IP'].src}"
                    summary += f"<br> Destination IP: {packet['IP'].dst}"

                if packet.haslayer("TCP") or packet.haslayer("UDP"):
                    protocol = "TCP" if packet.haslayer("TCP") else "UDP"
                    color = "cyan"

                    insecurePorts = [23, 21, 445, 135, 139, 3389]

                    def format_port(port):
                        if port in insecurePorts:
                            return f"<span style='color:red;font-weight:bold;'>{port}</span>"
                        return f"<span style='color:blue;'>{port}</span>"

                    summary += f"<br> Protocol: <span style='color:{color}; font-weight:bold;'>{protocol}</span>"
                    summary += f"<br> Source Port: {format_port(packet.sport)}"
                    summary += f"<br> Destination Port: {format_port(packet.dport)}<br>"

                # Instead of appending immediately -> add to queue
                self.packet_queue.append(summary)

            except Exception as e:
                self.packet_queue.append(f"<br><span style='color:red;'>[ERROR] {str(e)}</span>")

    #change value of "Ethernet" in the sniff command to "Wi-Fi" and if ncap is installed on host computer it will run off of Wi-Fi - this needs to be addressed in terminal
        def sniff_thread():
            try:
                sniff(filter=f"ip and net {ip}" if ip else "ip", prn=packet_sniffer, count=count, iface=interface_name, store=False)
                self.terminal_output.append("[INFO] Packet sniffing completed.")
            except Exception as e:
                self.terminal_output.append(f"[ERROR] {str(e)}")

        thread = threading.Thread(target=sniff_thread, daemon=True)
        thread.start()

    def flush_packets(self):
        max_packets_per_refresh = 10  # tweak this if you want faster or slower updates
        count = 0

        while self.packet_queue and count < max_packets_per_refresh:
            summary = self.packet_queue.popleft()
            self.terminal_output.append(summary)
            count += 1


    #------------ END of Packet Scanner Function ------------------------


    #------------file integrity monitoring function ------------------------
    #JSON file is created to compare and store the hashes - makes it easier to monitor
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
                self.editColors(f"[WARNING] {file} not found!", "orange")
                continue
            
            if file in hashes:
                if hashes[file] != new_hash:
                    self.editColors(f"[ALERT!!] {file} has been modified!", "red")
                else:
                    self.editColors(f"[OK] {file} is unchanged.","green")
            else:
                self.editColors(f"[NEW] Tracking new file: {file}", "blue")
            
            hashes[file] = new_hash
        
        self.save_hashes(hashes)
        self.editColors("[INFO] File Hash monitoring complete.", "cyan")

    def editColors(self, message, color):
            self.terminal_output.moveCursor(QTextCursor.MoveOperation.End)
            self.terminal_output.insertHtml(f'<span style="color:{color}">{message}</span><br>')
            self.terminal_output.moveCursor

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
            #integeter data type is required here for the argument
            start_port_num = int(start_port_num)
            end_port_num = int(end_port_num)
        
        except ValueError:
            portNumsError.exec()
            return
        
        self.portScan(target_ip_addr, start_port_num,end_port_num)
            

    #given the port range, it will divide the port range evenly into a list to be assigned to a worker
    def assign_thread_ports(self, port_range,max_workers):

        port_chunks = []
        start = int(port_range[0])
        end = int(port_range[1])
        #divide chunks evenly throughout 
        chunk_size = (end - start + 1) // max_workers

        for i in range(max_workers):
            chunk_start = start + i * chunk_size
            #if a remainder is left, it will be accounted for 
            chunk_end = start + (i+1) * chunk_size if i< max_workers - 1 else end
            port_chunks.append([chunk_start, chunk_end])
        return port_chunks
        

    def check_for_cves(self):

        for item in scan_results:

            service = item["service"]
            if not service or service in ["unnknown", ""]:
                item["cves"].append("[-] Unknown Service.")
                continue
            
            try:
                #request to obtain top 3 cves of service from NVD Website
                headers = {"apiKey": api_key}
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service}&resultsPerPage=3"
                response = requests.get(url,headers=headers)

                if response.status_code == 200:
                    results = response.json().get("vulnerabilities", [])
                    if not results:
                        item["cves"].append("[-] No CVEs found.")
                
                    for vulnerabilities in results:

                        #creates a list of top 3 cves, adds to service_cves list, then clears list for next service
                        cve_of_service = vulnerabilities["cve"]["id"]
                        descriptions = vulnerabilities["cve"].get("descriptions",[])
                        desc_of_cve = vulnerabilities["cve"]["descriptions"][0]["value"] if descriptions else "No description avaialable."
                        item["cves"].append(f"{cve_of_service}: {desc_of_cve}")
                else:
                    item["cves"].append("[-] Failed to fetch CVEs")
            except:
                self.terminal_output.append("[X] Error has Occurred!")

    def scan(self, target_ip_address, port_chunk):
        #every port will be checked, if SYN/ACK is received, port is open, otherwise (no response or error) it will return nothing
    #note : ports that are filtered are not accounted for.
        for port in range(port_chunk[0],port_chunk[1]+1):
            try:
                socket_scan = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket_scan.settimeout(1)
                result = socket_scan.connect_ex((target_ip_address,port))
                
                #open ports with known service will be added, else "unknown"
                if result == 0:
                    try:
                        service = socket.getservbyport(port, "tcp")
                    except: 
                        service = "unknown"

                    scan_results.append({"port": port, "service": service, "cves": []})
               
                socket.close()
                socket_scan.close()

            except: 
                continue 

        #input from user - target IP addr, start port, end port
    def portScan(self, target_ip_addr, start_port, end_port):

        invalidPortsDialog = QMessageBox()
        invalidPortsDialog.setWindowTitle("Error Has Occurred")
        invalidPortsDialog.setText("Start Port Must Begin Earlier Than End Port. Ex. 1-10")
    
        if (start_port < end_port):
            
            port_range = [start_port,end_port]
            total_ports = int(end_port)-int(start_port)

            #max amount of threads that will execute asynchronously
            #depending on given workers, it changes time it takes of port scanner
            MAX_WORKERS = 1 if total_ports < 20 else 20


            #parameter to divide port range evenly
            port_chunks = self.assign_thread_ports(port_range,MAX_WORKERS)

            self.terminal_output.append(f"\n\n[INFO] Now scanning {target_ip_addr} from ports {start_port} to {end_port}.\n")
            start_time = time.time()

            #executing scan function to a thread to asynchronously run.
            with ThreadPoolExecutor(max_workers = MAX_WORKERS) as executor:
                executor.map(self.scan, [target_ip_addr] * len(port_chunks),port_chunks)
                
            self.check_for_cves()
            end_time = time.time()

            if not scan_results:
                self.terminal_output.append("[!] No Ports are open in the given range!")
            else:
                for item in sorted(scan_results, key=lambda x: x["port"]):
                    self.terminal_output.append(f"<span style='color: white';>[!] Port {item["port"]} is open!</span>")
                    self.terminal_output.append(f"<span style='color :DodgerBlue';>[?]Service: {item["service"]}</span>")
                    self.terminal_output.append(f"""<span style='color: red;'>        
                                            [$] Common Vulnerability & Exposures Associated with Port(CVEs):</span>""")
                    for cve in item["cves"]:
                        self.terminal_output.append(f"     - {cve}\n")

            scan_results.clear()
            self.terminal_output.append(f"\n[INFO] Scanned {total_ports+1} ports in {end_time-start_time:.2f} seconds\n\n")
        else:
            invalidPortsDialog.exec()
    # ----------- END OF port scanner functions -----------------
    

if __name__ == "__main__":

    app = QApplication(sys.argv)
    window = IDS_GUI()
    window.show()
    sys.exit(app.exec())