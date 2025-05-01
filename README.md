# Accuvis
IDS (Intrusion Detection System) built in Python


andrewBranch
Python Libraries: pcapy, scapy, hashlib, PyQt6


hashlib:
should be included naturally in python as a separate module

PyQT6 == pip install PyQt6
=======
Python Libraries: pcapy, scapy, hashlib

May need this installed as well: https://npcap.com/

For running in IDE: Make sure your Python/Scripts folder is in your environmental PATH variable, and set your Python interpretter to the proper version that has your scapy, hashlib, and pcapy libraries installed. 

**Changes made**
Pcapy will be replaced with Socket library
main
Instead of implementing a login screen, we utilized our time to add-on 'Accuvis Live.' A live detection system that notifies user of malicious traffic.

================================================================================================
Implementation of National Vulnerability Database (NVD) to output CVES related to open port
***ELEOPER IS SHARING HIS NVD API KEY INSIDE CODE ***

ASCII ART 
pip install pyfiglet

================================================================================================
Before Running Program, Please Install External Libraries :
pip install PyQt6    - GUI
pip install pcapy    - Packet Scanner
pip install requests - Port Scanner(National Vulnerability Database)
pip install pyfiglet - Ascii Art

Additional prerequisite downloads:
https://nmap.org/npcap/ - Used for Packet Scanner ; Accuvis uses its drivers

Native Python Libraries Used:
socket  - Port Scanner
hashlib - File Integrity Monitor

Notes on Port Scanner :
We are using an API key to generate faster and more requests from the National Vulnerability Database (NVD)