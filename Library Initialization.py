from scapy.all import *
import pcapy

def scapy_test():
    testPacket = scapy.IP(dst="8.8.8.8")/scap.ICMP()
    print("The Scapy Library is working properly")
    print(packet.summary())

def scapy_test():
    deviceList = pcapy.findalldevs()
    print("The Pcapy extension is working properly")
    print(deviceList)