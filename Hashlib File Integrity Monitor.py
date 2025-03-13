from scapy.all import *
from scapy.all import sniff
import ipaddress


def packet_sniffer(packet): # this will print a summary of each captured packet
    print("\n"+packet.summary())
    if packet.haslayer("IP"):
        print(f" Source IP: {packet['IP'].src}")
        print(f" Destination IP: {packet['IP'].dst}")
    if packet.haslayer("TCP") or packet.haslayer("UDP"):
        protocol = "TCP" if packet.haslayer("TCP") else "UDP"
        sourcePort = packet.sport
        destPort = packet.dport
        print(f" Protocol: {protocol}")
        print(f" Source Port: {sourcePort}")
        print(f" Destination Port: {destPort}\n")

# Define your network filter (Replace with your actual network range)
netAddress = input("Please enter your target IP address or network (ex: 192.168.1.0/24): ")

while True:
    packetCount = input("How many packets would you like to trace for? ")
    if packetCount.isdigit() and int(packetCount) > 0:
        packetCount = int(packetCount)
        break
    else:
        print("This input is incorrect. Please enter a positive number.")

# try statement checks for network information validation
try:
    if "/" in netAddress: #this will see if CIDR notation is used
        networkIP = ipaddress.IPv4Network(netAddress, strict=False)
        ipRange = [str(ip) for ip in networkIP.hosts()] #this will search through usable IP's
    else:
        ipRange = netAddress #single IP address not network address
except ValueError:
    print("Incorrect value has been given for the IP address and/or subnet. Please try again!")


# Sniff packets on the specified network or target ip 
print("\n The packet capture has begun.. the following "+str(packetCount)+" packets are: ")
sniff(filter=netAddress, prn=packet_sniffer, iface="Ethernet", store=0, count=packetCount)
