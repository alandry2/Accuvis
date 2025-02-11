from scapy.all import *
from scapy.all import IP, TCP

res, unans = sr( IP(dst="10.0.0.1") #typically we want the GUI to have user input what IP address they want to ping
                /TCP(flags="S", dport=(1,1024)) )