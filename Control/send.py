import argparse
import sys
import socket
import random
import struct
import time

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import IntField
from scapy.all import Ether, IP, UDP, TCP

THRESHOLD = 18
verbose = 1

class MyFlow(Packet):
    name = "MyFlow"
    fields_desc=[ IntField("id",0) ]

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "ens3" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find ens3 interface")
        exit(1)
    return iface

def main():

    if len(sys.argv)<2:
        print('pass 1 arguments: <testfile>')
        exit(1)

    

    print("Sending multiple packet")
    payload = "hello"
    
    iface = get_if()
    s = conf.L2socket(iface=iface)
    
    filename = sys.argv[1]
    f = open(filename, "r")


    while(True):
        line = f.readline()
        if not line:
            break
        latency = float(line)
        print(latency)
        srcIP = socket.inet_ntoa(struct.pack('!L', random.randint(0,65535)))
        dstIP = socket.inet_ntoa(struct.pack('!L', random.randint(0,65535)))
        srcPort = random.randint(0,65535)
        dstPort = random.randint(0,65535)
        seqNr = 20
        # Send SynPkt
        synPkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        synPkt = synPkt /IP(src=srcIP, dst=dstIP, proto=6) /TCP(dport=dstPort, sport=srcPort, flags="S", seq=seqNr) / payload
        packetLen = len(synPkt)
        if verbose == 1:
            synPkt.show()
        s.send(synPkt)
        
        time.sleep(latency)
        
        # Send AckPkt
        ackNr = seqNr + len(payload) + 1
        ackPkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        ackPkt = ackPkt /IP(src=dstIP, dst=srcIP, proto=6) /TCP(sport=dstPort, dport=srcPort, flags="A", ack=ackNr) / payload
        if verbose == 1:
            ackPkt.show()
        s.send(ackPkt)
    


main()
   