#!/usr/bin/env python
import sys
import struct
import os
import socket

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import Ether, IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR

V = 2

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "ens4" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find ens4 interface")
        exit(1)
    return iface


class UpdateData(Packet):
    name = "UpdateData"
    fields_desc=[ 
        BitField("read", 0, 32),
        BitField("rtt", 0, 32),
        BitField("srcIP", 0, 32),
        BitField("dstIP", 0, 32),
        BitField("srcPort", 0, 16),
        BitField("dstPort", 0, 16)
        ]

pnum = 0
recievedInfo = {}
rtts = []
tail_flows = []

def handle_pkt(pkt):
    if  len(pkt) == 80: # or Ether in pkt and pkt[Ether].src == '00:00:ff:ff:ff:ff':
        print("got a packet", len(pkt))
        global pnum
        global recievedInfo
        parsed_pkt = UpdateData(_pkt=bytes(pkt)) 
        if V == 1:
            print("got a packet: ", pnum)
            
        if V == 2:
            parsed_pkt2 = Ether(_pkt=bytes(parsed_pkt[1])) 
            parsed_pkt.show2() 
            parsed_pkt2.show2()
        pnum += 1

        if(parsed_pkt.read > 0):
            rtts.append(parsed_pkt[UpdateData].rtt)
            tail_flows.append([parsed_pkt[UpdateData].srcIP , parsed_pkt[UpdateData].dstIP , parsed_pkt[UpdateData].srcPort , parsed_pkt[UpdateData].dstPort])

        sys.stdout.flush()

def intToIP(ip):
    return socket.inet_ntoa(struct.pack('!L', ip))

def main():
    if len(sys.argv)<2:
        print('pass 1 arguments: <outpuFile>')
        exit(1)
    global recievedInfo
    # this recieves traffic on iface ens4(Change according to your needs)
    iface = 'ens4'
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    """
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))
    """    

    sniff(iface = iface,
        prn = lambda x: handle_pkt(x))
    print("stopped")
    print("Writing in file")
    filename = sys.argv[1]
    f = open(filename, "w")
    for i in range(len(rtts)):
        k = tail_flows[i]
        k2 = rtts[i]
        f.write(str(intToIP(k[1])) + " " + str(intToIP(k[0])) + " " + str(k[3]) + " " + str(k[2]) + " " + str(round(k2/1000000000, 3)) + "\n")
    print("Writen")
    exit()


if __name__ == '__main__':
    main()