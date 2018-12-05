#!/usr/bin/python3

import socket, sys
import binascii
import string
from struct import *
from dnslib import *
from NetHeaders import *
from NetUtils import *

#Eth:14Byte
#IP:20Byte
#TCP:20Byte
#UDP: 8Byte
#Application level Data appears after 54 bytes from very first byte of TCP byte sequence

try:
#If you want to handle low level network packet, you need raw socket with option PF_PACKET
	 rawSocket=socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.htons(0x0800))
except socket.error:
    print('Socket could not be created.')
    sys.exit()

while True:
    receivedPacket=rawSocket.recv(65565)
    #eth header : 6byte string*2,2byte string == 14byte
    #ip header : 12byte string,4byte string*2 == 20byte
    #tcp header : 20 bytes string
    ethernet_header = Ethernet(receivedPacket[0:14])
    ip_header = IPheader(receivedPacket[14:34])

    if ip_header.Proto == TCP:
        tcp_header = TCPheader(receivedPacket[34:54])
        ethernet_header.Display()
        HeaderDisplay("Ether",receivedPacket[0:14])

        ip_header.Display()
        HeaderDisplay("IP",receivedPacket[14:34])

        tcp_header.Display()
        HeaderDisplay("TCP",receivedPacket[34:54])

        if tcp_header.SrcPort == HTTP or tcp_header.DstPort == HTTP:
            http_header = HTTPheader(receivedPacket[54:])
            http_header.Display()
            HeaderDisplay("HTTP",receivedPacket[54:])

        print("\n")

    elif ip_header.Proto == UDP:
        udp_header=UDPheader(receivedPacket[34:42])
        udp_header.Display()
        HeaderDisplay("UDP",receivedPacket[34:42])
        if udp_header.SrcPort == DNS or udp_header.DstPort == DNS:
            dns_header = DNSheader(receivedPacket[42:54])
            dns_header.Display()
            print(DNSRecord.parse(receivedPacket[42:]))

