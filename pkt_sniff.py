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
    print("\n")
    receivedPacket=rawSocket.recv(65565)
    #eth header : 6byte string*2,2byte string == 14byte
    #ip header : 12byte string,4byte string*2 == 20byte
    #tcp header : optionaly, it's 32 bytes but normaly it's 20 bytes

    ethernet_header = Ethernet(receivedPacket[0:14])
    ip_header = IPheader(receivedPacket[14:34])
    ethLength = 14
    iphLength = 34

    

    if ip_header.Proto == TCP:
        ethernet_header.Display()
        HeaderDisplay("Ether",receivedPacket[0:ethLength])

        ip_header.Display()
        HeaderDisplay("IP",receivedPacket[ethLength:iphLength])

        tcp_header = TCPheader(receivedPacket[iphLength:54])
        tcphLength = int(iphLength+int(tcp_header.HeaderLength,16)/4)
        tcp_header.Display()
        HeaderDisplay("TCP",receivedPacket[iphLength:tcphLength])
        if tcp_header.SrcPort == HTTP or tcp_header.DstPort == HTTP:
            try:
                http_header = HTTPheader(receivedPacket[tcphLength:])
                http_header.Display()
                HeaderDisplay("HTTP",receivedPacket[tcphLength:])
            except:
                pass

        if tcp_header.SrcPort == SMTP or tcp_header.DstPort == SMTP:
            try:
                smtp_header = SMTPheader(receivedPacket[tcphLength:],(tcp_header.SrcPort,tcp_header.DstPort))
                smtp_header.Display()
                HeaderDisplay("SMTP",receivedPacket[tcphLength:])
            except:
                pass

        if receivedPacket[tcphLength+1:tcphLength+20].hex() == "426974546f7272656e742070726f746f636f6c":
            bit_header = BitTorrentheader(receivedPacket[tcphLength:])
            bit_header.Display()
            bit_seqs.append(int(tcp_header.Seqnum,16) + len(receivedPacket[tcphLength:]))
            HeaderDisplay("BitTorrent",receivedPacket[tcphLength:])
        
        if int(tcp_header.ACKnum,16) in bit_seqs:
            bit_header = BitTorrentheader(receivedPacket[tcphLength:])
            bit_header.Display()
            HeaderDisplay("BitTorrent",receivedPacket[tcphLength:])



    elif ip_header.Proto == UDP:
        ethernet_header.Display()
        HeaderDisplay("Ether",receivedPacket[0:ethLength])

        ip_header.Display()
        HeaderDisplay("IP",receivedPacket[ethLength:iphLength])
        udp_header=UDPheader(receivedPacket[34:42])
        udp_header.Display()
        HeaderDisplay("UDP",receivedPacket[34:42])
        if udp_header.SrcPort == DNS or udp_header.DstPort == DNS:
            dns_header = DNSheader(receivedPacket[42:54])
            dns_header.Display()
            print(DNSRecord.parse(receivedPacket[42:]))
            HeaderDisplay("DNS",receivedPacket[42:])
    print("\n")

