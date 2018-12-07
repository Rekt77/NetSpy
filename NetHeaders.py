import binascii
from struct import *
from dnslib import *
from NetUtils import *
import string
from NetHeaders import *

TCP = '06'
UDP = '11'
IPV4 = '0800'
DNS = '53'
HTTP = '80'
SMTP = '25'
DNS_QUERY_MESSAGE_HEADER = Struct("!6H")


class Ethernet():
    def __init__(self,header):
        eth=unpack("!6s6s2s",header)
        self.DstMAC= MAC_format(binascii.hexlify(eth[0]).decode())
        self.SrcMAC= MAC_format(binascii.hexlify(eth[1]).decode())
        self.Type = binascii.hexlify(eth[2]).decode()
        
    def Display(self):
        print("-"*79)
        print("\n\n\n\n")
        print("[+] ETH Header")
        print("Src MAC: "+self.SrcMAC," Dst MAC: "+self.DstMAC)
        print("Ethernet Type: "+self.Type)

class IPheader():
    def __init__(self,header):
        iph = unpack("!12s4s4s",header)
        iph_12 = binascii.hexlify(iph[0]).decode()
        self.Version = iph_12[0]
        self.HeaderLength = iph_12[1]
        self.ToS = iph_12[2:4]
        self.TotalLength = iph_12[4:8]
        self.Identification = iph_12[8:12]
        self.Flags = iph_12[12:14]
        self.FragOffset = iph_12[14:16]
        self.TTL = iph_12[16:18]
        self.Proto = iph_12[18:20]
        self.Checksum = iph_12[20:24]
        self.Srcip = socket.inet_ntoa(iph[1])
        self.Dstip = socket.inet_ntoa(iph[2])

    def Display(self):
        print("[+] IP Header")
        print("SrcIP: "+self.Srcip, " DstIP: "+self.Dstip)
        print("Version: "+self.Version, " Header Length: "+self.HeaderLength)
        print("ToS: "+self.ToS," Total Length: "+self.TotalLength)
        print("ID: "+self.Identification," FLAGS: "+self.Flags)
        print("TTL: "+self.TTL," Proto: "+self.Proto)

class TCPheader():
    def __init__(self,header):
        tcph=unpack("!2s2s16s",header)
        tcph_16 = binascii.hexlify(tcph[2]).decode()
        self.SrcPort=str(int(binascii.hexlify(tcph[0]).decode(),16))
        self.DstPort=str(int(binascii.hexlify(tcph[1]).decode(),16))
        self.Seqnum = tcph_16[0:8]
        self.ACKnum = tcph_16[8:16]
        self.HeaderLength = tcph_16[16:18]
        self.Flag = tcph_16[18:20]
        self.Windowsize = tcph_16[20:24]
        self.Checksum = tcph_16[24:28]
        self.URGpointer = tcph_16[28:32]

    def Display(self):
        print("[+] TCP Header")
        print("SrcPort: "+self.SrcPort, " DstPort: "+self.DstPort)
        print("Seqnum: "+self.Seqnum, " ACKnum: "+self.ACKnum)
        print("Header Length: "+self.HeaderLength," Flag: "+self.Flag)
        print("Window size: "+self.Windowsize," Checksum: "+self.Checksum)
        print("URGpointer: "+self.URGpointer)
     
class UDPheader():
    def __init__(self,header):
        udph=unpack("!2s2s2s2s",header)
        self.SrcPort=str(int(binascii.hexlify(udph[0]).decode(),16))
        self.DstPort=str(int(binascii.hexlify(udph[1]).decode(),16))
        self.Length = binascii.hexlify(udph[2]).decode()
        self.Checksum = binascii.hexlify(udph[3]).decode()

    def Display(self):
        print("[+] UDP Header")
        print("SrcPort: "+self.SrcPort, " DstPort: "+self.DstPort)
        print("Seqnum: "+self.Length, " ACKnum: "+self.Checksum)
        
class HTTPheader():
    Request=False
    Method=None
    Response=False

    def __init__(self,header):
        self.httph=header.hex()

    def isRequest(self):
        if self.httph.find("474554") == 0:
            self.Request=True
            self.Method="GET"

        if self.httph.find("504f5354") == 0:
            self.Request=True
            self.Method="POST"

        if self.httph.find("48545450") >= 0 and self.Request == False:
            self.Response=True

    def Display(self):
        self.isRequest()
        if self.Request == True or self.Response == True:
            print("[+] HTTP Header")
            if self.Response == True:
                print("Version: "+ "HTTP/1.1 Response")

            if self.Request == True:
                print("Version: "+ "HTTP/1.1 %s Request"%self.Method)

            for each_line in self.httph.split('0d0a'):
                try:
                    print(bytearray.fromhex(each_line).decode())
                except:
                    pass

class DNSheader():
    def __init__(self,header):
        dnsh=unpack("!2s2s2s2s2s2s",header)
        self.TransactID=binascii.hexlify(dnsh[0]).decode()
        self.Flags=binascii.hexlify(dnsh[1]).decode()
        self.Questions = binascii.hexlify(dnsh[2]).decode()
        self.Answer_RRs = binascii.hexlify(dnsh[3]).decode()
        self.Authority_RRs = binascii.hexlify(dnsh[4]).decode()
        self.Additional_RRs = binascii.hexlify(dnsh[5]).decode()

    def Display(self):
        print("[+] DNS Header")
        print("TransactID: "+self.TransactID, " Flags: "+self.Flags)
        print("Questions: "+self.Questions, " Answer_RRs: "+self.Answer_RRs)
        print("Authority_RRs: "+self.Authority_RRs, " Additional_RRs: "+self.Additional_RRs)

class SMTPheader():
    isServer=False
    isClient=False

    def __init__(self,smtp_header,portTuple):
        self.tcp_port=portTuple
        self.smtph = smtp_header.hex()
    
    def isFragmented(self):
        if self.smtph.find("46726f6d") == 0:
            self.Fragmented=True

    def machineCheck(self):
        if self.tcp_port[0] == SMTP:
            self.isServer = True

        if self.tcp_port[1] == SMTP:
            self.isClient = True

    def Display(self):
        self.machineCheck()
        print("[+] SMTP Header")
        if self.isClient == True:
            print("CLIENT: ", end="")

        if self.isServer == True:
            print("SERVER: ", end= "")

        for each_line in self.smtph.split('0d0a'):
            try:
                print(bytearray.fromhex(each_line).decode())
            except:
                pass

class BitTorrentheader():
    isHandShake = False
    Length =""
    Proto ="Bit Torrent"
    ExtensionBytes = ""
    SHA1 = ""
    PeerID = ""

    def __init__(self,bittorrent_header):
        self.bith = bittorrent_header.hex()
        self.HandShake()
        if self.isHandShake == True:
            self.Length = self.bith[0:2]
            self.Proto = bytearray.fromhex(self.bith[2:40]).decode()
            self.ExtensionBytes = self.bith[40:56]
            self.SHA1 = self.bith[56:96]
            self.PeerID = self.bith[96:116]

    def HandShake(self):
        if self.bith[2:40] == "426974546f7272656e742070726f746f636f6c":
            self.isHandShake=True

    def Display(self):
        print("[+] BitTorrent Header")
        print("Length: "+self.Length, " Proto: "+self.Proto)
        print("Extension: "+self.ExtensionBytes, " SHA1: "+self.SHA1)
        print("Peer ID: "+self.PeerID)