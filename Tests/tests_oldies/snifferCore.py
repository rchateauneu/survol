#!/usr/bin/python

import sys
import socket
import struct
import binascii
import time

def PortStr(receivedPacket,offset):
	port = 256*receivedPacket[offset+0] + receivedPacket[offset+1]
	try:
		portNam = socket.getservbyport( int(port) )
	except socket.error:
		portNam = str(port)
	return portNam


protoDict = {
	0:"HOPOPT, IPv6 Hop-by-Hop Option",
	1:"ICMP, Internet Control Message Protocol",
	2:"IGAP, IGMP, RGMP",
	3:"GGP, Gateway to Gateway Protocol",
	4:"IP in IP encapsulation",
	5:"ST, Internet Stream Protocol",
	6:"TCP, Transmission Control Protocol",
	7:"UCL, CBT",
	8:"EGP, Exterior Gateway Protocol",
	9:"IGRP, Interior Gateway Routing Protocol",
	10:"BBN RCC Monitoring",
	11:"NVP, Network Voice Protocol",
	12:"PUP",
	13:"ARGUS",
	14:"EMCON, Emission Control Protocol",
	15:"XNET, Cross Net Debugger",
	16:"Chaos",
	17:"UDP, User Datagram Protocol",
	18:"TMux, Transport Multiplexing Protocol",
	19:"DCN Measurement Subsystems",
	20:"HMP, Host Monitoring Protocol",
	21:"Packet Radio Measurement",
	22:"XEROX NS IDP",
	23:"Trunk-1",
	24:"Trunk-2",
	25:"Leaf-1",
	26:"Leaf-2",
	27:"RDP, Reliable Data Protocol",
	28:"IRTP, Internet Reliable Transaction Protocol",
	29:"ISO Transport Protocol Class 4",
	30:"NETBLT, Network Block Transfer",
	31:"MFE Network Services Protocol",
	32:"MERIT Internodal Protocol",
	33:"DCCP, Datagram Congestion Control Protocol",
	34:"Third Party Connect Protocol",
	35:"IDPR, Inter-Domain Policy Routing Protocol",
	36:"XTP, Xpress Transfer Protocol",
	37:"Datagram Delivery Protocol",
	38:"IDPR, Control Message Transport Protocol",
	39:"TP++ Transport Protocol",
	40:"IL Transport Protocol",
	41:"IPv6 over IPv4",
	42:"SDRP, Source Demand Routing Protocol",
	43:"IPv6 Routing header",
	44:"IPv6 Fragment header",
	45:"IDRP, Inter-Domain Routing Protocol",
	46:"RSVP, Reservation Protocol",
	47:"GRE, General Routing Encapsulation",
	48:"DSR, Dynamic Source Routing Protocol",
	49:"BNA",
	50:"ESP, Encapsulating Security Payload",
	51:"AH, Authentication Header",
	52:"I-NLSP, Integrated Net Layer Security TUBA",
	53:"SWIPE, IP with Encryption",
	54:"NARP, NBMA Address Resolution Protocol",
	55:"Minimal Encapsulation Protocol",
	56:"TLSP, Transport Layer Security Protocol using Kryptonet key management",
	57:"SKIP",
	58:"ICMPv6, Internet Control Message Protocol for IPv6,MLD, Multicast Listener Discovery",
	59:"IPv6 No Next Header",
	60:"IPv6 Destination Options",
	61:"Any host internal protocol",
	62:"CFTP",
	63:"Any local network",
	64:"SATNET and Backroom EXPAK",
	65:"Kryptolan",
	66:"MIT Remote Virtual Disk Protocol",
	67:"Internet Pluribus Packet Core",
	68:"Any distributed file system",
	69:"SATNET Monitoring",
	70:"VISA Protocol",
	71:"Internet Packet Core Utility",
	72:"Computer Protocol Network Executive",
	73:"Computer Protocol Heart Beat",
	74:"Wang Span Network",
	75:"Packet Video Protocol",
	76:"Backroom SATNET Monitoring",
	77:"SUN ND PROTOCOL-Temporary",
	78:"WIDEBAND Monitoring",
	79:"WIDEBAND EXPAK",
	80:"ISO-IP",
	81:"VMTP, Versatile Message Transaction Protocol",
	82:"SECURE-VMTP",
	83:"VINES",
	84:"TTP",
	85:"NSFNET-IGP",
	86:"Dissimilar Gateway Protocol",
	87:"TCF",
	88:"EIGRP",
	89:"OSPF, Open Shortest Path First Routing Protocol, MOSPF, Multicast Open Shortest Path First",
	90:"Sprite RPC Protocol",
	91:"Locus Address Resolution Protocol",
	92:"MTP, Multicast Transport Protocol",
	93:"AX",
	94:"IP-within-IP Encapsulation Protocol",
	95:"Mobile Internetworking Control Protocol",
	96:"Semaphore Communications Sec",
	97:"EtherIP",
	98:"Encapsulation Header",
	99:"Any private encryption scheme",
	100:"GMTP",
	101:"IFMP, Ipsilon Flow Management Protocol",
	102:"PNNI over IP",
	103:"PIM, Protocol Independent Multicast",
	104:"ARIS",
	105:"SCPS",
	106:"QNX",
	107:"Active Networks",
	108:"IPPCP, IP Payload Compression Protocol",
	109:"SNP, Sitara Networks Protocol",
	110:"Compaq Peer Protocol",
	111:"IPX in IP",
	112:"VRRP, Virtual Router Redundancy Protocol",
	113:"PGM, Pragmatic General Multicast",
	114:"any 0-hop protocol",
	115:"L2TP, Level 2 Tunneling Protocol",
	116:"DDX, D-II Data Exchange",
	117:"IATP, Interactive Agent Transfer Protocol",
	118:"ST, Schedule Transfer",
	119:"SRP, SpectraLink Radio Protocol",
	120:"UTI",
	121:"SMP, Simple Message Protocol",
	122:"SM",
	123:"PTP, Performance Transparency Protocol",
	124:"ISIS over IPv4",
	125:"FIRE",
	126:"CRTP, Combat Radio Transport Protocol",
	127:"CRUDP, Combat Radio User Datagram",
	128:"SSCOPMCE",
	129:"IPLT",
	130:"SPS, Secure Packet Shield",
	131:"PIPE, Private IP Encapsulation within IP",
	132:"SCTP, Stream Control Transmission Protocol",
	133:"Fibre Channel",
	134:"RSVP-E2E-IGNORE",
	135:"Mobility Header",
	136:"UDP-Lite, Lightweight User Datagram Protocol",
	137:"MPLS in IP",
	138:"MANET protocols",
	139:"HIP, Host Identity Protocol",
	140:"Shim6, Level 3 Multihoming Shim Protocol for IPv6",
	141:"WESP, Wrapped Encapsulating Security Payload",
	142:"ROHC, RObust Header Compression",
	254:"Experimentation and testing",
	255:"reserved"
}

def ProtoText(proto):
	try:
		return protoDict[proto]
	except KeyError:
		return "Unknown protocol:%s" % proto

def sniffer(bufferSize=65565, showPort=False, showRawData=False):
	# the public network interface
	HOST = socket.gethostbyname(socket.gethostname())
	
	# Linux: rawSocket=socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.htons(0x0800))
	# Windows s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
	# s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

	# prevent socket from being left in TIME_WAIT state, enabling reuse
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind((HOST, 0))
	
	# Include IP headers
	s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
	
	s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

	# What is used under Linux but with a different initialisation.	

	while True:
		package=s.recv(bufferSize)
		# package = s.recvfrom(bufferSize)
		try:
			printPacket(package)
		except Exception:
			exc = sys.exc_info()[1]
			print("Caught:%s" % str(exc) )
		# Other(package[0])
		# time.sleep(0.3)
	
	# disable promiscuous mode
	s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
	
def printPacket(receivedPacket):
	lenall = len(receivedPacket)

	protoc = receivedPacket[9]
	if protoc == 6:
		print("TCP")
	elif protoc == 17:
		print("UDP")
		return # POUR LE MOMENT
	elif protoc == 103:
		print("PIM")
		return # POUR LE MOMENT
	else:
		print( ProtoText(protoc) )
		return # POUR LE MOMENT



	print("Len="+str(lenall))
	#print("Pack="+str(receivedPacket))

	# Octet index 1.
	ihl = receivedPacket[0] % 16
	# print("ihl="+str(ihl))
	#if ihl == 5 :
	#	return

	print("ihl=%d" % ihl )
	# print("Total:%s" % str(package[1]) )

	try:
		ip1 = "%d.%d.%d.%d" % ( receivedPacket[12],receivedPacket[13],receivedPacket[14],receivedPacket[15])
		print("ip1=" + ip1 + " " + socket.gethostbyaddr(ip1)[0])
	except socket.herror:
		print("ip1=" + ip1 + " UNKNOWN")
		return

	try:
		ip2 = "%d.%d.%d.%d" % ( receivedPacket[16],receivedPacket[17],receivedPacket[18],receivedPacket[19])
		print("ip2=" + ip2 + " " + socket.gethostbyaddr(ip2)[0])
	except socket.herror:
		print("ip2=" + ip2 + " UNKNOWN")

	# Cannot go further.
	if ihl == 6 :
		return

	# print('Data:', package[0])
	maxlen = 60
	if maxlen > lenall:
		maxlen = lenall

	for i  in range(0,ihl*4):
		sys.stdout.write("%d " % receivedPacket[i])
	sys.stdout.write("\n")
	for i  in range(ihl*4,maxlen):
		sys.stdout.write("%d " % receivedPacket[i])
	sys.stdout.write("\n")

	#TCP Header...
	#tcpHeader=receivedPacket[34:54]
	#tcpHdr=struct.unpack("!2s2s16s",tcpHeader)
	#sourcePort = 256*tcpHdr[0][0] + tcpHdr[0][1]
	#destinationPort=256*tcpHdr[1][0] + tcpHdr[1][1]

	if lenall < 44:
		return

	# offBase = 34
	offBase = ihl * 4
	


	sourcePort = PortStr(receivedPacket, offBase )
	destinationPort = PortStr(receivedPacket, offBase + 2)

	print("Source Port:%s" % sourcePort)
	print("Destination Port:%s" % destinationPort)
	
	#if( receivedPacket[20] == 80 or receivedPacket[21] == 80 or receivedPacket[22] == 80 or receivedPacket[23] == 80 ):
	#	sys.exit(0)


	print('')


sniffer() 


