#!/usr/bin/env python

"""
Sockets in promiscuous mode
"""

# It works also for WindDump.exe, on Windows.

import os
import re
import sys
import time
import socket
import binascii
import struct
import lib_util
import lib_common
from lib_properties import pc

#Usable = lib_util.UsableAsynchronousSource

################################################################################

def _decode_port_number(pck, offset):
    port = 256 * pck[offset+0] + pck[offset+1]
    return port


def _bytes_to_addr(pck, offset):
    try:
        ip = "%d.%d.%d.%d" % ( pck[offset+12],pck[offset+13],pck[offset+14],pck[offset+15] )
        addr = socket.gethostbyaddr(ip)[0]
        return addr
    except socket.herror:
        return ""


def _insert_packet(grph, protoc , sourceAddr, sourcePort, destinationAddr, destinationPort):
    if protoc == 6:
        lsocketNode = lib_common.gUriGen.AddrUri(sourceAddr, sourcePort )
        rsocketNode = lib_common.gUriGen.AddrUri(destinationAddr, destinationPort )
        grph.add((lsocketNode, pc.property_socket_end, rsocketNode))

################################################################################


def _process_frame(grph, receivedPacket):

    protoc = receivedPacket[9]
    # 6 = TCP
    # 17 = UDP
    # 103 = PIM
    if protoc != 6: # TCP
        return

    ihl = receivedPacket[0] % 16
    # Cannot go further.
    if ihl <= 6 :
        return

    sourceAddr = _bytes_to_addr(receivedPacket, 12)
    destinationAddr = _bytes_to_addr(receivedPacket, 16)

    lenall = len(receivedPacket)
    if lenall >= 24:
        offBase = ihl * 4

        sourcePort = _decode_port_number(receivedPacket, offBase)
        destinationPort = _decode_port_number(receivedPacket, offBase + 2)
    else:
        sourcePort = 0
        destinationPort = 0

    _insert_packet(grph, protoc, sourceAddr, sourcePort, destinationAddr, destinationPort)


# The communication queue is made of protocol+addr+port+addr+port.
# The entity id should be the default value and is not relevant.
def _promiscuous_win(loop_number):

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

    # prevent socket from being left in TIME_WAIT state, enabling reuse
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((lib_util.currentHostname, 0))
    
    # Include IP headers
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    bufferSize=4096
    cgiEnv = lib_common.CgiEnv()
    while loop_number:
        loop_number -= 1
        grph = cgiEnv.ReinitGraph()
        # TODO: Avoid an allocation.
        package=s.recv(bufferSize)
        _process_frame(grph, package)
        # Less data otherwise it is not sustainable.
        time.sleep(0.2)
        cgiEnv.OutCgiRdf()

    # disable promiscuous mode
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


################################################################################


def _promiscuous_linux(loop_number):
    rawSocket=socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.htons(0x0800))

    cgiEnv = lib_common.CgiEnv()
    while loop_number:
        loop_number -= 1

        grph = cgiEnv.ReinitGraph()

        #ifconfig eth0 promisc up
        receivedPacket=rawSocket.recv(2048)
    
        #Ethernet Header...
        ethernetHeader=receivedPacket[0:14]
        ethrheader=struct.unpack("!6s6s2s",ethernetHeader)
        #destinationIP= binascii.hexlify(ethrheader[0])
        #sourceIP= binascii.hexlify(ethrheader[1])
        protoc = binascii.hexlify(ethrheader[2])
    
        #IP Header... 
        ipHeader=receivedPacket[14:34]
        ipHdr=struct.unpack("!12s4s4s",ipHeader)
        destinationIP=socket.inet_ntoa(ipHdr[2])
        sourceIP=socket.inet_ntoa(ipHdr[1])
    
        #TCP Header...
        tcpHeader=receivedPacket[34:54]
        tcpHdr=struct.unpack("!2s2s16s",tcpHeader)
        sourcePort = _decode_port_number(tcpHdr[0], 0)

        destinationPort = _decode_port_number(tcpHdr[1], 0)
        time.sleep(0.2)

        _insert_packet(grph, protoc, sourceIP, sourcePort, destinationIP, destinationPort)

        cgiEnv.OutCgiRdf()

################################################################################


def Main(loop_number = 1):
    try:
        if lib_util.isPlatformWindows:
            _promiscuous_win(loop_number)
        else:
            _promiscuous_linux(loop_number)
    except Exception as exc:
        lib_common.ErrorMessageHtml("Sockets in promiscuous mode:" + str(exc))


if __name__ == '__main__':
    if lib_util.is_snapshot_behaviour():
        Main()
    else:
        while True:
            Main(1000000)
            time.sleep(20)
