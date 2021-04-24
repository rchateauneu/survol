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

import lib_uris
import lib_util
import lib_common
from lib_properties import pc

################################################################################

def _decode_port_number(pck, offset):
    port = 256 * pck[offset+0] + pck[offset+1]
    return port


def _bytes_to_addr(pck, offset):
    try:
        ip = "%d.%d.%d.%d" % (pck[offset+12], pck[offset+13], pck[offset+14], pck[offset+15])
        addr = socket.gethostbyaddr(ip)[0]
        return addr
    except socket.herror:
        return ""


def _insert_packet(grph, protoc, source_addr, source_port, destination_addr, destination_port):
    if protoc == 6:
        lsocket_node = lib_uris.gUriGen.AddrUri(source_addr, source_port)
        rsocket_node = lib_uris.gUriGen.AddrUri(destination_addr, destination_port)
        grph.add((lsocket_node, pc.property_socket_end, rsocket_node))

################################################################################


def _process_frame(grph, received_packet):

    protoc = received_packet[9]
    # 6 = TCP
    # 17 = UDP
    # 103 = PIM
    if protoc != 6: # TCP
        return

    ihl = received_packet[0] % 16
    # Cannot go further.
    if ihl <= 6 :
        return

    source_addr = _bytes_to_addr(received_packet, 12)
    destination_addr = _bytes_to_addr(received_packet, 16)

    lenall = len(received_packet)
    if lenall >= 24:
        off_base = ihl * 4

        source_port = _decode_port_number(received_packet, off_base)
        destination_port = _decode_port_number(received_packet, off_base + 2)
    else:
        source_port = 0
        destination_port = 0

    _insert_packet(grph, protoc, source_addr, source_port, destination_addr, destination_port)


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

    buffer_size = 4096
    cgiEnv = lib_common.ScriptEnvironment()
    while loop_number:
        loop_number -= 1
        grph = cgiEnv.ReinitGraph()
        # TODO: Avoid an allocation.
        package = s.recv(buffer_size)
        _process_frame(grph, package)
        # Less data otherwise it is not sustainable.
        time.sleep(0.2)
        cgiEnv.OutCgiRdf()

    # disable promiscuous mode
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


################################################################################


def _promiscuous_linux(loop_number):
    raw_socket=socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))

    cgiEnv = lib_common.ScriptEnvironment()
    while loop_number:
        loop_number -= 1

        grph = cgiEnv.ReinitGraph()

        #ifconfig eth0 promisc up
        received_packet = raw_socket.recv(2048)
    
        #Ethernet Header...
        ethernet_header = received_packet[0:14]
        ethrheader = struct.unpack("!6s6s2s", ethernet_header)
        #destination_ip= binascii.hexlify(ethrheader[0])
        #source_ip= binascii.hexlify(ethrheader[1])
        protoc = binascii.hexlify(ethrheader[2])
    
        #IP Header... 
        ip_header = received_packet[14:34]
        ip_hdr = struct.unpack("!12s4s4s", ip_header)
        destination_ip = socket.inet_ntoa(ip_hdr[2])
        source_ip=socket.inet_ntoa(ip_hdr[1])
    
        #TCP Header...
        tcp_header = received_packet[34:54]
        tcp_hdr = struct.unpack("!2s2s16s", tcp_header)
        source_port = _decode_port_number(tcp_hdr[0], 0)

        destination_port = _decode_port_number(tcp_hdr[1], 0)
        time.sleep(0.2)

        _insert_packet(grph, protoc, source_ip, source_port, destination_ip, destination_port)

        cgiEnv.OutCgiRdf()


def Snapshot(loop_number=1):
    try:
        if lib_util.isPlatformWindows:
            _promiscuous_win(loop_number)
        else:
            _promiscuous_linux(loop_number)
    except Exception as exc:
        lib_common.ErrorMessageHtml("Sockets in promiscuous mode:" + str(exc))


def Main():
    if lib_util.is_snapshot_behaviour():
        Snapshot()
    else:
        while True:
            Snapshot(1000000)
            time.sleep(20)


if __name__ == '__main__':
    Main()
