#!/usr/bin/env python

"""
Nmap network exploration results
"""

import sys
import re
import socket
import xml.dom.minidom

import lib_uris
import lib_util
import lib_common
from lib_properties import pc


def Main():
    paramkey_ports_range = "Ports Range"
    paramkey_graph_display = "Graph display"

    cgiEnv = lib_common.ScriptEnvironment(
            {paramkey_ports_range: "22-443", paramkey_graph_display: False})

    # This is just a first experimentation with nmap.
    # This scans a couple of ports from the current host.
    # Ideally, the port range could be changed in edit mode of this script.
    # xyz = "C:\\Program Files (x86)\\Nmap\\nmap.exe"
    # nmap_path="nmap"
    # The program nmap must be in the PATH.
    # args = ["nmap", '-oX', '-', '127.0.0.1', '-p', '22-443' ]

    ports_range = cgiEnv.get_parameters(paramkey_ports_range)
    args = ["nmap", '-oX', '-', '127.0.0.1', '-p', ports_range]

    is_graph_display = cgiEnv.get_parameters(paramkey_graph_display)
    
    p = lib_common.SubProcPOpen(args)

    grph = cgiEnv.GetGraph()

    nmap_last_output, nmap_err = p.communicate()

    dom = xml.dom.minidom.parseString(nmap_last_output)

    for dhost in dom.getElementsByTagName('host'):
        host = dhost.getElementsByTagName('address')[0].getAttributeNode('addr').value
        nodeHost = lib_uris.gUriGen.HostnameUri(host)
        for dhostname in dhost.getElementsByTagName('hostname'):
            hostnam = dhostname.getAttributeNode('name').value
            grph.add((nodeHost, pc.property_hostname, lib_util.NodeLiteral(hostnam)))

        for dport in dhost.getElementsByTagName('port'):
            # protocol
            proto = dport.getAttributeNode('protocol').value
            port = int(dport.getAttributeNode('portid').value)
            socket_node = lib_uris.gUriGen.AddrUri(host, port, proto)

            if not is_graph_display:
                state = dport.getElementsByTagName('state')[0].getAttributeNode('state').value
                grph.add((socket_node, lib_common.MakeProp("State"), lib_util.NodeLiteral(state)))
                
                reason = dport.getElementsByTagName('state')[0].getAttributeNode('reason').value
                grph.add((socket_node, lib_common.MakeProp("Reason"), lib_util.NodeLiteral(reason)))

            # BEWARE: Normally the LHS node should be a process !!!
            grph.add((nodeHost, pc.property_has_socket, socket_node))

    if is_graph_display:
        cgiEnv.OutCgiRdf()
    else:
        cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_has_socket])


if __name__ == '__main__':
    Main()
