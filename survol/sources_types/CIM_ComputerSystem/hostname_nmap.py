#!/usr/bin/env python

"""
Nmap network exploration results
"""

import sys
import re
import socket
import xml.dom.minidom
import lib_util
import lib_common
from lib_properties import pc

from sources_types import addr as survol_addr


def Main():
    paramkeyPortsRange = "Ports Range"

    cgiEnv = lib_common.ScriptEnvironment({paramkeyPortsRange: "22-443"})
    hostname = cgiEnv.GetId()
    node_host = lib_common.gUriGen.HostnameUri(hostname)

    # This is just a first experimentation with nmap.
    # Ideally, the port range could be changed in edit mode of this script.
    ports_range = cgiEnv.get_parameters(paramkeyPortsRange)
    args = ['nmap', '-oX', '-', hostname, '-p', ports_range ]

    # NOTE: This is completely similar to the script in the sources directory.
    try:
        p = lib_common.SubProcPOpen(args)
    except Exception as exc:
        lib_common.ErrorMessageHtml("Cannot find nmap:"+str(exc))

    grph = cgiEnv.GetGraph()

    nmap_last_output, nmap_err = p.communicate()

    try:
        dom = xml.dom.minidom.parseString(nmap_last_output)
    except xml.parsers.expat.ExpatError as exc:
        lib_common.ErrorMessageHtml("XML error:" + nmap_last_output+", caught:" + str(exc) )

    for dhost in dom.getElementsByTagName('host'):
        node_ip = dhost.getElementsByTagName('address')[0].getAttributeNode('addr').value

        grph.add((node_host, lib_common.MakeProp("IP"), lib_util.NodeLiteral(node_ip)))

        for dhostname in dhost.getElementsByTagName('hostname'):
            sub_hostnam = dhostname.getAttributeNode('name').value

            # grph.add( ( node_host, pc.property_hostname, lib_util.NodeLiteral( sub_hostnam ) ) )
            # It should be the same as the main hostname, which is taken as reference to avoid ambiguities.
            grph.add((node_host, lib_common.MakeProp("Hostname"), lib_util.NodeLiteral(sub_hostnam)))

        for dport in dhost.getElementsByTagName('port'):
            proto = dport.getAttributeNode('protocol').value

            # port number converted as integer
            port = int(dport.getAttributeNode('portid').value)
            socket_node = lib_common.gUriGen.AddrUri( hostname, port, proto)
            survol_addr.DecorateSocketNode(grph, socket_node, hostname, port, proto)

            state = dport.getElementsByTagName('state')[0].getAttributeNode('state').value
            grph.add((socket_node, lib_common.MakeProp("State"), lib_util.NodeLiteral(state)))
            
            reason = dport.getElementsByTagName('state')[0].getAttributeNode('reason').value
            grph.add((socket_node, lib_common.MakeProp("Reason"), lib_util.NodeLiteral(reason)))

            # name if any
            #for dname in dport.getElementsByTagName('service'):
            #    name = dname.getAttributeNode('name').value
            #    print("            name="+name)

            #for dscript in dport.getElementsByTagName('script'):
            #    script_id = dscript.getAttributeNode('id').value
            #    script_out = dscript.getAttributeNode('output').value
            #    print("script_id="+script_id)
            #    print("script_out="+script_out)

            # BEWARE: Normally the LHS node should be a process !!!
            grph.add((node_host, pc.property_has_socket, socket_node))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
