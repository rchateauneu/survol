#!/usr/bin/env python

"""
Nmap ping scan
LAN ping (256 addresses)
"""

import sys
import socket
import xml.dom.minidom
import lib_util
import lib_common
from lib_properties import pc

# lib_util.GlobalGetHostByName(lib_util.currentHostname) Renvoie "127.0.0.1"

# http://stackoverflow.com/questions/3698901/retrieving-netmask-for-interfaces-with-multiple-ip-addresses-using-python
#
#import fcntl
#
#SIOCGIFNETMASK = 0x891b
#
#def get_network_mask(ifname):
#    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#    netmask = fcntl.ioctl(s, SIOCGIFNETMASK, struct.pack('256s', ifname))[20:24]
#    return socket.inet_ntoa(netmask)
#
#>>> get_network_mask('eth0')
#'255.255.255.0'
#
# /sbin/ip addr show
#3: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast qlen 1000
#    link/ether 00:18:e7:08:02:81 brd ff:ff:ff:ff:ff:ff
#    inet 192.168.1.68/24 brd 192.168.1.255 scope global eth0
#    inet6 fe80::218:e7ff:fe08:281/64 scope link
#       valid_lft forever preferred_lft forever
#


# Calculates a mask, similar to "192.168.1.0/24"
def Main():
    paramkeyPortsRange = "Ports Range"

    cgiEnv = lib_common.ScriptEnvironment()

    # net_mask = "192.168.1.0/24"

    # '10.102.235.173'
    local_ip_addr = lib_util.GlobalGetHostByName(socket.gethostname())
    
    split_ip_addr = local_ip_addr.split(".")
    
    split_ip_addr[3] = "0"
    net_mask = ".".join(split_ip_addr) + "/24"
    
    # "sP" is ping scan.
    # args = ["nmap", '-oX', '-', '-sP', '192.168.1.0/24', ]
    args = ["nmap", '-oX', '-', '-sP', net_mask,]

    # TODO: Get the netmask for the interface.

    # The program nmap must be in the PATH.
    p = lib_common.SubProcPOpen(args)
    #except WindowsError: # On Windows, this cannot find "FileNotFoundError"
    #    exc = sys.exc_info()[1]
    #    lib_common.ErrorMessageHtml("Cannot find nmap:"+str(exc)+". Maybe a dependency problem")
    #except FileNotFoundError:
    #    lib_common.ErrorMessageHtml("Cannot find nmap")
    #except : # On Windows, this cannot find "FileNotFoundError"
    #    exc = sys.exc_info()
    #    lib_common.ErrorMessageHtml("Cannot run nmap:"+str(exc))

    grph = cgiEnv.GetGraph()

    nmap_last_output, nmap_err = p.communicate()

    dom = xml.dom.minidom.parseString(nmap_last_output)

    # <host><status state="down" reason="no-response"/>
    # <address addr="192.168.1.67" addrtype="ipv4" />
    # </host>
    # <host><status state="up" reason="syn-ack"/>
    # <address addr="192.168.1.68" addrtype="ipv4" />
    # <hostnames><hostname name="Unknown-00-18-e7-08-02-81.home" type="PTR" /></hostnames>
    # </host>

    # Possibly
    # <address addr="08:2E:5F:13:0E:48" addrtype="mac" vendor="Hewlett Packard"/>

    for dhost in dom.getElementsByTagName('host'):
        status = dhost.getElementsByTagName('status')[0].getAttributeNode('state').value
        
        node_host = None
        addr_vendor = None
        
        # TODO: This could be an option. Test this.
        if status != "up":
            continue

        for addr_element in dhost.getElementsByTagName('address'):
            # "mac", "ipv4"
            addr_type = addr_element.getAttributeNode('addrtype').value
            if addr_type == "ipv4":
                host = addr_element.getAttributeNode('addr').value
                # sys.stderr.write("host=%s\n"%host)
                node_host = lib_common.gUriGen.HostnameUri( host )
            elif addr_type == "mac":
                try:
                    addr_vendor = addr_element.getAttributeNode('vendor').value
                    mac_addr = addr_element.getAttributeNode('addr').value
                except:
                    addr_vendor = None

        if node_host:
            if addr_vendor:
                grph.add((node_host, lib_common.MakeProp("MAC address"), lib_util.NodeLiteral(mac_addr)))
                grph.add((node_host, lib_common.MakeProp("Vendor"), lib_util.NodeLiteral(addr_vendor)))
        
        for dhostname in dhost.getElementsByTagName('hostname'):
            hostnam = dhostname.getAttributeNode('name').value
            # sys.stderr.write("    hostnam=%s\n"%hostnam)
            grph.add((node_host, pc.property_hostname, lib_util.NodeLiteral(hostnam)))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
