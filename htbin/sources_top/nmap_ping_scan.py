#!/usr/bin/python

"""
Nmap ping scan
LAN ping (256 addresses)
"""

import sys
import rdflib
import subprocess
import xml.dom.minidom
import lib_util
import lib_common
from lib_properties import pc

# socket.gethostbyname(lib_util.currentHostname) Renvoie "127.0.0.1"

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
#hostAddr = socket.gethostbyname(lib_util.currentHostname)
#hostSplit = hostAddr.split('.')
#hostSplit[3] = "0"
#netMask = '.'.join( hostSplit ) + "/24"
#
#sys.stderr.write("hostName=%s hostAddr=%s netMask=%s\n" % ( lib_util.currentHostname, hostAddr, netMask ) )

def Main():
	paramkeyPortsRange = "Ports Range"

	cgiEnv = lib_common.CgiEnv(
			"http://nmap.org/images/nmap-logo-64px.png"
			)

	netMask = "192.168.1.0/24"

	# "sP" is ping scan.
	# args = ["nmap", '-oX', '-', '-sP', '192.168.1.0/24', ]
	args = ["nmap", '-oX', '-', '-sP', netMask, ]

	# TODO: Get the netmask for the interface.

	try:
		# The program nmap must be in the PATH.
		p = subprocess.Popen(args, bufsize=100000, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	except WindowsError: # On Windows, this cannot find "FileNotFoundError"
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Cannot find nmap:"+str(exc)+". Maybe a dependency problem")
	except FileNotFoundError:
		lib_common.ErrorMessageHtml("Cannot find nmap")

	grph = rdflib.Graph()

	(nmap_last_output, nmap_err) = p.communicate()

	dom = xml.dom.minidom.parseString(nmap_last_output)


	# <host><status state="down" reason="no-response"/>
	# <address addr="192.168.1.67" addrtype="ipv4" />
	# </host>
	# <host><status state="up" reason="syn-ack"/>
	# <address addr="192.168.1.68" addrtype="ipv4" />
	# <hostnames><hostname name="Unknown-00-18-e7-08-02-81.home" type="PTR" /></hostnames>
	# </host>


	for dhost in dom.getElementsByTagName('host'):
		status = dhost.getElementsByTagName('status')[0].getAttributeNode('state').value
		if status != "up":
			continue

		host = dhost.getElementsByTagName('address')[0].getAttributeNode('addr').value
		# print("host="+host)
		nodeHost = lib_common.gUriGen.HostnameUri( host )
		for dhostname in dhost.getElementsByTagName('hostname'):
			hostnam = dhostname.getAttributeNode('name').value
		#	print("        hostnam="+hostnam)
			grph.add( ( nodeHost, pc.property_hostname, rdflib.Literal( hostnam ) ) )

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
