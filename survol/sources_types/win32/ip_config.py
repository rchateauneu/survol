#!/usr/bin/python

"""
IP configuration
"""

import os
import sys
import subprocess
import lib_common
import lib_util
from lib_properties import pc

from sources_types import CIM_NetworkAdapter

# IP configuraton

# >>> for n in w.Win32_NetworkAdapter():
# ...     print(n)
#
# instance of Win32_NetworkAdapter
# {
#         AdapterType = "Ethernet 802.3";
#         AdapterTypeId = 0;
#         Availability = 3;
#         Caption = "[00000007] Realtek PCIe GBE Family Controller";
#         ConfigManagerErrorCode = 0;
#         ConfigManagerUserConfig = FALSE;
#         CreationClassName = "Win32_NetworkAdapter";
#         Description = "Realtek PCIe GBE Family Controller";
#         DeviceID = "7";
#         GUID = "{372DB82B-FE28-489B-B744-FC1C0F726791}";
#         Index = 7;
#         Installed = TRUE;
#         InterfaceIndex = 11;
#         MACAddress = "8C:DC:D4:34:D4:38";
#         Manufacturer = "Realtek";
#         MaxNumberControlled = 0;
#         Name = "Realtek PCIe GBE Family Controller";
#         NetConnectionID = "Local Area Connection";
#         NetConnectionStatus = 2;
#         NetEnabled = TRUE;
#         PhysicalAdapter = TRUE;
#         PNPDeviceID = "PCI\\VEN_10EC&DEV_8168&SUBSYS_18E9103C&REV_0C\\4&11DD9C9B&0&00E2";
#         PowerManagementSupported = FALSE;
#         ProductName = "Realtek PCIe GBE Family Controller";
#         ServiceName = "RTL8167";
#         Speed = "100000000";
#         SystemCreationClassName = "Win32_ComputerSystem";
#         SystemName = "RCHATEAU-HP";
#         TimeOfLastReset = "20171014214032.375199+060";
# };
#

# C:\Python27\python.exe C:/Users/rchateau/Developpement/ReverseEngineeringApps/PythonStyle/Experimental/Test_ip_config.py
# Ethernet adapter Local Area Connection
#     Connection-specific DNS Suffix :
#   = DESCRIPTION:Realtek PCIe GBE Family Controller
#     Physical Address : 8C-DC-D4-34-D4-38
#     DHCP Enabled : Yes
#     Autoconfiguration Enabled : Yes
#     Link-local IPv6 Address : fe80::3c7a:339:64f0:2161%11(Preferred)
#   = ADDRESS:192.168.0.14()
#     Subnet Mask : 255.255.255.0
#     Lease Obtained : 14 October 2017 21:40:58
#     Lease Expires : 24 October 2017 21:40:58
#   = GATEWAY:192.168.0.1
#   = DHCP:192.168.0.1
#     DHCPv6 IAID : 244112596
#     DHCPv6 Client DUID : 00-01-00-01-1C-9B-61-ED-8C-DC-D4-34-D4-38
#   = DNS:194.168.4.100
#   = DNS:194.168.8.100
#     NetBIOS over Tcpip : Enabled


def CreateIpConfigData():
	"""
		This loads into a map the result of IPCONFIG command.
	"""
	mapIpconfigs = dict()
	currItf = ""
	proc = subprocess.Popen(['ipconfig','/all'],stdout=subprocess.PIPE)
	for currLine in proc.stdout.readlines():
		currLine = currLine.decode("utf-8").rstrip()
		if currLine:
			if currLine[0] != " ":
				currItf = currLine.strip()
				if currItf[-1] == ":":
					currItf = currItf[:-1]
				mapIpconfigs[currItf] = []
			else:
				idxColon = currLine.find(":")
				if idxColon >= 0:
					currKey = currLine[:idxColon].replace(". ","").strip()
					currVal = currLine[idxColon+1:].strip()
				else:
					currVal = currLine.strip()
				mapIpconfigs[currItf].append( (currKey, currVal))
	return mapIpconfigs

def AddOneNodeIpConfig(grph,rootNode,keyMap,subMapIpconfigs):

	txtDescription = None

	# if key.startswith("Ethernet adapter") or key.startswith("Wireless LAN adapter"):
	for kvPair in subMapIpconfigs:
		if kvPair[0] == "Description":
			txtDescription = kvPair[1]
			break

	if not txtDescription:
		return None

	naNode = CIM_NetworkAdapter.MakeUri(txtDescription)

	prpDHCP_Server = lib_common.MakeProp("DHCP Server")
	prpDHCP_Server = lib_common.MakeProp("DHCP Server")

	# if key.startswith("Ethernet adapter") or key.startswith("Wireless LAN adapter"):
	for kvPair in subMapIpconfigs:
		propName = kvPair[0]
		paramVal = kvPair[1]
		prp = lib_common.MakeProp(propName)

		if propName in ["IPv4 Address","DHCP Server","DNS Servers","Default Gateway"]:
			ipAddr = paramVal.replace("(Preferred)","")
			if ipAddr:
				hostNode = lib_common.gUriGen.HostnameUri( ipAddr )
			grph.add( (naNode, prp, hostNode ) )
		else:
			grph.add( (naNode, prp, lib_common.NodeLiteral(paramVal) ) )

	return naNode

def AddNodesIpConfig(grph,rootNode,mapIpconfigs):

	prpNetAdapt = lib_common.MakeProp("Network adapter")
	for keyMap in mapIpconfigs:
		subMapIpconfigs = mapIpconfigs[keyMap]
		naNode = AddOneNodeIpConfig(grph,rootNode,keyMap,subMapIpconfigs)
		if naNode:
			grph.add( (rootNode, prpNetAdapt, naNode ) )

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	rootNode = lib_common.nodeMachine
	mapIpconfigs = CreateIpConfigData()

	AddNodesIpConfig(grph,rootNode,mapIpconfigs)

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()

