#!/usr/bin/env python

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

# IP configuration

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


def _create_ip_config_data():
    """
        This loads into a map the result of IPCONFIG command.
    """
    map_ipconfigs = dict()
    curr_itf = ""
    proc = subprocess.Popen(['ipconfig', '/all'], stdout=subprocess.PIPE)
    for curr_line in proc.stdout.readlines():
        curr_line = curr_line.decode("utf-8").rstrip()
        if curr_line:
            if curr_line[0] != " ":
                curr_itf = curr_line.strip()
                if curr_itf[-1] == ":":
                    curr_itf = curr_itf[:-1]
                map_ipconfigs[curr_itf] = []
            else:
                idx_colon = curr_line.find(":")
                if idx_colon >= 0:
                    curr_key = curr_line[:idx_colon].replace(". ","").strip()
                    curr_val = curr_line[idx_colon+1:].strip()
                else:
                    curr_val = curr_line.strip()
                map_ipconfigs[curr_itf].append((curr_key, curr_val))
    return map_ipconfigs


def add_one_node_ip_config(grph, rootNode, keyMap, sub_map_ipconfigs):

    txt_description = None

    # if key.startswith("Ethernet adapter") or key.startswith("Wireless LAN adapter"):
    for kv_pair in sub_map_ipconfigs:
        if kv_pair[0] == "Description":
            txt_description = kv_pair[1]
            break

    if not txt_description:
        return None

    na_node = CIM_NetworkAdapter.MakeUri(txt_description)

    # if key.startswith("Ethernet adapter") or key.startswith("Wireless LAN adapter"):
    for kv_pair in sub_map_ipconfigs:
        prop_name = kv_pair[0]
        param_val = kv_pair[1]
        prp = lib_common.MakeProp(prop_name)

        if prop_name in ["IPv4 Address", "DHCP Server", "DNS Servers", "Default Gateway"]:
            ip_addr = param_val.replace("(Preferred)", "")
            if ip_addr:
                # ip_addr = ip_addr.replace("%", "&percnt;")
                # An IPV6 address might be "fe80::2c38:c4c6:b033:af27%14": This is not the ideal solution.
                ip_addr = ip_addr.replace("%", "(percnt)")
                host_node = lib_common.gUriGen.HostnameUri(ip_addr)
                grph.add((na_node, prp, host_node))
        else:
            grph.add((na_node, prp, lib_util.NodeLiteral(param_val)))

    return na_node


def _add_nodes_ip_config(grph, root_node, map_ipconfigs):
    prp_net_adapt = lib_common.MakeProp("Network adapter")
    for key_map in map_ipconfigs:
        sub_map_ipconfigs = map_ipconfigs[key_map]
        na_node = add_one_node_ip_config(grph, root_node, key_map, sub_map_ipconfigs)
        if na_node:
            grph.add((root_node, prp_net_adapt, na_node))


def Main():
    cgiEnv = lib_common.CgiEnv()

    grph = cgiEnv.GetGraph()

    root_node = lib_common.nodeMachine
    map_ipconfigs = _create_ip_config_data()

    _add_nodes_ip_config(grph, root_node, map_ipconfigs)

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()

