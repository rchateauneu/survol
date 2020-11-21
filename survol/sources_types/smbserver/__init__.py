"""
Samba protocol server
"""

import socket
import lib_common
from lib_properties import pc

def EntityOntology():
	return ( ["Id"], )

def AddInfo(grph,node,entity_ids_arr):
	smbNam = entity_ids_arr[0]

	smbIP = lib_util.GlobalGetHostByName(smbNam)

	nodeHost = lib_common.gUriGen.HostnameUri( smbIP )
	grph.add( ( node, lib_common.MakeProp("SMB server"), nodeHost ) )
