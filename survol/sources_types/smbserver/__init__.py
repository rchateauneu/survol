"""
Samba protocol server
"""

import socket

import lib_util
import lib_uris
import lib_common


def EntityOntology():
	return (["Id"],)


def AddInfo(grph, node, entity_ids_arr):
	smb_nam = entity_ids_arr[0]

	smb_ip = lib_util.GlobalGetHostByName(smb_nam)

	node_host = lib_uris.gUriGen.HostnameUri(smb_ip)
	grph.add((node, lib_common.MakeProp("SMB server"), node_host))
