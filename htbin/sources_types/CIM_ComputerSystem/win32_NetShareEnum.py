#!/usr/bin/python

"""
Network shares
"""

import os
import sys
import socket
import rdflib
import lib_util
import lib_common
from lib_properties import pc

import win32api
import win32net
import win32netcon
import win32security

Usable = lib_util.UsableWindows

def Main():
	cgiEnv = lib_common.CgiEnv()
	hostname = cgiEnv.GetId()

	nodeHost = lib_common.gUriGen.HostnameUri(hostname)

	grph = rdflib.Graph()

	# Loop over the shares.
	shareresume=0
	while 1:
		try:
			# If running on the local machine, pass the host as None otherwise authorization is checked
			# just like a remote machine, which means User Account Control (UAC) disabling,
			# and maybe setting LocalAccountTokenFilterPolicy=1
			if hostname == lib_util.currentHostname:
				hostname_or_None = None
			else:
				hostname_or_None = hostname
			sharedata, total, shareresume = win32net.NetShareEnum(hostname_or_None, 2, shareresume)
		except Exception:
			# "Access is denied."
			exc = sys.exc_info()[1]
			lib_common.ErrorMessageHtml("Hostname="+hostname+". Exception:"+str(exc))

		for share in sharedata:
			sys.stderr.write("share=%s\n" % ( str(share) ) )
			# share={'remark': 'Remote Admin', 'passwd': None, 'current_uses': 0, 'netname': 'ADMIN$', 'max_uses': 4294967295, 'path': 'C:\\\\Windows', 'type': 2147483648, 'permissions': 0}
			share_netname = share['netname']
			share_path = share['path']
			share_remark = share['remark']

			shareNode = lib_common.gUriGen.SmbShareUri( "//" + hostname + "/" + share_netname )
			grph.add( ( nodeHost, pc.property_smbshare, shareNode ) )

			# TODO: Horrible display. Strange because this is encoded in the function.
			# mountNode = lib_common.gUriGen.FileUri( share_path )
			# mountNode = lib_common.gUriGen.FileUri( lib_util.EncodeUri(share_path) )
			mountNode = lib_common.gUriGen.FileUri( share_path.replace('\\','/') )

			grph.add( ( shareNode, pc.property_smbmount, mountNode ) )
			grph.add( ( shareNode, pc.property_information, rdflib.Literal(share_remark) ) )

		if not shareresume:
			break

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
