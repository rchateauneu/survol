#!/usr/bin/python

"""
Network shares
"""

import sys
import lib_util
import lib_common
from lib_properties import pc

import win32net

def Main():
	cgiEnv = lib_common.CgiEnv()
	hostname = cgiEnv.GetId()

	nodeHost = lib_common.gUriGen.HostnameUri(hostname)

	grph = cgiEnv.GetGraph()

	# Loop over the shares.
	shareresume=0
	while 1:
		try:
			# If running on the local machine, pass the host as None otherwise authorization is checked
			# just like a remote machine, which means User Account Control (UAC) disabling,
			# and maybe setting LocalAccountTokenFilterPolicy=1
			if lib_util.IsLocalAddress( hostname ):
				hostname_or_None = None
				level = 2 # 1,2
			else:
				hostname_or_None = hostname
				level = 1 # 1,2

			sharedata, total, shareresume = win32net.NetShareEnum(hostname_or_None, level, shareresume)

		except Exception:
			# "Access is denied."
			exc = sys.exc_info()[1]
			lib_common.ErrorMessageHtml("Hostname="+hostname+". Exception:"+str(exc))

		for share in sharedata:
			DEBUG("share=%s", str(share) )
			# share={'remark': 'Remote Admin', 'passwd': None, 'current_uses': 0, 'netname': 'ADMIN$', 'max_uses': 4294967295, 'path': 'C:\\\\Windows', 'type': 2147483648, 'permissions': 0}
			share_netname = share['netname']
			try:
				share_path = share['path']
				share_remark = share['remark']
			except:
				share_path = ""
				share_remark = ""

			shareNode = lib_common.gUriGen.SmbShareUri( "//" + hostname + "/" + share_netname )
			grph.add( ( nodeHost, pc.property_smbshare, shareNode ) )

			if share_path:
				# TODO: Horrible display. Strange because this is encoded in the function.
				# mountNode = lib_common.gUriGen.FileUri( share_path.replace('\\','/') )
				mountNode = lib_common.gUriGen.FileUri( share_path )
				grph.add( ( shareNode, pc.property_smbmount, mountNode ) )

			if share_remark:
				grph.add( ( shareNode, pc.property_information, lib_common.NodeLiteral(share_remark) ) )

		if not shareresume:
			break

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
