#!/usr/bin/python

"""
NET SHARE information
"""

# Output example:
#> net share C$
#Share name        C$
#Path              C:\
#Remark            Default share
#Maximum users     No limit
#Users
#Caching           Manual caching of documents
#Permission        Everyone, FULL
#
#The command completed successfully.

import re
import sys
import lib_util
import lib_common
from lib_properties import pc
import lib_kbase

def Main():
	cgiEnv = lib_common.CgiEnv()
	# Ex: "//LONW00052257.euro.net.intra/D$"
	smbShr = cgiEnv.GetId()

	if not lib_util.isPlatformWindows:
		lib_common.ErrorMessageHtml("NET command on Windows only")

	# If called fron cgiserver.py, double slashes are collapsed into one.
	shrMatch = re.match( "/?/([^/]+)/([^/]+)",smbShr)
	if not shrMatch:
		# It can also tolerate backslahes.
		smbShr = smbShr.replace("\\","/")
		shrMatch = re.match( "/?/([^/]+)/([^/]+)",smbShr)
		if not shrMatch:
			# It also accepts backslashes instead of slashes.
			lib_common.ErrorMessageHtml("Invalid share name:%s"%smbShr)

	hostName = shrMatch.group(1)
	hostNode = lib_common.gUriGen.HostnameUri( hostName )

	#sys.stderr.write("smbShr=%s\n"%smbShr)
	shrNam = shrMatch.group(2)

	nodeSmbShr = lib_common.gUriGen.SmbShareUri( smbShr )

	grph = cgiEnv.GetGraph()

	# TODO: This can work only on the local machine.
	net_share_cmd = [ "net", "share", shrNam ]

	net_share_pipe = lib_common.SubProcPOpen(net_share_cmd)

	( net_share_last_output, net_share_err ) = net_share_pipe.communicate()

	# Converts to string for Python3.
	asstr = net_share_last_output.decode("utf-8")
	sys.stderr.write("asstr=%s\n"%asstr)

	# Share name        ShrProvTuto
	# Path              C:\Users\rchateau\Developpement\ReverseEngineeringApps\SharedProviderTutorial
	# Remark
	# Maximum users     No limit

	lines = asstr.split('\n')

	propMap = dict()
	shrPath = "UndefinedPath"
	for lin in lines:
		sys.stderr.write("lin=%s\n"%lin)
		txtContent = lin[18:].strip()
		if lin.startswith("Path"):
			shrPath = txtContent
		else:
			propKey = lin[:18].strip()
			if propKey:
				propMap[propKey] = txtContent

	mountNode = lib_common.gUriGen.FileUri( "//" + lib_util.currentHostname + "/" + shrPath )

	for propKey in propMap:
		propVal = propMap[propKey]
		grph.add( ( nodeSmbShr, lib_common.MakeProp(propKey), lib_kbase.MakeNodeLiteral(propVal) ) )

	grph.add( ( nodeSmbShr, pc.property_smbmount, mountNode ) )
	grph.add( ( nodeSmbShr, pc.property_host, hostNode ) )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
