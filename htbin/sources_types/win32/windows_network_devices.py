#!/usr/bin/python

"""
Windows network devices
Command wmic logicaldisk
"""

import re
import subprocess
import sys
import psutil
import rdflib
import lib_util
import lib_common
from lib_properties import pc

Usable = lib_util.UsableWindows

def Main():
	cgiEnv = lib_common.CgiEnv()

	if not lib_util.isPlatformWindows:
		lib_common.ErrorMessageHtml("This works only on Windows platforms")

	grph = cgiEnv.GetGraph()

	#on windows
	#Get the fixed drives
	#wmic logicaldisk get name,description
	# We could also use the WMI package index but the point here
	# is also to prove that as long as we return RDF data, the
	# implementation details have no importance.

	# What about the ftp disks

	# Nothing is done for Linux because this is a different logic,
	# so there is no point emulating the same behaviour.

	drivelist = subprocess.Popen('wmic logicaldisk get name,description,ProviderName', shell=True, stdout=subprocess.PIPE)
	drivelisto, err = drivelist.communicate()
	strlist = drivelisto
	# This was the original line tested on Python 3 on Windows, but on Linux we get:
	# driveLines = strlist.split(b'\n') SyntaxError: invalid syntax
	# So we have replaced it, but this must be tested.
	# On Windows, now we get "Type str doesn't support the buffer API"
	# driveLines = strlist.split('\n')

	if sys.version_info >= (3,):
		strlistStr = str( strlist, encoding='utf8' )
	else:
		strlistStr = str( strlist )
	driveLines = strlistStr.split('\n')

	dictHosts = {}


	for lin in driveLines[1:]:
		#devtype = lin[0:18].decode('ascii').strip()
		#devname = lin[20:21].decode('ascii')
		#devprov = lin[22:].decode('ascii').strip()
		devtype = lin[0:18].strip()
		devname = lin[20:21]
		devprov = lin[22:].strip()
		# End of the list not interesting.
		if ( devtype == "" ):
			break
		if ( devtype != "Network Connection" ):
			continue

		# This is a temporary URN. It models a Windows device.
		# diskNodeName = 'urn://' + lib_common.HostName() + "/drives:" + devname
		# TODO: Put this in lib_common
		# diskNode = rdflib.term.URIRef(diskNodeName)
		devSplit = devprov.split('\\')
		hostName = devSplit[2]

		try:
			hostNode = dictHosts[ hostName ]
		except KeyError:
			hostNode = lib_common.gUriGen.HostnameUri( hostName )
			dictHosts[ hostName ] = hostNode

		diskNode = lib_common.gUriGen.SmbShareUri( "//" + hostName + "/" + devSplit[3] )

		# grph.add( ( diskNode, pc.property_win_netdev, rdflib.Literal( devname ) ) )

		grph.add( ( lib_common.gUriGen.FileUri( devname + ':' ), pc.property_mount, diskNode ) )

		grph.add( ( diskNode,  pc.property_file_system_type, rdflib.Literal( devtype ) ) )

		grph.add( ( hostNode, pc.property_smbshare, diskNode) )

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
