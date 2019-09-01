#!/usr/bin/env python

"""
NET VIEW command
"""

# http://ss64.com/nt/net_share.html

# D:\Projects\Divers\Reverse\PythonStyle\htbin\sources>net view
# Server Name            Remark
# 
# -------------------------------------------------------------------------------
# \\LONW000063245
# \\LONW00050624
# \\LONW00051025
# \\LONW00051272
# \\LONW00051815
# \\LONW00051877
# \\LONW00052163

import sys
import re
import socket
import lib_util
import lib_common
from lib_properties import pc
import lib_smb

Usable = lib_smb.UsableNetCommands

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	net_view_cmd = [ "net", "view" ]

	net_view_pipe = lib_common.SubProcPOpen(net_view_cmd)

	( net_view_last_output, net_view_err ) = net_view_pipe.communicate()

	# Converts to string for Python3.
	asstr = net_view_last_output.decode("utf-8")
	lines = asstr.split('\n')

	seenHyphens = False

	for lin in lines:
		if re.match(".*-------.*",lin):
			seenHyphens = True
			continue

		if re.match(".*The command completed successfully.*",lin):
			break
		if not seenHyphens:
			continue

		#print("se="+str(seenHyphens)+" Lin2=("+lin+")")
		tst_view = re.match( r'^\\\\([A-Za-z0-9_$]+)', lin )
		if not tst_view:
			continue

		shrSrv = tst_view.group(1)

		shareSrvNode = lib_common.gUriGen.SmbServerUri( shrSrv )
		grph.add( ( lib_common.nodeMachine, pc.property_smbview, shareSrvNode ) )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
