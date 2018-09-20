#!/usr/bin/python

"""
NET USE command
"""

# D:\Projects\Divers\Reverse\PythonStyle\htbin\sources>net use
# New connections will be remembered.
# 
# Status       Local     Remote                    Network
# 
# -------------------------------------------------------------------------------
# OK           E:        \\pars01110240\software   Microsoft Windows Network
# OK           F:        \\infsapps\applications   Microsoft Windows Network
# OK           H:        \\londata002.uk.net.intra\EM-IT
#                                                 Microsoft Windows Network
# OK           S:        \\LONSHR-IRG\IRG          Microsoft Windows Network
# OK           U:        \\LONDATA001.uk.net.intra\UK936025
#                                                 Microsoft Windows Network
# The command completed successfully.

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

	net_use_cmd = [ "net", "use" ]

	net_use_pipe = lib_common.SubProcPOpen(net_use_cmd)

	( net_use_last_output, net_use_err ) = net_use_pipe.communicate()

	# Converts to string for Python3.
	asstr = net_use_last_output.decode("utf-8")
	lines = asstr.split('\n')

	seenHyphens = False

	# NOTHING VISIBLE FOR APACHE USER ?
	# "There are no entries in the list"

	# print("Content-type: text/html\n\n<head></head><body>")

	# When the remote field is too long, the content is split into two lines.
	currStatus = ''
	currLocal = ''
	currRemote = ''
	currNetwork = ''

	for lin in lines:
		# NOT VISIBLE FOR APACHE USER ???????
		# print("se="+str(seenHyphens)+" Lin=("+lin+")<br>")
		if re.match(".*-------.*",lin):
			seenHyphens = True
			continue

		if re.match(".*The command completed successfully.*",lin):
			break
		#print("se="+str(seenHyphens)+" Lin1=("+lin+")")
		if not seenHyphens:
			continue

		if currLocal == '':
			currStatus = lin[:12]
			currLocal = lin[15:]
			if lin[48] == ' ':
				currRemote = lin[16:47]
				currNetwork = lin[49:]
			else:
				currRemote = lin[16:]
				# Will read network at next line.
				continue
		else:
			currNetwork = lin[48:]

		currRemote = currRemote.strip()
		lib_util.Logger().debug("currRemote=%s",currRemote)

		# "\\192.168.0.15\rchateau   Microsoft Windows Network"
		currLocal = currLocal.strip().split(" ")[0]

		lib_util.Logger().debug("currLocal=%s",currLocal)
		shareNode = lib_common.gUriGen.SmbShareUri( currRemote )
		grph.add( ( lib_common.gUriGen.FileUri( currLocal + ':' ), pc.property_mount, shareNode ) )

		# Reset the line, will read next disk.
		currLocal = ''

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
