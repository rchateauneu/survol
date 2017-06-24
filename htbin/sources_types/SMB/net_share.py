#!/usr/bin/python

"""
NET SHARE command
"""

# D:\Projects\Divers\Reverse\PythonStyle\htbin\sources>net share
#
# Share name   Resource                        Remark
#
# -------------------------------------------------------------------------------
# C$           C:\                             Default share
# D$           D:\                             Default share
# IPC$                                         Remote IPC
# ADMIN$       C:\Windows                      Remote Admin
# The command completed successfully.
#
# C:\Documents and Settings\Remi>net share
#
#           1         2         3         4
# 01234567890123456789012345678901234567890123456789
# Share name   Resource                        Remark
#
# -------------------------------------------------------------------------------
# IPC$                                         Remote IPC
# Remi         C:\Documents and Settings\Remi
# SharedDocs   C:\DOCUMENTS AND SETTINGS\ALL USERS\DOCUMENTS
#
# The command completed successfully.

import sys
import re
import subprocess
import lib_util
import lib_common
from lib_properties import pc
import lib_smb

def Main():
	cgiEnv = lib_common.CgiEnv()

	# TODO: Should test Linux instead ?
	# TODO: The command "net" exists on Linux !!!!
	if not lib_util.isPlatformWindows:
		lib_common.ErrorMessageHtml("NET command on Windows only")

	grph = cgiEnv.GetGraph()

	net_share_cmd = [ "net", "share" ]

	net_share_pipe = subprocess.Popen(net_share_cmd, bufsize=100000, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

	( net_share_last_output, net_share_err ) = net_share_pipe.communicate()

	# Converts to string for Python3.
	asstr = net_share_last_output.decode("utf-8")
	#print("Str="+asstr)
	lines = asstr.split('\n')

	seenHyphens = False

	for lin in lines:
		#print("se="+str(seenHyphens)+" Lin=("+lin+")")
		if re.match(".*-------.*",lin):
			seenHyphens = True
			continue

		if re.match(".*The command completed successfully.*",lin):
			break
		#print("se="+str(seenHyphens)+" Lin1=("+lin+")")
		if not seenHyphens:
			continue

		#print("se="+str(seenHyphens)+" Lin2=("+lin+")")
		tst_share = re.match( r'^([A-Za-z0-9_$]+) +([^ ]+).*', lin )
		if not tst_share:
			continue

		shrNam = tst_share.group(1)

		strlin = str(lin)
		# Nasty formatting of "NET SHARE" command.
		if len(lin) >= 45:
			# There is a remark or a very long resource.
			if lin[44] == ' ':
				# Character just before remark is a space.
				shrRes = lin[13:44].rstrip()
			else:
				shrRes = lin[13:]
		else:
			shrRes = lin[13:]
		#print("nam="+shrNam)
		#print("res="+shrRes)

		shareNode = lib_common.gUriGen.SmbShareUri( "//" + lib_util.currentHostname + "/" + shrNam )
		grph.add( ( lib_common.nodeMachine, pc.property_smbshare, shareNode ) )

		# mountNode = lib_common.gUriGen.FileUri( "//" + lib_util.currentHostname + "/" + shrRes )
		shrRes = shrRes.replace("\\","/").strip()
		mountNode = lib_common.gUriGen.DirectoryUri( shrRes )
		grph.add( ( shareNode, pc.property_smbmount, mountNode ) )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()

