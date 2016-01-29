#!/usr/bin/python

#$ smbclient -L DUOLNX -N
#Anonymous login successful
#Domain=[MDKGROUP] OS=[Unix] Server=[Samba 3.0.28a]
#
#        Sharename       Type      Comment
#        ---------       ----      -------
#        print$          Disk
#        pdf-gen         Printer   PDF Generator (only valid users)
#        homes           Disk      Home Directories
#        IncomingCopied  Disk      IncomingCopied
#        IncomingToCopy  Disk      IncomingToCopy
#        Samsung         Disk      SamsungDisk
#        IPC$            IPC       IPC Service (Samba Server 3.0.28a DuoLinux)
#Anonymous login successful
#Domain=[MDKGROUP] OS=[Unix] Server=[Samba 3.0.28a]
#
#        Server               Comment
#        ---------            -------
#        DUOLNX               Samba Server 3.0.28a DuoLinux
#
#        Workgroup            Master
#        ---------            -------
#        HOME                 BTHUB5
#        MDKGROUP             DUOLNX


import re
import os
import sys
import subprocess

import rdflib

import lib_common
from lib_properties import pc

cgiEnv = lib_common.CgiEnv("Shares of a Samba server")
smbServer = cgiEnv.GetId()

if 'win' in sys.platform:
	lib_common.ErrorMessageHtml("smbclient not available on Windows")

grph = rdflib.Graph()

nodeSmbShr = lib_common.gUriGen.SmbServerUri( smbServer )

smbclient_cmd = [ "smbclient", "-L", smbServer, "-N" ]

# This print is temporary until we know how to display smb-shared files.
# print("Content-Type: text/html")
# print("")
# print("Command="+str(smbclient_cmd))
# print("<br>")

smbclient_pipe = subprocess.Popen(smbclient_cmd, bufsize=100000, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

( smbclient_last_output, smbclient_err ) = smbclient_pipe.communicate()

lines = smbclient_last_output.split('\n')

modeSharedList = False
for lin in lines:
	# print( "l="+lin+"<br>" )
	# Normally this is only the first line
	# session setup failed: NT_STATUS_LOGON_FAILURE
	mtch_net = re.match( "^.*(NT_STATUS_.*)", lin )
	if mtch_net:
		# print("OK<br>")
		lib_common.ErrorMessageHtml("Smb failure: " + mtch_net.group(1) + " to smb share:" + smbServer)

	if re.match("^\sServer\s+Comment", lin):
		modeSharedList = False
		continue

	if re.match("^\sWorkgroup\s+Master", lin):
		modeSharedList = False
		continue

	if re.match("^\sSharename\s+Type\s+Comment", lin):
		modeSharedList = True
		continue

	if re.match ("^\s*----+ +---+ +", lin ):
		continue

	# print("m="+str(modeSharedList))
	# print("l="+lin)
	if modeSharedList:
		# The type can be "Disk", "Printer" or "IPC".
		mtch_share = re.match( "^\s+([^\s]+)\s+Disk\s+(.*)$", lin )
		if mtch_share:
			shareName = mtch_share.group(1)

			shareNode = lib_common.gUriGen.SmbShareUri( "//" + smbServer + "/" + shareName )

			grph.add( ( nodeSmbShr, pc.property_smbshare, shareNode ) )

cgiEnv.OutCgiRdf(grph)


