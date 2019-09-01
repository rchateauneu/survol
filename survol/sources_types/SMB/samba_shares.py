#!/usr/bin/env python

"""
Samba shares
"""

# smbtree -N -b --debuglevel=0
# MDKGROUP
#         \\DUOLNX                        Samba Server 3.0.28a DuoLinux
#                 \\DUOLNX\IPC$                   IPC Service (Samba Server 3.0.28a DuoLinux)
#                 \\DUOLNX\Samsung                SamsungDisk
#                 \\DUOLNX\IncomingToCopy         IncomingToCopy
#                 \\DUOLNX\IncomingCopied         IncomingCopied
#                 \\DUOLNX\homes                  Home Directories
#                 \\DUOLNX\pdf-gen                PDF Generator (only valid users)
#                 \\DUOLNX\print$
# HOME
#         \\BTHUB5                        BT Home Hub 5.0A File Server
#                 \\BTHUB5\IPC$                   IPC Service (BT Home Hub 5.0A File Server)
#
# nmblookup --debuglevel=0 DUOLNX
# querying DUOLNX on 192.168.1.255
# 192.168.1.68 DUOLNX<00>

import sys
import re
import socket
import lib_util
import lib_common
from lib_properties import pc
import lib_smb


# This returns the IP address of a netbios machine name.
def NetBiosLookupHelper(machine):
	nmblookup_cmd = [ "nmblookup", "--debuglevel=0", machine ]

	nmblookup_pipe = lib_common.SubProcPOpen(nmblookup_cmd)

	( nmblookup_last_output, nmblookup_err ) = nmblookup_pipe.communicate()

	lines = nmblookup_last_output.split('\n')

	mtch = re.match( r'^([^ \t]*)', lines[1] )

	if mtch:
		return mtch.group(1)

	return "0.0.0.0"

netbios_cache = {}

# See http://support.microsoft.com/kb/163409 for details.
def NetBiosLookup(machine):
	global netbios_cache

	try:
		addr = netbios_cache[ machine ]
	except KeyError:
		addr = NetBiosLookupHelper(machine)
		netbios_cache[ machine ] = addr

	return addr

def Main():
	cgiEnv = lib_common.CgiEnv()

	# TODO: Should test Linux instead ?
	if lib_util.isPlatformWindows:
		lib_common.ErrorMessageHtml("smbtree not available on Windows")

	grph = cgiEnv.GetGraph()

	smbtree_cmd = [ "smbtree", "-N", "-b", "--debuglevel=0" ]

	smbtree_pipe = lib_common.SubProcPOpen(smbtree_cmd)

	( smbtree_last_output, smbtree_err ) = smbtree_pipe.communicate()

	lines = smbtree_last_output.split('\n')

	for lin in lines:
		# print(lin)

		tst_domain = re.match( r'^([A-Z]+) *', lin )
		if tst_domain:
			domain = tst_domain.group(1)
			# print( "Domain=" + tst_domain.group(1) )

			continue

		tst_machine = re.match( r'^[ \t]+\\\\([A-Z0-9_]+)[ \t]+([^\t].*)', lin )
		if tst_machine:
			machine = tst_machine.group(1)
			addr = NetBiosLookup( machine )
			# print( "Machine=" + tst_machine.group(1) + " Comment=" + tst_machine.group(2) )

			nodeHost = lib_common.gUriGen.HostnameUri( addr )
			grph.add( ( nodeHost, pc.property_netbios, lib_common.gUriGen.SmbServerUri(machine) ) )
			# TODO: Maybe will create a specific node for a domain.
			grph.add( ( nodeHost, pc.property_domain, lib_common.gUriGen.SmbDomainUri(domain) ) )

			continue

		tst_share = re.match( r'^[ \t]+\\\\([A-Z0-9_]+)\\([^ \t]+)[ \t]+([^\t].*)', lin )
		if tst_share:
			machine = tst_share.group(1)
			share = tst_share.group(2)

			shareNode = lib_common.gUriGen.SmbShareUri( "//" + machine + "/" + share )
			grph.add( ( nodeHost, pc.property_smbshare, shareNode ) )

			continue

	# print( smbtree_last_output )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
