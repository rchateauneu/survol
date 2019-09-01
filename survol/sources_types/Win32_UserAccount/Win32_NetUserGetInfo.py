#!/usr/bin/env python

"""
Windows user information
"""

# >>> win32net.NetUserGetInfo(None,"rchateau",3)
# {'comment': u'', 'workstations': u'', 'country_code': 0L, 'last_logon': 1480721751L, 'password_expired': 0L, 'full_name': u'', 'parm
# s': u'', 'code_page': 0L, 'priv': 2L, 'auth_flags': 0L, 'logon_server': u'\\\\*', 'home_dir': u'', 'home_dir_drive': u'', 'usr_comme
# nt': u'', 'profile': u'', 'acct_expires': 4294967295L, 'primary_group_id': 513L, 'bad_pw_count': 0L, 'user_id': 1001L, 'logon_hours'
# : '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff', 'password': None, 'units_per_week': 168L,
# 'last_logoff': 0L, 'name': u'rchateau', 'max_storage': 4294967295L, 'num_logons': 15896L, 'password_age': 45314825L, 'flags': 66081L
# , 'script_path': u''}

import sys
import lib_util
import lib_common
from lib_properties import pc

import win32net

from sources_types import Win32_UserAccount as survol_Win32_UserAccount

Usable = lib_util.UsableWindows

CanProcessRemote = True

def Main():
	cgiEnv = lib_common.CgiEnv(can_process_remote = True)

	try:
		# Exception if local machine.
		hostName = cgiEnv.m_entity_id_dict["Domain"]
	except KeyError:
		hostName = None

	if not hostName or lib_util.IsLocalAddress( hostName ):
		serverBox = lib_common.gUriGen
		serverNode = lib_common.nodeMachine
		servName_or_None = None
	else:
		serverBox = lib_common.RemoteBox(hostName)
		serverNode = lib_common.gUriGen.HostnameUri(hostName)
		servName_or_None = hostName

		# hostname = "Titi" for example
		# lib_win32.WNetAddConnect(hostName)





	userName = cgiEnv.m_entity_id_dict["Name"]

	grph = cgiEnv.GetGraph()

	nodeUser = survol_Win32_UserAccount.MakeUri( userName, hostName )

	try:
		infoList = win32net.NetUserGetInfo(servName_or_None, userName, 2)
	except:
		lib_common.ErrorMessageHtml("Error:"+str(sys.exc_info()))

	for infoKey in infoList:

		try:
			infoVal = infoList[infoKey]
			grph.add( ( nodeUser, lib_common.MakeProp(infoKey), lib_common.NodeLiteral(infoVal) ) )
		except:
			txtDisp = str( sys.exc_info()[1] )
			grph.add( ( nodeUser, lib_common.MakeProp(infoKey), lib_common.NodeLiteral(txtDisp) ) )



	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()


