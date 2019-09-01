#!/usr/bin/env python

"""
Windows users
"""

import sys
import socket
import psutil
import lib_common
import lib_util
from lib_properties import pc

# Similar to enumerate_user.py.

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	# [suser(name='Remi', terminal=None, host='0.246.33.0', started=1411052436.0)]

	try:
		# Windows XP, Python 3.
		try:
			# Windows XP, Python 3.4.
			users_list = psutil.users()
		except AttributeError:
			# Linux and Python 2.5
			# Windows 7, Python 3.2 : mais c'est la version de psutil qui compte.
			users_list = psutil.get_users()
	except AttributeError:
		# AttributeError: 'module' object has no attribute 'users'
		lib_common.ErrorMessageHtml("Function users() not available")

	for user in users_list:
		usrNam = lib_common.FormatUser( user.name )
		userNode = lib_common.gUriGen.UserUri( usrNam )

		grph.add( ( lib_common.nodeMachine, pc.property_user, userNode ) )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
