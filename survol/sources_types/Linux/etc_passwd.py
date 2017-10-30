#!/usr/bin/python

"""
/etc/passwd users
"""

import sys
import lib_common
import lib_util
from lib_properties import pc
from sources_types import user as survol_user

# TODO: https://docs.python.org/2/library/pwd.html might be simpler.
def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()



	usersList = survol_user.LoadEtcPasswd()

	# User name
	# Information used to validate a user's password; in most modern uses.
	# user identifier number.
	# group identifier number.
	# Gecos field, commentary that describes the person or account.
	# Path to the user's home directory.
	# Program that is started every time the user logs into the system.
	#
	# polkituser:x:17:17:system user for policykit:/:/sbin/nologin
	# puppet:x:103:106:Puppet configuration management daemon,,,:/var/lib/puppet:/bin/false
	for userNam, splitLin in list( usersList.items() ):
		userNode = lib_common.gUriGen.UserUri( userNam )
		comment = splitLin[4]
		# Sometimes the comment equals the user, so nothing to mention.
		if comment != "" and comment != userNam:
			grph.add( ( userNode, pc.property_information, lib_common.NodeLiteral( comment ) ) )
		homePath = splitLin[5]
		if homePath:
			if homePath == "/nonexistent":
				grph.add( ( userNode, pc.property_information, lib_common.NodeLiteral(homePath) ) )
			else:
				homeNode = lib_common.gUriGen.DirectoryUri( homePath )
				grph.add( ( userNode, pc.property_information, homeNode ) )
		execName = splitLin[6].strip()
		if execName:
			if execName == "/bin/false":
				grph.add( ( userNode, pc.property_information, lib_common.NodeLiteral(execName) ) )
			else:
				execNode = lib_common.gUriGen.FileUri( execName )
				grph.add( ( userNode, pc.property_information, execNode ) )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()


