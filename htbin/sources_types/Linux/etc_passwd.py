#!/usr/bin/python

"""
/etc/passwd users
"""

import sys
import rdflib
import lib_common
import lib_util
from lib_properties import pc
from sources_types import user as survol_user

Usable = lib_util.UsableLinux

# TODO: https://docs.python.org/2/library/pwd.html might be simpler.
def Main():
	cgiEnv = lib_common.CgiEnv()

	if not lib_util.isPlatformLinux:
		lib_common.ErrorMessageHtml("/etc/passwd for Linux only")

	grph = cgiEnv.GetGraph()

	usersList = survol_user.LoadEtcPasswd()

	# polkituser:x:17:17:system user for policykit:/:/sbin/nologin
	for userNam, splitLin in list( usersList.items() ):
		userNode = lib_common.gUriGen.UserUri( userNam )
		comment = splitLin[4]
		# Sometimes the comment equals the user, so nothing to mention.
		if comment != "" and comment != userNam:
			grph.add( ( userNode, pc.property_information, rdflib.Literal( comment ) ) )
		grph.add( ( userNode, pc.property_information, rdflib.Literal( splitLin[6] ) ) )

	cgiEnv.OutCgiRdf( grph )

if __name__ == '__main__':
	Main()


