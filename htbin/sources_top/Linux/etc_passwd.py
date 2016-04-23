#!/usr/bin/python

import sys
import rdflib
import lib_entities.lib_entity_user
import lib_common
from lib_properties import pc

# TODO: https://docs.python.org/2/library/pwd.html might be simpler.

def Main():
	cgiEnv = lib_common.CgiEnv("Users on a Linux platform (/etc/passwd)")

	if not 'linux' in sys.platform:
		lib_common.ErrorMessageHtml("/etc/passwd for Linux only")

	grph = rdflib.Graph()

	usersList = lib_entities.lib_entity_user.LoadEtcPasswd()

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


