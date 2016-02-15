import sys
import rdflib
import psutil
import lib_common
from lib_properties import pc


# TODO: If repetitive calls to this function, keep the result in memory.
def LoadEtcPasswd():
	passwdFil = open("/etc/passwd")
	usersList = {}

	# polkituser:x:17:17:system user for policykit:/:/sbin/nologin
	for lin in passwdFil:
		sys.stderr.write("User:"+lin)
		splitLin = lin.split(':')

		# Comments might contain UTF8 accents.
		# grph.add( ( userNode, pc.property_information, rdflib.Literal( splitLin[4].encode('utf-8') ) ) )
		try:
			txt = splitLin[4].encode('utf-8')
		except UnicodeDecodeError:
			txt = exc = sys.exc_info()[1]
		splitLin[4] = txt

		usersList[ splitLin[0] ] = splitLin
	return usersList

# This must add information about the user.
def AddInfo(grph,node,entity_ids_arr):
	usrNam = entity_ids_arr[0]

	try:
		usersList = LoadEtcPasswd()
		userSplit = usersList[ usrNam ]
		grph.add( ( node, pc.property_information, rdflib.Literal( userSplit[4] ) ) )

		# We insert this link to the home directory because it should not
		# imply an access to the file itself, so it cannot fail.
		homeDir = userSplit[5]
		homeDirNode = lib_common.gUriGen.FileUri( homeDir )

		grph.add( ( node, pc.property_directory, homeDirNode ) )

	except KeyError:
		grph.add( ( node, pc.property_information, rdflib.Literal( "No information available" ) ) )
