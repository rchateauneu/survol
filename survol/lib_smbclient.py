import re
import sys
import lib_util
import lib_common
from lib_properties import pc

def SmbCleanupFilNam(filNam,filSz):
	smbMtch = re.match( "(.*[^ ]) +D +", filNam )
	if smbMtch:
		return smbMtch.group(1)

	smbMtch = re.match( "(.*[^ ]) +A +", filNam )
	if smbMtch:
		return smbMtch.group(1)

	smbMtch = re.match( "(.*[^ ]) +", filNam )
	if smbMtch:
		return smbMtch.group(1)

	# When the remote machine is Windows,
	# there are other codes such as DRH etc...

	# Very specific and instable formatting.
	# if filSz == "0" and filNam[-9:] == " D       ":
	# 	filNam = filNam[:-10].rstrip()

	return filNam



# Lister les fichiers d'un SMB avec smbclient.
def AddFromSmbClient( grph, smbDir, smbShr, passWrd, rootNode ):

	smbclient_cmd = [ "smbclient", "-c", "ls", "-D", smbDir, smbShr, passWrd ]

	# This print is temporary until we know how to display smb-shared files.
	DEBUG( "Command=%s", str(smbclient_cmd) )

	smbclient_pipe = lib_common.SubProcPOpen(smbclient_cmd)

	( smbclient_last_output, smbclient_err ) = smbclient_pipe.communicate()

	lines = smbclient_last_output.split('\n')
	for lin in lines:
		DEBUG( "l="+lin)
		# Normally this is only the first line
		# session setup failed: NT_STATUS_LOGON_FAILURE
		mtch_net = re.match( "^.*(NT_STATUS_.*)", lin )
		if mtch_net:
			# print("OK<br>")
			lib_common.ErrorMessageHtml("Smb failure: " + mtch_net.group(1) + " smbShr:" + smbShr + " smbDir:" + smbDir)

		#   .                                   D        0  Wed Jul 23 23:22:34 2014
		#  ..                                  D        0  Sat Oct 19 00:25:58 2013
  		#Dumezil - Idees romaines.pdf         7389096  Fri Aug 27 14:00:44 2010
  		#02 Hubert Felix Thiefaine - Je Ne Sais Plus Quoi Faire Pour Te Decevoir.mp3         3679004  Sat Jun  5 09:06:45 2010
		#fldigi.exe                          A 40177610  Sat Jun 29 00:20:46 2013

		#  My Playlists                        D        0  Wed May  1 14:14:55 2013
		#  Sample Music                       DR        0  Wed May  1 19:46:06 2013

		regDate = '[A-Za-z]+ +[A-Za-z]+ +[0-9]+ +[0-9]+:[0-9]+:[0-9]+ +[0-9]+'

		regFull = '^(.*) ([0-9]+) +' + regDate

		tstFil = re.match( regFull, lin )

		if tstFil:
			filNam = tstFil.group(1)[2:]
			filSz = tstFil.group(2)

			filNam = SmbCleanupFilNam(filNam,filSz)

			DEBUG("Fi=%s, Sz=%s", filNam, filSz )

			filNod = lib_common.gUriGen.SmbFileUri( smbShr, smbDir + "/" + filNam )
			grph.add( ( rootNode, pc.property_directory, filNod ) )


