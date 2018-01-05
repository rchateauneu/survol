#!/usr/bin/python

"""
Neighboring Survol agents.

Distant Survol agents can broadcast their presence with SLP.
Set the Service Location Protocol flag to enable this detection.
"""

import sys
import lib_util
import lib_common
import lib_credentials
from lib_properties import pc
from sources_types import neighborhood as survol_neighborhood

def AddSurvolNode(grph,hostSurvol,urlSurvolClean):
	sys.stderr.write("AddSurvolNode hostSurvol=%s\n"%(hostSurvol))
	survolHostNode = lib_common.gUriGen.HostnameUri( hostSurvol )

	currDispMode = lib_util.GuessDisplayMode()

	# Several possibilities:
	# - Open a new HTML page with this URL. Or SVG, passed on the current mode.
	# - If we are in D3 mode, this should return a JSON object from the other agent.
	if currDispMode == "json":

		if lib_util.IsLocalAddress( hostSurvol ):
			machName_or_None = None
			serverBox = lib_common.gUriGen
		else:
			machName_or_None = hostSurvol
			serverBox = lib_common.OtherAgentBox(urlSurvolClean)

		# This is the URL of the remote host, on the remote agent.
		nodeRemoteHost = serverBox.HostnameUri(hostSurvol)
		grph.add( ( survolHostNode, lib_common.MakeProp("Survol host"), nodeRemoteHost ) )

		nodeSurvolUrl = lib_common.NodeUrl(urlSurvolClean)
		grph.add( ( survolHostNode, lib_common.MakeProp("Survol agent"), nodeSurvolUrl ) )

	else:
		urlSurvolModed = lib_util.AnyUriModed(urlSurvolClean, currDispMode)

		nodeSurvolUrl = lib_common.NodeUrl(urlSurvolModed)

		# Should check the URL to be sure it is valid.

		# sys.stderr.write("AddSurvolNode urlSurvolModed=%s\n"%(urlSurvolModed))
		grph.add( ( survolHostNode, lib_common.MakeProp("Survol agent"), nodeSurvolUrl ) )

	return nodeSurvolUrl


def CallbackNodeAdder(grph,urlSurvol):
	parsed_url = lib_util.survol_urlparse( urlSurvol )
	hostSurvol = parsed_url.hostname
	# sys.stderr.write("SurvolServersDisplay hostSurvol=%s\n"%(hostSurvol))
	if hostSurvol:
		nodeSurvolUrl = AddSurvolNode(grph,hostSurvol,urlSurvol)
		return nodeSurvolUrl
	else:
		return None


def SurvolServersDisplay(grph):
	lstSurvolServers = []
	credNames = lib_credentials.GetCredentialsNames( "Survol" )
	sys.stderr.write("SurvolServersDisplay\n")
	for urlSurvol in credNames:
		# sys.stderr.write("SurvolServersDisplay urlSurvol=%s\n"%(urlSurvol))

		# The credentials are not needed until a Survol agent uses HTTPS.
		CallbackNodeAdder(grph,urlSurvol)


def Main():
	# If this flag is set, the script uses SLP (Servicel Location Protocol)
	# to browse other Survol Agents.
	paramkeySLP = "Service Location Protocol"

	cgiEnv = lib_common.CgiEnv(
		parameters = { paramkeySLP : False }
	)

	flagSLP = bool(cgiEnv.GetParameters( paramkeySLP ))

	grph = cgiEnv.GetGraph()

	SurvolServersDisplay(grph)

	if flagSLP:
		dictServices = survol_neighborhood.GetSLPServices("survol")
		for keyService in dictServices:
			nodeSurvolUrl = CallbackNodeAdder(grph,keyService)
			grph.add( ( nodeSurvolUrl,
						pc.property_information,
						lib_common.NodeLiteral("Service Location Protocol") ) )
			attrsService = dictServices[keyService]
			for keyAttr in attrsService:
				propAttr = lib_common.MakeProp(keyAttr)
				valAttr = attrsService[keyAttr]
				grph.add( ( nodeSurvolUrl, propAttr, lib_common.NodeLiteral(valAttr) ) )


	cgiEnv.OutCgiRdf()


if __name__ == '__main__':
	Main()
