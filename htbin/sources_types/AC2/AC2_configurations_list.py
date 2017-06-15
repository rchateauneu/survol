#!/usr/bin/python

"""
Available AC2 configurations
"""

import os
import sys
import rdflib
import rdflib
import lib_util
import lib_common

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	# List xml config files in the directory given by the environment variable "XCOMP_AC2_BASE" which by default is "C:\AC2"
	envVarNam = "XCOMP_AC2_BASE"
	try:
		ac2TopDir = os.environ[envVarNam]
	except:
		lib_common.ErrorMessageHtml("Cannot get environment variable value %s"%envVarNam )

	# Directory on Windows.
	nodeTopDir = lib_common.gUriGen.DirectoryUri( ac2TopDir.replace("\\","/") + "/confs")

	rootNode = lib_common.nodeMachine

	grph.add( ( rootNode, lib_common.MakeProp("Machine"), nodeTopDir ) )

	for root, dirs, files in os.walk(ac2TopDir):
		for file in files:
			if file.endswith(".xml"):
				fullFileName = os.path.join(root, file)
				nodeConfig = lib_common.gUriGen.UriMakeFromDict("AC2/configuration", { "File": fullFileName })
				grph.add( ( nodeTopDir, lib_common.MakeProp("AC2 configuration"), nodeConfig ) )

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()

