#!/usr/bin/env python

"""
Environment variables
"""

import os
import re
import sys
import psutil
import lib_util
import lib_common
from lib_properties import pc
from sources_types import CIM_Process

# https://stackoverflow.com/questions/11887762/compare-version-strings-in-python
def versiontuple(v):
	filled = []
	for apoint in v.split("."):
		filled.append(apoint.zfill(8))
	return tuple(filled)

# psutil.__version__
# '3.2.2'
# The feature environ is new in version 4.0.0.
def Usable(entity_type,entity_ids_arr):
	"""Psutil version must be at least 4.0.0"""
	usab = versiontuple(psutil.__version__) >= versiontuple("4.0.0")
	DEBUG("psutil.__version__=%s usab=%d",psutil.__version__,usab)
	return usab

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	try:
		procid = int( cgiEnv.GetId() )
	except Exception:
		lib_common.ErrorMessageHtml("Must provide a pid")

	objProc = CIM_Process.PsutilGetProcObj(procid)

	envProp = lib_common.MakeProp("environment")

	try:
		# Psutil version after 4.0.0
		envsDict = objProc.environ()
	except:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Error:" + str(exc))

	node_process = lib_common.gUriGen.PidUri(procid)

	for envKey in envsDict :
		envVal = envsDict[envKey]
		DEBUG("envKey=%s envVal=%s", envKey,envVal)
		nodeEnvNam = lib_util.NodeLiteral(envKey)

		# When a file or a directory displayed with a node,
		# its name is shortened so it can fit into the table.,
		# so it is less visible.

		# Some are probably for Windows only.
		if envKey in ["PATH","PSMODULEPATH","PYPATH"]:
			valSplit = envVal.split(os.pathsep)
			nodFilArr = [lib_common.gUriGen.DirectoryUri(filNam) for filNam in valSplit]
			nodFilArrNod = lib_util.NodeLiteral(nodFilArr)
			#for filNam in valSplit:
			#	nodFil = lib_common.gUriGen.DirectoryUri(filNam)
			grph.add((nodeEnvNam,pc.property_rdf_data_nolist2,nodFilArrNod))
		elif os.path.isdir(envVal):
			nodFil = lib_common.gUriGen.DirectoryUri(envVal)
			#grph.add((nodeEnvNam,pc.property_directory,nodFil))
			grph.add((nodeEnvNam,pc.property_rdf_data_nolist2,nodFil))
		elif os.path.exists(envVal):
			nodFil = lib_common.gUriGen.FileUri(envVal)
			grph.add((nodeEnvNam,pc.property_rdf_data_nolist2,nodFil))
			#grph.add((nodeEnvNam,pc.property_directory,nodFil))
		else:
			# TODO: Beware that "\L" is transformed into "<TABLE>" by Graphviz !!!
			envValClean = envVal.replace(">","_").replace("<","_").replace("&","_").replace("\\","_")
			nodeEnvValue = lib_util.NodeLiteral(envValClean)
			grph.add((nodeEnvNam,pc.property_rdf_data_nolist2,nodeEnvValue))
		grph.add((node_process,envProp,nodeEnvNam))

	# cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_directory,envProp])
	cgiEnv.OutCgiRdf("LAYOUT_RECT", [envProp])

if __name__ == '__main__':
	Main()





