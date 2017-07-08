#!/usr/bin/python

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
	sys.stderr.write("psutil.__version__=%s usab=%d\n"%(psutil.__version__,usab))
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

	# Psutil version after 4.0.0
	envsDict = objProc.environ()

	node_process = lib_common.gUriGen.PidUri(procid)

	if lib_util.isPlatformLinux:
		separatorPath = ":"
	elif lib_util.isPlatformWindows:
		separatorPath = ";"
	else:
		separatorPath = "#'#'#'"

	for envKey in envsDict :
		envVal = envsDict[envKey]
		sys.stderr.write("envKey=%s envVal=%s\n"%(envKey,envVal))
		nodeEnvNam = lib_util.NodeLiteral(envKey)
		if envKey in ["PATH"]:
			valSplit = envVal.split(separatorPath)
			for filNam in valSplit:
				nodFil = lib_common.gUriGen.DirectoryUri(filNam)
				# FileUri
				grph.add((nodeEnvNam,pc.property_directory,nodFil))
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





