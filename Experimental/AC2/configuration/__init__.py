"""
AC2 configuration
"""

import os
import sys
import lib_common
import xml.dom.minidom
import lib_uris
from lib_properties import pc
from sources_types import AC2

def Graphic_colorbg():
	return "#88CCCC"

def EntityOntology():
	return ( ["File"], )

# Ambiguity with tables, oracle or normal users.
def MakeUri(configFilename):
	return lib_common.gUriGen.UriMakeFromDict("AC2/configuration", { "File" : configFilename } )

def AddInfo(grph,node,entity_ids_arr):
	configName = entity_ids_arr[0]
	nodeFile = lib_common.gUriGen.FileUri(configName)
	grph.add( ( node, lib_common.MakeProp("Configuration file"), nodeFile ) )

def EntityName(entity_ids_arr):
	return AC2.ConfigFileNameClean(entity_ids_arr[0])


def GetDom(configName):
	# Because of Windows: "C:/AC2\Application_Sample.xml"
	configFile = configName.replace("\\","/")

	DEBUG("configFile=%s",configFile)

	try:
		dom = xml.dom.minidom.parse(configFile)
	except:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Cannot parse %s:%s"%(configFile,str(exc)) )

	return dom

