#!/usr/bin/python

"""
Embedded Windows icon resources
"""

import os
import re
import sys
import time
import lib_mime
import lib_util
import lib_uris
import lib_kbase
import lib_win32
import lib_common
from lib_properties import pc
from sources_types import win32
from sources_types.win32 import resource as survol_win32_resource

# This script works only on a Windows executable or DLL etc...
Usable = lib_util.UsableWindowsBinary

# This specifies that the object is an Url which returns a MIME object,
# and can therefore be displayed as such.
def MakeMimeProp(prp):
	ret = primns_slash + "/MIME_PROPERTY/" + prp
	url = ret.replace(" ","_")
	return lib_kbase.MakeNodeUrl( url )


def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	pathName = cgiEnv.GetId()

	iconGroups = survol_win32_resource.GetIconNamesList(pathName)

	filNode = lib_common.gUriGen.FileUri(pathName)

	#propNam = ( "/MIME_PROPERTY/" + survol_win32_resource.mimeTypeResource ).replace(" ","_")
	#propIcon = lib_properties.MakeProp(survol_win32_resource.mimeTypeResource)

	for groupName in iconGroups:
		# TODO: Is it sorted in lib_export_html.py ??
		lib_mime.AddMimeUrl(grph,filNode, "win32/resource",survol_win32_resource.mimeTypeResource,[pathName,groupName])

	cgiEnv.OutCgiRdf("LAYOUT_RECT",[pc.property_rdf_data_nolist2] )

if __name__ == '__main__':
	Main()

