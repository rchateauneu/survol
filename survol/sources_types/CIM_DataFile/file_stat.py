#!/usr/bin/env python

"""
File stat information

This returns general information about a non-directory data file.
"""

# BEWARE: Do NOT rename it as stat.py otherwise strange errors happen,
# probably a collision of modules names, with the message:
# "Fatal Python error: Py_Initialize: can't initialize sys standard streams"

import os
import sys
from sources_types import CIM_DataFile
import lib_util
import lib_common
from lib_properties import pc


def Main():
	cgiEnv = lib_common.CgiEnv()
	filNam = cgiEnv.GetId()

	DEBUG("file_stat.py filNam=%s", filNam)

	filNode = lib_common.gUriGen.FileUri(filNam)

	grph = cgiEnv.GetGraph()

	info = CIM_DataFile.GetInfoStat(filNam)

	# st_mode: protection bits.
	# st_ino: inode number.

	# st_dev: device.
	CIM_DataFile.AddDevice(grph, filNode, info)

	CIM_DataFile.AddStatNode( grph, filNode, info )
	CIM_DataFile.AddMagic( grph, filNode, filNam )

	# st_nlink: number of hard links.

	CIM_DataFile.AffFileOwner(grph, filNode, filNam)

	# Displays the file and the parent directories/
	currFilNam = filNam
	currNode = filNode
	while True:
		dirPath = os.path.dirname(currFilNam)
		if dirPath == currFilNam:
			break
		if dirPath == "":
			break
		dirNode = lib_common.gUriGen.DirectoryUri(dirPath)
		grph.add( ( dirNode, pc.property_directory, currNode) )
		DEBUG("file_stat.py dirPath=%s", dirPath)
		statPath = os.stat(dirPath)
		CIM_DataFile.AddStatNode( grph, dirNode, statPath)

		CIM_DataFile.AddFileProperties(grph, currNode, currFilNam)

		currFilNam = dirPath
		currNode = dirNode

	# If windows, print more information: DLL version etc...
	# http://stackoverflow.com/questions/580924/python-windows-file-version-attribute

	# cgiEnv.OutCgiRdf()
	# cgiEnv.OutCgiRdf("LAYOUT_TWOPI")
	cgiEnv.OutCgiRdf("LAYOUT_RECT_RL")


if __name__ == '__main__':
	Main()
