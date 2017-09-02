#!/usr/bin/python

# INTERMEDIARY RELEASE. TO BE FINISHED.

"""
Python properties
"""

import os
import os.path
import sys
import lib_util
import lib_uris
import lib_common
from lib_properties import pc

from sources_types import python
from sources_types.python import package

try:
	import dis
except ImportError:
	pass

def Usable(entity_type,entity_ids_arr):
	"""Can run with Python files only"""

	pyFilNam = entity_ids_arr[0]

	return False


def Main():
	cgiEnv = lib_common.CgiEnv()

	pyFilNam = cgiEnv.GetId()

	# sys.stderr.write("dbFilNam=%s\n"%dbFilNam)

	grph = cgiEnv.GetGraph()

	# filNode = lib_common.gUriGen.FileUri(pyFilNam)
	# 
	# try:
	# 
	# 	AddAssociatedFiles(grph,filNode,pyFilNam)
	# except:
	# 	exc = sys.exc_info()[0]
	# 	lib_common.ErrorMessageHtml("File:%s Unexpected error:%s" % ( pyFilNam, str( exc ) ) )
	# AddImportedModules(grph,filNode,pyFilNam,maxDepth,dispPackages,dispFiles)

	cgiEnv.OutCgiRdf("LAYOUT_SPLINE")

if __name__ == '__main__':
	Main()
