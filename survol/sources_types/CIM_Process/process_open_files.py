#!/usr/bin/env python

"""
Files opened by process
"""

import sys
import lib_common
from sources_types import CIM_Process

from lib_properties import pc

def Main():
	paramkeyShowSharedLib = "Show shared libraries"
	paramkeyShowFontFiles = "Show font files"

	cgiEnv = lib_common.CgiEnv(
		parameters = { paramkeyShowSharedLib : False,
					   paramkeyShowFontFiles : False }
	)
	top_pid = int( cgiEnv.GetId() )

	flagShowSharedLib = bool(cgiEnv.GetParameters( paramkeyShowSharedLib ))
	flagShowFontFiles = bool(cgiEnv.GetParameters( paramkeyShowFontFiles ))

	grph = cgiEnv.GetGraph()

	proc_obj = CIM_Process.PsutilGetProcObj(top_pid)

	# sys.stderr.write("top_pid=%d\n" % top_pid)

	node_process = lib_common.gUriGen.PidUri(top_pid)
	CIM_Process.AddInfo( grph, node_process, [ str(top_pid) ] )

	################################################################################

	try:
		fillist = CIM_Process.PsutilProcOpenFiles( proc_obj )
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Caught:"+str(exc)+":"+str(proc_obj))

	for fil in fillist:
		# TODO: Resolve symbolic links. Do not do that if shared memory.
		# TODO: AVOIDS THESE TESTS FOR SHARED MEMORY !!!!
		if lib_common.MeaninglessFile(fil.path, not flagShowSharedLib, not flagShowFontFiles ):
			continue

		fileNode = lib_common.gUriGen.FileUri( fil.path )
		grph.add( ( node_process, pc.property_open_file, fileNode ) )

	# This works but not really necessary because there are not so many files.
	# cgiEnv.OutCgiRdf( "", [pc.property_open_file] )
	cgiEnv.OutCgiRdf("LAYOUT_SPLINE")

if __name__ == '__main__':
	Main()
