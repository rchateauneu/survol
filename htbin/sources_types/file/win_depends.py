#!/usr/bin/python

"""
Windows module dependencies (exe, dll, ocx, sys...) with Dependency Walker
"""

import os
import re
import sys
import time
import rdflib
import lib_util
import lib_win32
import lib_common
from lib_properties import pc

def Usable(entity_type,entity_ids_arr):
	if not lib_util.UsableWindows(entity_type,entity_ids_arr):
		return False
	fulFileName = entity_ids_arr[0]
	filename, file_extension = os.path.splitext(fulFileName)
	return file_extension.upper() in [".EXE", ".DLL", ".COM", ".OCX", ".SYS", ".ACM", ".BPL", ".DPL"]

# Returns symbols associated to a DLL or an EXE file.

# depends.exe:
# http://www.dependencywalker.com/
# Dependency Walker is a free utility that scans any 32-bit or 64-bit
# Windows module (exe, dll, ocx, sys, etc.) and builds
# a hierarchical tree diagram of all dependent modules.
# CA PEUT GENERER UN FICHIER CSV avec l.option /OC:
# Seul le script peut savoir s'il peut traiteer le fichier ou pas.
# Donc on va tout melanger et s'attendre a recevoir des messages d'erreurs.
# En plus un fichier peut avoir ete renomme.
# Une dll peut avoir ete copiee sur un disque Linux (Wine) etc...
# Donc on ne peut pas savoir a priori.
# http://www.dependencywalker.com/help/html/hidr_command_line_help.htm

# BEWARE: The PATH is different for Apache user and the results are less meaningful.
# TODO: HOW TO PROPERLY SET THE PATH ???

def Main():
	paramkeyGroupByDirs = "Group by directories"

	cgiEnv = lib_common.CgiEnv(	parameters = { paramkeyGroupByDirs : True })

	flagGroupByDirs = bool(cgiEnv.GetParameters( paramkeyGroupByDirs ))

	win_module = cgiEnv.GetId()

	lib_win32.CheckWindowsModule(win_module)

	# This has to be in the path. Is it the 32 bits or 64 bits one ?
	depends_bin = "depends.exe"

	sys.stderr.write("depends_bin=%s\n" % (depends_bin) )

	tmpFilObj = lib_common.TmpFile("depends")
	tmpOutFil = tmpFilObj.Name
	command = depends_bin + " /c /OC: " + tmpOutFil + ' "' + win_module + '"'

	sys.stderr.write("Depends command=%s\n"%(command))

	grph = rdflib.Graph()

	nodeDLL = lib_common.gUriGen.FileUri( win_module )

	# TODO: Check the return value.
	# http://www.dependencywalker.com/help/html/hidr_command_line_help.htm
	out_lines = os.popen( command )
	for lin in out_lines:
		continue
		# Wait for the end, otherwise the file will not be ready.

	try:
		sys.stderr.write("Depends tmpOutFil=%s\n"%(tmpOutFil))
		input_file = open(tmpOutFil, 'r')
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Caught "+str(exc)+" when processing:"+tmpOutFil)

	# Status,Module,File Time Stamp,Link Time Stamp,File Size,Attr.,Link Checksum,Real Checksum,CPU,Subsystem,Symbols,Preferred Base,Actual Base,Virtual Size,Load Order,File Ver,Product Ver,Image Ver,Linker Ver,OS Ver,Subsystem Ver
	# ?,"MSVCR80D.DLL","Error opening file. The system cannot find the file specified (2).",,,,,,,,,,,,,,,,,,
	# D?,"XLCALL32.DLL","Error opening file. The system cannot find the file specified (2).",,,,,,,,,,,,,,,,,,
	# E6,"c:\windows\system32\ADVAPI32.DLL",2012-10-18 21:27:04,2012-10-18 21:27:12,876544,A,0x000D9B98,0x000D9B98,x64,Console,"CV",0x000007FF7FF10000,Unknown,0x000DB000,Not Loaded,6.1.7601.22137,6.1.7601.22137,6.1,9.0,6.1,6.1
	# E6,"c:\windows\system32\API-MS-WIN-CORE-CONSOLE-L1-1-0.DLL",2013-08-02 03:12:18,2013-08-02 03:12:52,3072,HA,0x000081B6,0x000081B6,x64,Console,"CV",0x0000000000400000,Unknown,0x00003000,Not Loaded,6.1.7601.18229,6.1.7601.18229,6.1,9.0,6.1,6.1

	# Used only if libraries are grouped by directory.
	dirsToNodes = {}

	for lin in input_file:
		# TODO: Beware of commas in file names!!!!! Maybe module shlex ?
		linargs = lin.split(',')
		module = linargs[1]
		# The library filename is enclosed in double-quotes, that we must remove.
		modulNam = module[1:-1]
		libNode = lib_common.gUriGen.SharedLibUri( modulNam )

		# If the libraries are displayed in groups belnging to a dir, this is clearer.
		if flagGroupByDirs:
			dirNam = os.path.dirname(modulNam)
			if dirNam == "":
				dirNam = "Unspecified dir"
			try:
				dirNod = dirsToNodes[ dirNam ]
			except KeyError:
				# TODO: Beware, in fact this is a directory.
				dirNod = lib_common.gUriGen.FileUri( dirNam )
				grph.add( ( nodeDLL, pc.property_library_depends, dirNod ) )
				dirsToNodes[ dirNam ] = dirNod
			grph.add( ( dirNod, pc.property_library_depends, libNode ) )
		else:
			grph.add( ( nodeDLL, pc.property_library_depends, libNode ) )

		if linargs[0] != '?':
			cpu = linargs[8]
			if cpu not in [ "", "CPU" ]:
				grph.add( ( nodeDLL, pc.property_library_cpu, rdflib.Literal(cpu) ) )

	# Temporary file removed by constructor.
	input_file.close()

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()

# Another solution:
#py2exe contains an extension module that determines binary dependencies: 
#
#>>> from py2exe.py2exe_util import depends 
#>>> impport pprint 
#>>> pprint.pprint(depends(r"c:\windows\system32\notepad.exe").keys()) 
#['C:\\WINDOWS\\system32\\USER32.dll', 
#'C:\\WINDOWS\\system32\\SHELL32.dll', 