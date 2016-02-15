#!/usr/bin/python

"""
Dependency Walker builds a dependency tree diagram of a Windows module (exe, dll, ocx, sys...)
"""

import os
import sys
import rdflib
import lib_win32
import lib_common
from lib_properties import pc

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

cgiEnv = lib_common.CgiEnv("DLL dependencies (Windows)")
win_module = cgiEnv.GetId()

lib_win32.CheckWindowsModule(win_module)

# This has to be in the path. Is it the 32 bits or 64 bits one ?
depends_bin = "depends.exe"

grph = rdflib.Graph()

sys.stderr.write("depends_bin=%s\n" % (depends_bin) )

def GetDependencies(win_module,grph = None):
	sys.stderr.write("win_module=%s\n" % ( win_module ) )

	dict_nodes = dict()

	tmpFilObj = lib_common.TmpFile("depends")
	tmpOutFil = tmpFilObj.Name
	# http://www.dependencywalker.com/help/html/hidr_command_line_help.htm
	command = depends_bin + " /c /f:1 /OC: " + tmpOutFil + ' "' + win_module + '"'

	sys.stderr.write("Depends command=%s\n"%(command))

	# TODO: Check the return value.
	# http://www.dependencywalker.com/help/html/hidr_command_line_help.htm
	try:
		out_lines = os.popen( command )
		for lin in out_lines:
			continue
			# Wait for the end, otherwise the file will not be ready.

		sys.stderr.write("Depends tmpOutFil=%s\n"%(tmpOutFil))
		input_file = open(tmpOutFil, 'r')
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Depends:"+ str(exc))

	# Status,Module,File Time Stamp,Link Time Stamp,File Size,Attr.,Link Checksum,Real Checksum,CPU,Subsystem,Symbols,Preferred Base,Actual Base,Virtual Size,Load Order,File Ver,Product Ver,Image Ver,Linker Ver,OS Ver,Subsystem Ver
	# ?,"MSVCR80D.DLL","Error opening file. The system cannot find the file specified (2).",,,,,,,,,,,,,,,,,,
	# D?,"XLCALL32.DLL","Error opening file. The system cannot find the file specified (2).",,,,,,,,,,,,,,,,,,
	# E6,"c:\windows\system32\ADVAPI32.DLL",2012-10-18 21:27:04,2012-10-18 21:27:12,876544,A,0x000D9B98,0x000D9B98,x64,Console,"CV",0x000007FF7FF10000,Unknown,0x000DB000,Not Loaded,6.1.7601.22137,6.1.7601.22137,6.1,9.0,6.1,6.1
	# E6,"c:\windows\system32\API-MS-WIN-CORE-CONSOLE-L1-1-0.DLL",2013-08-02 03:12:18,2013-08-02 03:12:52,3072,HA,0x000081B6,0x000081B6,x64,Console,"CV",0x0000000000400000,Unknown,0x00003000,Not Loaded,6.1.7601.18229,6.1.7601.18229,6.1,9.0,6.1,6.1
	for lin in input_file :
		# TODO: Beware of commas in file names!!!!! Maybe module shlex ?
		linargs = lin.split(',')

		# The library filename is enclosed in double-quotes, that we must remove.
		module = linargs[1][1:-1]

		if grph != None:
			libNode = lib_common.gUriGen.SharedLibUri( module )
			if linargs[0] != '?':
				cpu = linargs[8]
				grph.add( ( libNode, pc.property_library_cpu, rdflib.Literal(cpu) ) )
		else:
			libNode = None

		dict_nodes[ module ] = libNode

	# Temporary file removed by constructor.
	input_file.close()
	
	return dict_nodes

# Dependencies of the top DLL.
dictNodes = GetDependencies(win_module,grph)
nodeDLL = lib_common.gUriGen.FileUri( win_module )
dictNodes[ win_module ] = nodeDLL

deps_set_main = dictNodes.keys()

deps_sets_dict_deep = { win_module : deps_set_main }

dict_node = {}


for module in deps_set_main:
	deps_sets_dict_deep[ module ] = GetDependencies(module).keys()

deps_sets_dict_shallow = {}

# Now remove redundancy, so that it will really look like a tree.
for module in deps_sets_dict_deep:
	sub_deps_set_deep = deps_sets_dict_deep[ module ]
	# This is a copy.
	sub_deps_set_shallow = set( sub_deps_set_deep )

	for submodule in sub_deps_set_deep:
		submodule_deps = sub_deps_set_deep[submodule]
		sub_deps_set_shallow.difference_update( submodule_deps )

	deps_sets_dict_shallow[ module ] = sub_deps_set_shallow

for module in deps_sets_dict_shallow:
	sub_deps_set_shallow = deps_sets_dict_shallow[ module ]
	lib_node = dict_node[ module ]

	for submodule in sub_deps_set_shallow:
		lib_node_sub = dict_node[ submodule ]

		grph.add( ( lib_node_sub, pc.property_library_depends, lib_node ) )



cgiEnv.OutCgiRdf(grph)


# Another solution:
#py2exe contains an extension module that determines binary dependencies: 
#
#>>> from py2exe.py2exe_util import depends 
#>>> impport pprint 
#>>> pprint.pprint(depends(r"c:\windows\system32\notepad.exe").keys()) 
#['C:\\WINDOWS\\system32\\USER32.dll', 
#'C:\\WINDOWS\\system32\\SHELL32.dll', 