#!/usr/bin/env python

"""
PEFile imported entries and modules
"""

	
import sys
import lib_uris
import lib_win32
import lib_common
import lib_shared_lib_path
from lib_properties import pc

import pefile

#import win32api

#Usable = lib_util.UsableWindowsBinary

# TODO: THIS SHOULD USE THE ENVIRONMENT VARIABLE "PATH" OF THE RUNNING PROCESS.
# TODO: INSTEAD, IT IS USING THE CURRENT PROCESS'ONE, WHICH IS WRONG.

class EnvPeFile:

	def __init__(self,grph):
		self.grph = grph

	def RecursiveDepends(self,filNam,maxLevel):
		# sys.stderr.write( "filNam=%s maxLevel=%d\n"%(filNam,maxLevel))
		rootNode = lib_common.gUriGen.FileUri( filNam )
		versStr = lib_win32.VersionString(filNam)
		self.grph.add( ( rootNode, pc.property_information, lib_common.NodeLiteral(versStr) ) )

		if maxLevel == 0:
			return rootNode

		# TODO: Consider a cache for this value. Beware of case for filNam.
		pe = pefile.PE(filNam)

		try:
			for entry in pe.DIRECTORY_ENTRY_IMPORT:
				if sys.version_info >= (3,):
					entry_dll = entry.dll.encode('utf-8')
				else:
					entry_dll = entry.dll
				# sys.stderr.write( "entry.dll=%s\n"%entry_dll)

				# sys.stderr.write("entry=%s\n"%str(entry.struct))
				dllPath = lib_shared_lib_path.FindPathFromSharedLibraryName(entry_dll)
				if dllPath:
					subNode = self.RecursiveDepends( dllPath, maxLevel - 1)
					self.grph.add( ( rootNode, pc.property_library_depends, subNode ) )

					for imp in entry.imports:
						# sys.stderr.write("\t%s %s\n"% (hex(imp.address), imp.name) )
						if imp.name is not None:
							symNode = lib_uris.gUriGen.SymbolUri( imp.name, dllPath )
							self.grph.add( ( subNode, pc.property_symbol_declared, symNode ) )

						break
		except AttributeError:
			# sys.stderr.write("EXCEPTION\n")
			pass

		return rootNode


def Main():

	paramkeyMaximumDepth = "Maximum depth"

	cgiEnv = lib_common.CgiEnv(	parameters = { paramkeyMaximumDepth : 3 })

	maxDepth = int(cgiEnv.GetParameters( paramkeyMaximumDepth ))

	win_module = cgiEnv.GetId()

	DEBUG("win_module=%s",win_module)

	lib_win32.CheckWindowsModule(win_module)

	grph = cgiEnv.GetGraph()

	env = EnvPeFile(grph)

	rootNode = env.RecursiveDepends( win_module, maxDepth )

	cgiEnv.OutCgiRdf("LAYOUT_RECT",[pc.property_symbol_declared])
	# cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()

