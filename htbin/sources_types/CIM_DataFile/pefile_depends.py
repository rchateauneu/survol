#!/usr/bin/python

"""
Windows dependencies (exe, dll, ocx, sys...) with pefile
"""

import os
import os.path
import sys
import rdflib
import lib_util
import lib_win32
import lib_common
from lib_properties import pc

import pefile
import win32api

Usable = lib_util.UsableWindowsBinary

# BEWARE: The PATH is different for Apache user and the results are less meaningful.
# TODO: HOW TO PROPERLY SET THE PATH ???

class EnvPeFile:

	def __init__(self,grph):
		self.grph = grph

		# try paths as described in MSDN
		self.dirs_norm = lib_win32.WindowsCompletePath()

		self.cache_dll_to_imports = dict()

	def RecursiveDepends(self,filNam,maxLevel):
		filNamLower = filNam.lower()

		if filNamLower in self.cache_dll_to_imports:
			# We already have seen this file name.
			rootNode = self.cache_dll_to_imports[filNamLower]
		else:
			#sys.stderr.write("filNam=%s\n"%filNam)
			rootNode = lib_common.gUriGen.FileUri( filNam )
			versStr = lib_win32.VersionString(filNam)
			self.grph.add( ( rootNode, pc.property_information, rdflib.Literal(versStr) ) )
			self.cache_dll_to_imports[filNamLower] = rootNode

			if maxLevel == 0:
				return rootNode

			pe = pefile.PE(filNam)

			try:
				for entry in pe.DIRECTORY_ENTRY_IMPORT:
					if sys.version_info >= (3,):
						entry_dll = entry.dll.encode('utf-8')
					else:
						entry_dll = entry.dll
					# sys.stderr.write("entry.dll=%s\n"%entry.dll)
					# sys.stderr.write("entry=%s\n"%str(entry.struct))
					for aDir in self.dirs_norm:
						# sys.stderr.write("aDir=%s entry_dll=%s\n"%(aDir,entry_dll))
						dllPath = os.path.join(aDir, entry_dll)
						if os.path.exists(dllPath):
							subNode = self.RecursiveDepends( dllPath, maxLevel - 1)
							self.grph.add( ( rootNode, pc.property_library_depends, subNode ) )
							break
			except AttributeError:
				pass

		return rootNode


def Main():
	cgiEnv = lib_common.CgiEnv()

	win_module = cgiEnv.GetId()

	sys.stderr.write("win_module=%s\n"%win_module)

	lib_win32.CheckWindowsModule(win_module)

	grph = cgiEnv.GetGraph()

	env = EnvPeFile(grph)

	rootNode = env.RecursiveDepends( win_module, maxLevel = 8 )

	#sys.stderr.write("NbFils=%d\n" % len(env.cache_dll_to_imports))
	#for key in env.cache_dll_to_imports:
	#	sys.stderr.write("Key=%s\n"%key)

	cgiEnv.OutCgiRdf(grph,"LAYOUT_SPLINE")
	# cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()

