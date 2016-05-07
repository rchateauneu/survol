#!/usr/bin/python

"""
Dependency Walker builds a dependency tree diagram of a Windows module (exe, dll, ocx, sys...)
"""

import os
import os.path
import re
import sys
import time
import rdflib
import lib_util
import lib_win32
import lib_common
from lib_properties import pc

try:
	import pefile
except ImportError:
	exc = sys.exc_info()[1]
	lib_common.ErrorMessageHtml("Cannot import pefile:"+str(exc))

try:
	import win32api
except ImportError:
	exc = sys.exc_info()[1]
	lib_common.ErrorMessageHtml("Cannot import win32api:"+str(exc))

# BEWARE: The PATH is different for Apache user and the results are less meaningful.
# TODO: HOW TO PROPERLY SET THE PATH ???



def VersionString (filNam):
    try:
    	info = win32api.GetFileVersionInfo (filNam, "\\")
    	ms = info['FileVersionMS']
    	ls = info['FileVersionLS']
    	return "%d.%d.%d.%d" % ( win32api.HIWORD (ms), win32api.LOWORD (ms), win32api.HIWORD (ls), win32api.LOWORD (ls) )
    except:
    	return None

class EnvPeFile:

	def __init__(self,grph):
		self.grph = grph
		self.path = win32api.GetEnvironmentVariable('PATH')

		# try paths as described in MSDN
		self.dirs = [os.getcwd(), win32api.GetSystemDirectory(), win32api.GetWindowsDirectory()] + self.path.split(';')

		self.dirs_norm = []
		dirs_l = []
		for aDir in self.dirs:
			aDirLower = aDir.lower()
			if aDirLower not in dirs_l:
				dirs_l.append(aDirLower)
				self.dirs_norm.append(aDir)

		self.cache_dll_to_imports = dict()

	def RecursiveDepends(self,filNam,maxLevel):
		filNamLower = filNam.lower()

		if filNamLower in self.cache_dll_to_imports:
			# We already have seen this file name.
			rootNode = self.cache_dll_to_imports[filNamLower]
		else:
			#sys.stderr.write("filNam=%s\n"%filNam)
			rootNode = lib_common.gUriGen.FileUri( filNam )
			versStr = VersionString(filNam)
			self.grph.add( ( rootNode, pc.property_information, rdflib.Literal(versStr) ) )
			self.cache_dll_to_imports[filNamLower] = rootNode

			if maxLevel == 0:
				return rootNode

			pe = pefile.PE(filNam)

			# return rootNode

			try:
				for entry in pe.DIRECTORY_ENTRY_IMPORT:
					# sys.stderr.write("entry.dll=%s\n"%entry.dll)
					# sys.stderr.write("entry=%s\n"%str(entry.struct))
					for aDir in self.dirs_norm:
						dllPath = os.path.join(aDir, entry.dll)
						if os.path.exists(dllPath):
							subNode = self.RecursiveDepends( dllPath, maxLevel - 1)
							self.grph.add( ( rootNode, pc.property_library_depends, subNode ) )
							break
			except AttributeError:
				pass

		return rootNode


def Main():
	cgiEnv = lib_common.CgiEnv("DLL dependencies with pefile (Windows)")

	win_module = cgiEnv.GetId()

	sys.stderr.write("win_module=%s\n"%win_module)

	lib_win32.CheckWindowsModule(win_module)

	grph = rdflib.Graph()

	env = EnvPeFile(grph)

	rootNode = env.RecursiveDepends( win_module, maxLevel = 8 )

	#sys.stderr.write("NbFils=%d\n" % len(env.cache_dll_to_imports))
	#for key in env.cache_dll_to_imports:
	#	sys.stderr.write("Key=%s\n"%key)

	cgiEnv.OutCgiRdf(grph,"LAYOUT_SPLINE")
	# cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()

