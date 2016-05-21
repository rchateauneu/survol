#!/usr/bin/python

"""
Imported entries and modules
"""

import os
import os.path
import re
import sys
import time
import rdflib
import lib_uris
import lib_util
import lib_win32
import lib_common
from lib_properties import pc

import pefile

import win32api

# TODO: MUST TAKE THE GOOD PROCESS PATH, NOT OURS.

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

	def RecursiveDepends(self,filNam,maxLevel):
		# sys.stderr.write( "filNam=%s maxLevel=%d\n"%(filNam,maxLevel))
		rootNode = lib_common.gUriGen.FileUri( filNam )
		versStr = VersionString(filNam)
		self.grph.add( ( rootNode, pc.property_information, rdflib.Literal(versStr) ) )

		if maxLevel == 0:
			return rootNode

		# TODO: Consider a cache for this value. Beware of case for filNam.
		pe = pefile.PE(filNam)

		try:
			for entry in pe.DIRECTORY_ENTRY_IMPORT:
				# sys.stderr.write( "entry.dll=%s\n"%entry.dll)

				# sys.stderr.write("entry=%s\n"%str(entry.struct))
				for aDir in self.dirs_norm:
					dllPath = os.path.join(aDir, entry.dll)
					if os.path.exists(dllPath):
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

	cgiEnv = lib_common.CgiEnv("DLL imports (pefile)",
									parameters = { paramkeyMaximumDepth : 3 })

	maxDepth = int(cgiEnv.GetParameters( paramkeyMaximumDepth ))

	win_module = cgiEnv.GetId()

	sys.stderr.write("win_module=%s\n"%win_module)

	lib_win32.CheckWindowsModule(win_module)

	grph = rdflib.Graph()

	env = EnvPeFile(grph)

	rootNode = env.RecursiveDepends( win_module, maxDepth )

	cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT",[pc.property_symbol_declared])
	# cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()

