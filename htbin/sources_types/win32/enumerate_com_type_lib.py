#!/usr/bin/python

"""
Registered COM type libraries
"""

import os
import sys
import rdflib
import lib_common
from lib_properties import pc

import win32api
import win32con

import lib_com_type_lib

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	try:
		num = 0
		while True:
			try:
				# DO NOT close handle.
				# (<class 'pywintypes.error'>, error(6, 'RegQueryInfoKey', 'The handle is invalid.')
				keyName = win32api.RegEnumKey(lib_com_type_lib.key, num)
			except win32api.error:
				exc = sys.exc_info()
				sys.stderr.write("RegEnumKey CAUGHT:%s\n"%str(exc))
				break

			versions = lib_com_type_lib.ComKeyAllNameVersion(lib_com_type_lib.key, keyName)

			# sys.stderr.write("key=%s\n" % keyName)

			# Name of the last version.
			( bestTypLibName, bestVersion ) = lib_com_type_lib.ComKeyLastName(versions)
			# sys.stderr.write("BestName=%s\n" % bestTypLibName )

			# for vers, name in list( versions.items() ):
			#	sys.stderr.write("    vers=%s name=%s\n" % (vers,name) )

			# The name will be awful. First we must experiment a bit.
			typelibNode = lib_com_type_lib.CreateComRegisteredTypeLibNode( grph, keyName, bestTypLibName, bestVersion )

			num = num + 1
	finally:
		# This avoids:  error(6, 'RegQueryInfoKey', 'The handle is invalid.')
		sys.stderr.write("DO NOT close handle\n")
		# win32api.RegCloseKey(lib_com_type_lib.key)

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
