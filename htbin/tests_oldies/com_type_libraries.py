#!/usr/bin/python

CA SERT A RIEN



import os
import sys
import rdflib
import lib_common
from lib_common import pc

import win32con
import win32api

import lib_com_type_lib


cgiEnv = lib_common.CgiEnv("Registered COM type libraries")

grph = rdflib.Graph()

try:
		num = 0
		while 1:
				try:
						keyName = win32api.RegEnumKey(lib_com_type_lib.key, num)
				except win32api.error:
						break

				versions = lib_com_type_lib.ComKeyAllNameVersion(lib_com_type_lib.key, keyName)

				# sys.stderr.write("key=%s\n" % keyName)

				# Name of the last version.
				( bestTypLibName, bestVersion ) = lib_com_type_lib.ComKeyLastName(versions)
				# sys.stderr.write("BestName=%s\n" % bestTypLibName )

				# for vers, name in list( versions.items() ):
				# 	sys.stderr.write("    vers=%s name=%s\n" % (vers,name) )

				# The name will be awful. First we must experiment a bit.
				typelibNode = lib_common.gUriGen.ComTypeLibUri( keyName )
				strTypLibName = bestTypLibName + " / " + str(bestVersion)
				grph.add( (typelibNode, pc.property_information, rdflib.Literal(strTypLibName) ) )

				num = num + 1
finally:
		win32api.RegCloseKey(lib_com_type_lib.key)


cgiEnv.OutCgiRdf(grph)
