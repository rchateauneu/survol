import os
import sys
import rdflib
import lib_common
from lib_properties import pc

import win32con
import win32api

key = win32api.RegOpenKey(win32con.HKEY_CLASSES_ROOT, "TypeLib")

def ComKeyAllNameVersion(key, keyName):
	result = {}
	# sys.stderr.write("keyName=%s\n" % keyName)

	subKey = win32api.RegOpenKey(key, keyName)
	try:
			subNum = 0
			bestVersion = 0.0
			while 1:
					try:
							versionStr = win32api.RegEnumKey(subKey, subNum)
					except win32api.error:
							break
					name = win32api.RegQueryValue(subKey, versionStr)
					# sys.stderr.write("name=%s\n" % name)

					try:
							versionFlt = float(versionStr)
					except ValueError:
							versionFlt = 0 # ????

					result[ versionFlt ] = name
					subNum = subNum + 1
	finally:
			win32api.RegCloseKey(subKey)

	return result

def ComKeyLastName(result):
	bestVrs = -999.0
	bestNam = ""

	for vers, name in list( result.items() ):
		if vers > bestVrs:
			bestVrs = vers
			bestNam = name
			
	return ( bestNam, bestVrs )

def CreateComRegisteredTypeLibNode( grph, key, name, version ):
	typelibNode = lib_common.gUriGen.ComRegisteredTypeLibUri( key )
	strTypLibName = "%s / %.1f" % ( name , version )
	grph.add( (typelibNode, pc.property_information, rdflib.Literal(strTypLibName) ) )

	return typelibNode
