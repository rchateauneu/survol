#!/usr/bin/python

"""
Versions of registered COM type libraries
"""

import os
import sys
import lib_util
import lib_common
from lib_properties import pc

import win32con
import win32api

import lib_com_type_lib

Usable = lib_util.UsableWindows

def Main():
	cgiEnv = lib_common.CgiEnv()
	clsidstr = cgiEnv.GetId()

	grph = cgiEnv.GetGraph()

	versions = lib_com_type_lib.ComKeyAllNameVersion(lib_com_type_lib.TypeLibRegistryKey, clsidstr)

	# typelibNode = lib_common.gUriGen.ComRegisteredTypeLibUri( clsidstr )

	###################  See Win32_ComClass !!!!

	for versionStr, name in list( versions.items() ):
		sys.stderr.write("Vers=%s Name=%s\n" % (versionStr,name) )

		# TODO: The top of the tree does not make sense.

		#strVersion = "Version=%.1f" % ( versionStr )
		#nodeDllVersionNode = lib_common.gUriGen.FileUri( "DLL" + name )
		#versionNode = lib_common.gUriGen.FileUri( name )
		#grph.add( (versionNode, pc.property_information, lib_common.NodeLiteral("name="+name) ) )
		#grph.add( (versionNode, pc.property_information, lib_common.NodeLiteral(strVersion) ) )
		#grph.add( (typelibNode, pc.property_com_version, versionStr ) )


		typelibNode = lib_com_type_lib.CreateComRegisteredTypeLibNode( grph, clsidstr, name, versionStr )

		# collected = []
		helpPath = ""

		try:
			key = win32api.RegOpenKey(win32con.HKEY_CLASSES_ROOT, "TypeLib\\%s\\%s" % (clsidstr, versionStr))
		except Exception:
			exc = sys.exc_info()[1]
			lib_common.ErrorMessageHtml("win32api.RegOpenKey clsidstr="+str(clsidstr)+" versionStr="+str(versionStr)+". Caught:"+str(exc))


		try:
			num = 0
			while True:
				try:
					subKey = win32api.RegEnumKey(key, num)
				except win32api.error:
					break
				hSubKey = win32api.RegOpenKey(key, subKey)
				try:
					value, typ = win32api.RegQueryValueEx(hSubKey, None)
					if typ == win32con.REG_EXPAND_SZ:
						value = win32api.ExpandEnvironmentStrings(value)
				except win32api.error:
					value = ""
				if subKey=="HELPDIR":
					helpPath = value
				elif subKey=="Flags":
					flags = value
				else:
					try:
						# lcid = localeid
						lcid = int(subKey)
						lcidkey = win32api.RegOpenKey(key, subKey)
						# Enumerate the platforms
						lcidnum = 0
						while 1:
							try:
								platform = win32api.RegEnumKey(lcidkey, lcidnum)
							except win32api.error:
								break
							try:
								hplatform = win32api.RegOpenKey(lcidkey, platform)
								fname, typ = win32api.RegQueryValueEx(hplatform, None)
								if typ == win32con.REG_EXPAND_SZ:
									fname = win32api.ExpandEnvironmentStrings(fname)
							except win32api.error:
								fname = ""

							# Ligne 189
							# collected.append((lcid, platform, fname))
							# ret.append(HLITypeLib(fname, "Type Library" + extraDesc))

							fnameMysteryNode = lib_common.gUriGen.ComTypeLibUri( fname )
							grph.add( (fnameMysteryNode, pc.property_information, lib_common.NodeLiteral("lcid=%d"%lcid) ) )
							grph.add( (fnameMysteryNode, pc.property_information, lib_common.NodeLiteral("platform="+platform) ) )
							grph.add( (typelibNode, pc.property_com_version, fnameMysteryNode ) )

							lcidnum = lcidnum + 1
						win32api.RegCloseKey(lcidkey)
					except ValueError:
						pass
				num = num + 1
		finally:
			win32api.RegCloseKey(key)

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
