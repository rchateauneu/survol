#!/usr/bin/env python

import os
import sys
import rdflib
import lib_common
from lib_common import pc

import win32con
import win32api

import lib_com_type_lib

# SISMILAR TO com_registered_type_lib_versions.py. WHY ???

cgiEnv = lib_common.CgiEnv("Versions of registered COM type libraries")
clsidstr = cgiEnv.GetId()

grph = cgiEnv.GetGraph()

# key = win32api.RegOpenKey(win32con.HKEY_CLASSES_ROOT, "TypeLib")
versions = lib_com_type_lib.ComKeyAllNameVersion(lib_com_type_lib.key, clsidstr)


for versionStr, name in list( versions.items() ):
	versionStr = "1.0"
	sys.stderr.write("vers=%s name=%s\n" % (versionStr,name) )


	collected = []
	helpPath = ""
	completeVers = "TypeLib\%s\%s" % (clsidstr, versionStr)
	sys.stderr.write("completeVers=%s\n" % (completeVers) )
	key = win32api.RegOpenKey(win32con.HKEY_CLASSES_ROOT, completeVers)

	try:
			num = 0
			while 1:
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
											collected.append((lcid, platform, fname))
											lcidnum = lcidnum + 1
									win32api.RegCloseKey(lcidkey)
							except ValueError:
									pass
					num = num + 1
	finally:

			win32api.RegCloseKey(key)

	#               if helpPath: ret.append(browser.MakeHLI(helpPath, "Help Path"))

	sys.stderr.write("clsidstr=%s\n" % clsidstr )

	for lcid, platform, fname in collected:
			extraDescs = []
			if platform!="win32":
					extraDescs.append(platform)
			if lcid:
					extraDescs.append("locale=%s"%lcid)
			extraDesc = ""
			if extraDescs: extraDesc = " (%s)" % ", ".join(extraDescs)

			sys.stderr.write("fname=%s, Type Library:%s\n" % ( fname, extraDesc ) )




cgiEnv.OutCgiRdf()


