#!/usr/bin/env python

"""
Versions of registered COM type libraries
"""

import os
import sys
import logging
import lib_util
import lib_common
from lib_properties import pc

import win32con
import win32api

import lib_com_type_lib


Usable = lib_util.UsableWindows


def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    clsidstr = cgiEnv.GetId()

    grph = cgiEnv.GetGraph()

    versions = lib_com_type_lib.ComKeyAllNameVersion(lib_com_type_lib.TypeLibRegistryKey, clsidstr)

    ###################  See Win32_ComClass !!!!

    for version_str, name in versions.items():
        logging.debug("Vers=%s Name=%s", version_str,name)

        # TODO: The top of the tree does not make sense.

        typelib_node = lib_com_type_lib.CreateComRegisteredTypeLibNode(grph, clsidstr, name, version_str)

        helpPath = ""

        try:
            key = win32api.RegOpenKey(win32con.HKEY_CLASSES_ROOT, "TypeLib\\%s\\%s" % (clsidstr, version_str))
        except Exception as exc:
            lib_common.ErrorMessageHtml(
                "win32api.RegOpenKey clsidstr="+str(clsidstr)+" version_str="+str(version_str)+". Caught:"+str(exc))

        try:
            num = 0
            while True:
                try:
                    sub_key = win32api.RegEnumKey(key, num)
                except win32api.error:
                    break
                h_sub_key = win32api.RegOpenKey(key, sub_key)
                try:
                    value, typ = win32api.RegQueryValueEx(h_sub_key, None)
                    if typ == win32con.REG_EXPAND_SZ:
                        value = win32api.ExpandEnvironmentStrings(value)
                except win32api.error:
                    value = ""
                if sub_key=="HELPDIR":
                    helpPath = value
                elif sub_key=="Flags":
                    flags = value
                else:
                    try:
                        # lcid = localeid
                        lcid = int(sub_key)
                        lcidkey = win32api.RegOpenKey(key, sub_key)
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

                            fname_mystery_node = lib_common.gUriGen.ComTypeLibUri(fname)
                            lcid_node = lib_util.NodeLiteral("lcid=%d" % lcid)
                            grph.add((fname_mystery_node, pc.property_information, lcid_node))
                            platform_node = lib_util.NodeLiteral("platform=" + platform)
                            grph.add((fname_mystery_node, pc.property_information, platform_node))

                            grph.add((typelib_node, pc.property_com_version, fname_mystery_node))

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
