import os
import sys
import logging

import win32con
import win32api

import lib_uris
import lib_util
import lib_common
from lib_properties import pc

TypeLibRegistryKey = win32api.RegOpenKey(win32con.HKEY_CLASSES_ROOT, "TypeLib")


def ComKeyAllNameVersion(key, key_name):
    result = {}
    logging.debug("ComKeyAllNameVersion key=%s keyName=%s", key, key_name)

    try:
        sub_key = win32api.RegOpenKey(key, key_name)
    except Exception as exc:
        lib_common.ErrorMessageHtml("ComKeyAllNameVersion key=%s keyName=%s. Error:%s" % (key, key_name, str(exc)))

    try:
        sub_num = 0
        bestVersion = 0.0
        while 1:
            try:
                version_str = win32api.RegEnumKey(sub_key, sub_num)
            except win32api.error:
                break
            name = win32api.RegQueryValue(sub_key, version_str)

            try:
                version_flt = float(version_str)
            except ValueError:
                version_flt = 0 # ????

            result[version_flt] = name
            sub_num = sub_num + 1
    finally:
        win32api.RegCloseKey(sub_key)

    return result


def ComKeyLastName(result):
    best_vrs = -999.0
    best_nam = ""

    for vers, name in result.items():
        if vers > best_vrs:
            best_vrs = vers
            best_nam = name
            
    return best_nam, best_vrs


def _filter_non_printable(str):
  return ''.join(c for c in str if ord(c) > 31 or ord(c) == 9)


def CreateComRegisteredTypeLibNode(grph, key, name, version):
    typelib_node = lib_uris.gUriGen.ComRegisteredTypeLibUri(key)
    # Just in case there would be characters breaking SVG conversion etc ...
    name = _filter_non_printable(name)
    str_typ_lib_name = "%s / %.1f" % (name, version)

    grph.add((typelib_node, pc.property_information, lib_util.NodeLiteral(str_typ_lib_name)))

    return typelib_node
