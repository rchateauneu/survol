#!/usr/bin/env python

"""
Registered COM type libraries
"""

import os
import sys
import logging

import win32api
import win32con

import lib_common
from lib_properties import pc
import lib_com_type_lib


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    try:
        num = 0
        while True:
            try:
                # DO NOT close handle.
                # (<class 'pywintypes.error'>, error(6, 'RegQueryInfoKey', 'The handle is invalid.')
                key_name = win32api.RegEnumKey(lib_com_type_lib.TypeLibRegistryKey, num)
            except win32api.error as exc:
                logging.warning("RegEnumKey CAUGHT:%s", str(exc))
                break

            versions = lib_com_type_lib.ComKeyAllNameVersion(lib_com_type_lib.TypeLibRegistryKey, key_name)

            # Name of the last version.
            best_typ_lib_name, best_version = lib_com_type_lib.ComKeyLastName(versions)

            # The name will be awful. First we must experiment a bit.
            lib_com_type_lib.CreateComRegisteredTypeLibNode(grph, key_name, best_typ_lib_name, best_version)

            num = num + 1
    finally:
        # This avoids:  error(6, 'RegQueryInfoKey', 'The handle is invalid.')
        logging.error("DO NOT close handle")
        # win32api.RegCloseKey(lib_com_type_lib.TypeLibRegistryKey

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
