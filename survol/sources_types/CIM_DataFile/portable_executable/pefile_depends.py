#!/usr/bin/env python

"""
Windows pefile dependencies (exe, dll, ocx, sys...)
"""

import os
import os.path
import sys
import logging
import lib_util
import lib_win32
import lib_common
from lib_properties import pc

import pefile
import win32api

# BEWARE: The PATH is different for Apache user and the results are less meaningful.
# TODO: HOW TO PROPERLY SET THE PATH ???


class EnvPeFile:

    def __init__(self, grph):
        self.grph = grph

        # try paths as described in MSDN
        self.dirs_norm = lib_win32.WindowsCompletePath()

        self.cache_dll_to_imports = dict()

    def recursive_depends(self, fil_nam, max_level):
        fil_nam_lower = fil_nam.lower()

        if fil_nam_lower in self.cache_dll_to_imports:
            # We already have seen this file name.
            root_node = self.cache_dll_to_imports[fil_nam_lower]
        else:
            root_node = lib_uris.gUriGen.FileUri(fil_nam)
            vers_str = lib_win32.VersionString(fil_nam)
            self.grph.add((root_node, pc.property_information, lib_util.NodeLiteral(vers_str)))
            self.cache_dll_to_imports[fil_nam_lower] = root_node

            if max_level == 0:
                return root_node

            pe = pefile.PE(fil_nam)

            try:
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    if lib_util.is_py3:
                        entry_dll = entry.dll.encode('utf-8')
                    else:
                        entry_dll = entry.dll
                    for a_dir in self.dirs_norm:
                        dll_path = os.path.join(a_dir, entry_dll)
                        if os.path.exists(dll_path):
                            subNode = self.recursive_depends(dll_path, max_level - 1)
                            self.grph.add((root_node, pc.property_library_depends, subNode))
                            break
            except AttributeError:
                pass

        return root_node


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    win_module = cgiEnv.GetId()

    logging.debug("win_module=%s", win_module)

    lib_win32.CheckWindowsModule(win_module)

    grph = cgiEnv.GetGraph()

    env = EnvPeFile(grph)

    rootNode = env.recursive_depends(win_module, max_level= 8)

    cgiEnv.OutCgiRdf("LAYOUT_SPLINE")


if __name__ == '__main__':
    Main()

