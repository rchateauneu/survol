#!/usr/bin/env python

"""
PEFile imported entries and modules
"""


import sys
import logging
import lib_util
import lib_uris
import lib_win32
import lib_common
import lib_shared_lib_path
from lib_properties import pc

import pefile

# TODO: THIS SHOULD USE THE ENVIRONMENT VARIABLE "PATH" OF THE RUNNING PROCESS.
# TODO: INSTEAD, IT IS USING THE CURRENT PROCESS'ONE, WHICH IS WRONG.


class EnvPeFile:
    def __init__(self, grph):
        self.grph = grph

    def _recursive_depends(self, fil_nam, max_level):
        root_node = lib_uris.gUriGen.FileUri(fil_nam)
        vers_str = lib_win32.VersionString(fil_nam)
        self.grph.add((root_node, pc.property_information, lib_util.NodeLiteral(vers_str)))

        if max_level == 0:
            return root_node

        # TODO: Consider a cache for this value. Beware of case for filNam.
        pe = pefile.PE(fil_nam)

        try:
            pe.DIRECTORY_ENTRY_IMPORT
        except AttributeError as exc:
            logging.info("No attribute:%s", exc)
            return None

        logging.debug("fil_nam=%s Imports=%d", fil_nam, len(pe.DIRECTORY_ENTRY_IMPORT))
        logging.debug("dir(pe)=%s", dir(pe))

        try:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                if lib_util.is_py3:
                    entry_dll = entry.dll.decode('utf-8')
                else:
                    entry_dll = entry.dll
                logging.debug("entry_dll=%s", entry_dll)
                assert isinstance(entry_dll, str), "File must be a str"

                dll_path = lib_shared_lib_path.FindPathFromSharedLibraryName(entry_dll)
                logging.debug("dll_path:%s", dll_path)
                if dll_path:
                    sub_node = self._recursive_depends(dll_path, max_level - 1)
                    # Maybe there are no sub-dependencies.
                    if sub_node:
                        self.grph.add((root_node, pc.property_library_depends, sub_node))

                        for imp in entry.imports:
                            # FIXME: Why displaying one entry only ?
                            if imp.name is not None:
                                sym_node = lib_uris.gUriGen.SymbolUri(imp.name.encode(), dll_path)
                                self.grph.add((sub_node, pc.property_symbol_declared, sym_node))
                            break
        except AttributeError as exc:
            logging.error("Caught:%s", exc)

        return root_node


def Main():
    paramkey_maximum_depth = "Maximum depth"

    cgiEnv = lib_common.ScriptEnvironment(parameters={paramkey_maximum_depth: 3})

    max_depth = int(cgiEnv.get_parameters(paramkey_maximum_depth))

    win_module = cgiEnv.GetId()

    logging.debug("win_module=%s", win_module)

    lib_win32.CheckWindowsModule(win_module)

    grph = cgiEnv.GetGraph()

    env = EnvPeFile(grph)

    rootNode = env._recursive_depends(win_module, max_depth)

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_symbol_declared])


if __name__ == '__main__':
    Main()

