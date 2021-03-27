#!/usr/bin/env python

"""
Entry points displayed from nm command
"""

import os
import sys
import logging

import lib_uris
import lib_nm
import lib_util
import lib_common
from lib_properties import pc


Usable = lib_util.UsableLinuxBinary


def _add_known_symbol(grph, node_shared_lib, symbolnam, file_name, type):
    symbol_node = lib_uris.gUriGen.SymbolUri(lib_util.EncodeUri(symbolnam), file_name)
    grph.add((node_shared_lib, pc.property_symbol_defined, symbol_node))
    grph.add((symbol_node, pc.property_symbol_type, lib_util.NodeLiteral(type)))


def _add_unknown_symbol(grph, node_shared_lib, symbolnam):
    symbol_node = lib_uris.gUriGen.SymbolUri(lib_util.EncodeUri(symbolnam), "*")
    grph.add((node_shared_lib, pc.property_symbol_undefined, symbol_node))


def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    file_shared_lib = cgiEnv.GetId()

    grph = cgiEnv.GetGraph()

    node_shared_lib = lib_uris.gUriGen.FileUri(file_shared_lib)

    cnt = 0
    for symbol_type, tail in lib_nm.GetSymbols(file_shared_lib):
        if symbol_type == 'T' or type == 't':
            _add_known_symbol(grph, node_shared_lib, tail, file_shared_lib, symbol_type)
            #"U" The symbol is undefined.
        elif symbol_type == 'U':
            _add_unknown_symbol(grph, node_shared_lib, tail)
        else:
            # Does not display all symbols because it is too much information.
            # _add_known_symbol(tail, file_shared_lib, symbol_type)
            pass
        cnt += 1

    logging.debug("Nm: Processed %d lines", cnt)
    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_symbol_defined, pc.property_symbol_undefined])


if __name__ == '__main__':
    Main()
