#!/usr/bin/env python

"""
Symbol information.
"""

import os
import sys
import logging

import lib_uris
import lib_util
import lib_common
import lib_symbol
from lib_properties import pc


# It does not need the pefile library.
def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    # "NtOpenObjectAuditAlarm%40C%3A\windows\system32\ntdll.dll"

    # The symbol is already demangled.
    symbol_encode = cgiEnv.m_entity_id_dict["Name"]
    # TODO: This should be packaged in lib_symbol.
    symbol_nam = lib_util.Base64Decode(symbol_encode)
    fil_nam = cgiEnv.m_entity_id_dict["File"]

    logging.debug("symbol=%s fil_nam=%s", symbol_nam, fil_nam)

    grph = cgiEnv.GetGraph()

    sym_node = lib_uris.gUriGen.SymbolUri(symbol_nam, fil_nam)
    if fil_nam:
        filNode = lib_uris.gUriGen.FileUri(fil_nam)
        grph.add((filNode, pc.property_symbol_defined, sym_node))

    ful_nam, lst_args = lib_symbol.SymToArgs(symbol_nam)
    if lst_args:
        for arg in lst_args:
            # TODO: Order of arguments must not be changed.
            arg_node = lib_uris.gUriGen.ClassUri(arg, fil_nam)
            grph.add((sym_node, pc.property_argument, arg_node))

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_argument])


if __name__ == '__main__':
    Main()
