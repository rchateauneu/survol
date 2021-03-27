#!/usr/bin/env python

"""
Windows symbol information, with pefile package.
"""

import re
import os
import os.path
import sys
import logging
import lib_uris
import lib_util
import lib_win32
import lib_common
import string
import lib_pefile
import lib_symbol
from lib_properties import pc

import pefile
import win32api


# This can run on a PE file only.
def Usable(entity_type,entity_ids_arr):
    """Can run on a pe file only"""

    try:
        # This is a bit hard-coded, the file comes second, and is not mandatory.
        fil_nam = entity_ids_arr[1]
        pe = pefile.PE(fil_nam)
        return True
    except Exception:
        return False


def FindPESymbol(fil_nam, symbol_nam):
    try:
        pe = pefile.PE(fil_nam)

        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if  lib_pefile.UndecorateSymbol(sym.name) == symbol_nam:
                return sym
    except Exception as exc:
        lib_common.ErrorMessageHtml("FindPESymbol %s %s. Caught:%s" % (fil_nam, symbol_nam, str(exc)))
    return None


def Main():

    cgiEnv = lib_common.ScriptEnvironment()

    # "NtOpenObjectAuditAlarm%40C%3A\windows\system32\ntdll.dll"
    # Filename is optional.

    # The symbol is already demangled.
    symbol_encode = cgiEnv.m_entity_id_dict["Name"]
    # TODO: This should be packaged in lib_symbol.
    symbol_nam = lib_util.Base64Decode(symbol_encode)
    fil_nam = cgiEnv.m_entity_id_dict["File"]

    logging.debug("symbol=%s fil_nam=%s", symbol_nam, fil_nam)

    grph = cgiEnv.GetGraph()

    sym_node = lib_uris.gUriGen.SymbolUri(symbol_nam, fil_nam)

    if fil_nam:
        fil_node = lib_common.gUriGen.FileUri( fil_nam )
        grph.add((fil_node, pc.property_symbol_defined, sym_node))
        vers_str = lib_win32.VersionString(fil_nam)
        grph.add((fil_node, pc.property_information, lib_util.NodeLiteral(vers_str)))

        sym = FindPESymbol(fil_nam, symbol_nam)

        if sym is not None:
            # Non-breaking space: A0    10100000         &#160;    &nbsp;
            doc_txt = getattr(sym, "__doc__")

            # This string is filled with spaces and CR which are translated into "&#160;".
            doc_txt = re.sub(r'\s+', ' ', doc_txt).strip()

            grph.add((sym_node, pc.property_information,lib_util.NodeLiteral(doc_txt)))

            # Possible values are "name","offset","ordinal","forwarder"
            try:
                fwrd = getattr(sym, "forwarder")
                grph.add((sym_node, lib_common.MakeProp("Forwarder"), lib_util.NodeLiteral(fwrd)))
            except:
                pass

            try:
                fwrd = getattr(sym,"ordinal")
                grph.add((sym_node, lib_common.MakeProp("Ordinal"), lib_util.NodeLiteral(fwrd)))
            except:
                pass

            ful_nam, lst_args = lib_symbol.SymToArgs(symbol_nam)
            if lst_args:
                for arg in lst_args:
                    # TODO: Order of arguments must not be changed.
                    arg_node = lib_uris.gUriGen.ClassUri(arg, fil_nam)
                    grph.add((sym_node, pc.property_argument, arg_node))

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_argument])


if __name__ == '__main__':
    Main()
