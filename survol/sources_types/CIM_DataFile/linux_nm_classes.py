#!/usr/bin/env python

"""
Classes methods from nm command
"""

import os
import sys
import logging
import lib_nm
import lib_util
import lib_common
from lib_properties import pc

Usable = lib_util.UsableLinuxBinary

# TODO: This is not completely finished.
# TODO: Should use the type "class" in "sources_types/class", and also "sources_types/com" for COM types.


_nodes_by_class = {}


def _extract_class_from_symbol(symbolnam):
    """The symbols must have been demangled."""

    # Should be very close to the end.
    last_par_close = symbolnam.rfind(")")
    if last_par_close == -1:
        return ""

    # Searches for the parenthesis matching the last one.
    cnt = 1
    last_par_open = last_par_close - 1
    while cnt != 0:
        if last_par_open == 0:
            return ""
        if symbolnam[last_par_open] == ")":
            cnt += 1
        elif symbolnam[last_par_open] == "(":
            cnt -= 1
        last_par_open -= 1


    # double_colon = symbol.rfind( "::", last_par_open )
    without_signature = symbolnam[:last_par_open + 1]
    double_colon = without_signature.rfind("::")
    if double_colon == -1:
        return ""

    last_space = symbolnam[:double_colon].rfind(" ")
    if last_space == -1:
        last_space = 0

    # class_nam = symbol[ double_colon + 1 : last_par_open ]
    class_nam = symbolnam[last_space:double_colon]
    logging.debug("symbol=%s without_signature=%s class_nam=%s", symbolnam, without_signature, class_nam)
    return class_nam


def _add_symbol_in_class(grph, node_shared_lib, symbolnam, file_name, prop):
    sym_class = _extract_class_from_symbol(symbolnam)

    symbol_node = lib_common.gUriGen.SymbolUri(lib_util.EncodeUri(symbolnam), file_name)
    if sym_class != "":
        try:
            node_class = _nodes_by_class[sym_class]
        except KeyError:
            node_class = lib_common.gUriGen.ClassUri(sym_class, file_name)
            _nodes_by_class[sym_class] = node_class
            grph.add((node_shared_lib, pc.property_member, node_class))
        grph.add((node_class, prop, symbol_node))
    else:
        grph.add((node_shared_lib, prop, symbol_node))
    return symbol_node


def _add_known_symbol(grph, nodeSharedLib, symbolnam, file_name, symbol_type):
    symbolNode = _add_symbol_in_class(grph, nodeSharedLib, symbolnam, file_name, pc.property_symbol_defined)
    grph.add((symbolNode, pc.property_symbol_type, lib_util.NodeLiteral(symbol_type)))


def _add_unknown_symbol(grph, node_shared_lib, symbolnam):
    symbol_node = _add_symbol_in_class(grph, node_shared_lib, symbolnam, "*", pc.property_symbol_undefined)


def Main():
    cgiEnv = lib_common.CgiEnv()
    file_shared_lib = cgiEnv.GetId()

    grph = cgiEnv.GetGraph()

    node_shared_lib = lib_common.gUriGen.FileUri(file_shared_lib)

    cnt = 0
    for symbol_type, tail in lib_nm.GetSymbols(file_shared_lib):
        if symbol_type == 'T' or symbol_type == 't':
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
