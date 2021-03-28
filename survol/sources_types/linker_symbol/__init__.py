"""
Callable or data library symbol
"""

import sys
import logging

import lib_properties
from lib_properties import pc
import lib_uris
import lib_util
import lib_common


def EntityOntology():
    return (["Name", "File"],)


def EntityName(entity_ids_arr):
    entity_id = entity_ids_arr[0]
    try:
        # Trailing padding.
        resu = lib_util.Base64Decode(entity_id)
        # TODO: Should have a more generic solution: i.e. always b64 encode CGI-incompatible strings.
        # See lib_uris.SymbolUri which does the encoding.
        resu = lib_util.html_escape(resu)
        return resu
    except TypeError as exc:
        logging.error("CANNOT DECODE: symbol=(%s):%s", entity_id, str(exc))
        return entity_id


# Each entity can have such a file with its name as file name.
# Then in its file, by convention adds information to a node.
def AddInfo(grph, node, entity_ids_arr):
    # TODO: Define symbol with two different key/vals, instead of this. Bad syntax !!!
    try:
        file_name = entity_ids_arr[1]
    except IndexError:
        file_name = ""

    # WRONG, TODO: Must check the node ???
    file_node = lib_uris.gUriGen.FileUri(file_name)
    grph.add((file_node, pc.property_symbol_defined, node))


# This adds a function call which is modelled with a function name and a file.
# This is used with plain code and with Python.
# This should include a line number or an address.
def AddFunctionCall(grph, call_node_prev, proc_node, call_name, file_name, code_location=None):
    logging.debug("file_name=%s", file_name)
    if call_name != None:
        call_node_new = lib_uris.gUriGen.SymbolUri(call_name, file_name)
        if not call_node_prev is None:
            # Intermediary function in the callstack.
            grph.add((call_node_new, pc.property_calls, call_node_prev))
        node_file = lib_uris.gUriGen.FileUri(file_name)
        grph.add((node_file, pc.property_defines, call_node_new))

        # This adds an address or a line number.
        # TODO: This should make the node unique, therefore a new class should be created.
        if code_location:
            grph.add((call_node_new, lib_common.MakeProp("Code location"), lib_util.NodeLiteral(code_location)))

        return call_node_new
    else:
        # Top-level function of the process.
        if not call_node_prev is None:
            grph.add((proc_node, pc.property_calls, call_node_prev))
        return None
