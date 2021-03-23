#!/usr/bin/env python

"""
COM type library entries
"""

import os
import sys

import lib_uris
import lib_common
import lib_util
from lib_properties import pc

import pythoncom
import win32con
import win32api

import lib_com_type_lib

Usable = lib_util.UsableWindows


def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    fname = cgiEnv.GetId()

    grph = cgiEnv.GetGraph()

    fname_mystery_node = lib_uris.gUriGen.ComTypeLibUri(fname)

    # TODO: Difficulty, many entries.

    HLITypeKinds = {
            pythoncom.TKIND_ENUM      : 'Enumeration',
            pythoncom.TKIND_RECORD    : 'Record',
            pythoncom.TKIND_MODULE    : 'Module',
            pythoncom.TKIND_INTERFACE : 'Interface',
            pythoncom.TKIND_DISPATCH  : 'Dispatch',
            pythoncom.TKIND_COCLASS   : 'CoClass',
            pythoncom.TKIND_ALIAS     : 'Alias',
            pythoncom.TKIND_UNION     : 'Union'
      }


    try:
        tlb = pythoncom.LoadTypeLib(fname)
    except pythoncom.com_error:
        lib_common.ErrorMessageHtml("Cannot load:" + fname)

    for idx in range(tlb.GetTypeInfoCount()):
        try:
            info_typ = tlb.GetTypeInfoType(idx)

            typ_nam = HLITypeKinds[info_typ]

            sub_entity_type = lib_util.ComposeTypes("com", "type_lib_entry", typ_nam.lower())

            name_com_entry_uri = "%s_(%d)" % (fname, idx)

            # TODO: Maybe this will be cleaner. Quick and dirty solution for the moment.
            # UriNodeCreatorName = "ComTypeLibEntry" + typ_nam + "Uri"
            # funcCreate = getattr( lib_common, UriNodeCreatorName )
            # entry_node = funcCreate( "%s_(%d)" % ( fname, idx ) )
            entry_node = lib_util.EntityUri(sub_entity_type, name_com_entry_uri)

            name, doc, ctx, helpFile = tlb.GetDocumentation(idx)

            grph.add((entry_node, pc.property_information, lib_util.NodeLiteral("name=%s" % name)))
            grph.add((entry_node, pc.property_information, lib_util.NodeLiteral("type=%s" % typ_nam)))
            grph.add((fname_mystery_node, pc.property_com_entry, entry_node))

        except pythoncom.com_error as exc:
            lib_common.ErrorMessageHtml("Caught:" + exc)

    cgiEnv.OutCgiRdf("LAYOUT_RECT")


if __name__ == '__main__':
    Main()
