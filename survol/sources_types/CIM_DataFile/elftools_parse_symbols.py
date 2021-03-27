#!/usr/bin/env python

"""
Symbols in ELF files
"""

import os
import sys
import logging

import lib_elf
import lib_util
import lib_common
from lib_properties import pc


Usable = lib_util.UsableLinuxBinary


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    file_shared_lib = cgiEnv.GetId()

    grph = cgiEnv.GetGraph()

    node_shared_lib = lib_common.gUriGen.FileUri(file_shared_lib)

    try:
        readelf = lib_elf.ReadElf(file_shared_lib)
    except Exception as exc:
        lib_common.ErrorMessageHtml("Caught:" + str(exc))

    list_notes = readelf.display_notes()
    for pr in list_notes:
        infoMsg = pr[0] + ":" + pr[1]
        grph.add((node_shared_lib, pc.property_information, lib_util.NodeLiteral(infoMsg)))

    list_syms, set_classes = readelf.display_symbol_tables()

    Main.nodesByClass = dict()

    def class_to_node(class_split, idx):
        cls_nam = "::".join(class_split[:idx])
        try:
            node_class = Main.nodesByClass[cls_nam]
        except KeyError:
            node_class = lib_common.gUriGen.ClassUri(cls_nam, file_shared_lib)
            # TODO: Create base classes ?
            Main.nodesByClass[cls_nam] = node_class

            if idx > 1:
                node_base_class = class_to_node(class_split, idx - 1)
                grph.add((node_base_class, pc.property_member, node_class))
            else:
                grph.add((node_shared_lib, pc.property_member, node_class))

        return node_class

    cnt = 0
    for sym in list_syms:
        cnt += 1
        # TODO: How to process big libraries ?
        # TODO: Maybe group by symbols.
        if cnt > 500:
            logging.error("Exceeded number of symbols")
            break

        if not sym.m_splt[0].startswith("std"):
            continue

        sym_nod = lib_common.gUriGen.SymbolUri(sym.m_name_demang, file_shared_lib)
        grph.add((sym_nod, lib_common.MakeProp("Version"), lib_util.NodeLiteral(sym.m_vers)))
        len_split = len(sym.m_splt)
        if len_split > 1:
            cls_nod = class_to_node(sym.m_splt, len_split - 1)
            grph.add((cls_nod, pc.property_symbol_defined, sym_nod))
        else:
            grph.add((node_shared_lib, pc.property_symbol_defined, sym_nod))

    # TODO: Fix this when adding pc.property_member
    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_symbol_defined])


if __name__ == '__main__':
    Main()
