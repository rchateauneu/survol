#!/usr/bin/env python

"""
Classes in ELF files
"""

import os
import sys

import lib_elf
import lib_util
import lib_common
from lib_properties import pc


Usable = lib_util.UsableLinuxBinary


def Main():
    paramkey_max_depth = "Maximum depth"

    cgiEnv = lib_common.ScriptEnvironment(
        parameters={paramkey_max_depth: 1})

    max_depth = int(cgiEnv.get_parameters(paramkey_max_depth))

    file_shared_lib = cgiEnv.GetId()

    grph = cgiEnv.GetGraph()

    node_shared_lib = lib_common.gUriGen.FileUri(file_shared_lib)

    node_global_namespace = lib_common.gUriGen.ClassUri("__global_namespace", file_shared_lib)
    grph.add((node_shared_lib, pc.property_member, node_global_namespace))

    try:
        readelf = lib_elf.ReadElf(file_shared_lib)
    except Exception as exc:
        lib_common.ErrorMessageHtml("Caught:" + str(exc))

    list_notes = readelf.display_notes()
    for pr in list_notes:
        info_msg = pr[0] + ":" + pr[1]
        grph.add((node_shared_lib, pc.property_information, lib_util.NodeLiteral(info_msg)))

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
                nodeBaseClass = class_to_node(class_split, idx - 1)
                grph.add((nodeBaseClass, pc.property_member, node_class))
            else:
                grph.add((node_shared_lib, pc.property_member, node_class))

        return node_class

    class_already_done = set()

    for sym in list_syms:
        len_split = len(sym.m_splt)
        if len_split > max_depth:
            splt_short = sym.m_splt[:max_depth]
            # TODO: Do the join only once.
            join_short = "::".join(splt_short)
            # TODO: Should test and insert in one lookup only.
            if join_short in class_already_done:
                continue
            class_already_done.add(join_short)

            # So it cannot be a symbol but a class or a namespace.
            cls_nod = class_to_node(splt_short, max_depth)

            # It is already linked to its ancestors.
        else:
            splt_short = sym.m_splt

            sym_nod = lib_common.gUriGen.SymbolUri(sym.m_name_demang, file_shared_lib)
            grph.add((sym_nod, lib_common.MakeProp("Version"), lib_util.NodeLiteral(sym.m_vers)))
            if len_split > 1:
                cls_nod = class_to_node(sym.m_splt, len_split - 1)
                grph.add((cls_nod, pc.property_symbol_defined, sym_nod))
            else:
                grph.add((node_global_namespace, pc.property_symbol_defined, sym_nod))

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_symbol_defined, pc.property_member])


if __name__ == '__main__':
    Main()
