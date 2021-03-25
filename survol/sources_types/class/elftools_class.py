#!/usr/bin/env python

"""
ELF files to class
"""

import os
import sys

import lib_uris
import lib_elf
import lib_util
import lib_common
from lib_properties import pc


# TODO: This does not work for a Java class: Must check the file name and magic number ("CAFEBABE").
def Usable(entity_type, entity_ids_arr):
    return True


def Main():
    paramkey_max_depth = "Maximum depth"

    cgiEnv = lib_common.ScriptEnvironment(
        parameters={paramkey_max_depth: 2})

    max_depth = int(cgiEnv.get_parameters(paramkey_max_depth))

    name_top_class = cgiEnv.m_entity_id_dict["Name"]

    # An executable, shared library. Maybe static library.
    file_name = cgiEnv.m_entity_id_dict["File"]

    grph = cgiEnv.GetGraph()

    # This expects that the string is not a symbol name but a class or a namespace.
    # Otherwise we would have scan the list of symbols, to find out.
    node_shared_lib = lib_uris.gUriGen.FileUri(file_name)

    try:
        readelf = lib_elf.ReadElf(file_name)
    except Exception as exc:
        lib_common.ErrorMessageHtml("Caught:" + str(exc))

    list_notes = readelf.display_notes()
    for pr in list_notes:
        info_msg = pr[0] + ":" + pr[1]
    grph.add((node_shared_lib, pc.property_information, lib_util.NodeLiteral(info_msg)))

    # TODO: List of classes is not needed.
    # TODO: Just read the symbols we need.
    list_syms, set_classes = readelf.display_symbol_tables()

    Main.nodesByClass = dict()

    def class_to_node(classSplit, idx):
        cls_nam = "::".join(classSplit[:idx ])
        try:
            node_class = Main.nodesByClass[cls_nam]
        except KeyError:
            node_class = lib_uris.gUriGen.ClassUri(cls_nam, file_name)
            # TODO: Create base classes ?
            Main.nodesByClass[cls_nam] = node_class

            if idx > 1:
                node_base_class = class_to_node(classSplit, idx - 1)
                grph.add((node_base_class, pc.property_member, node_class))
            else:
                grph.add((node_shared_lib, pc.property_member, node_class))

        return node_class

    class_already_done = set()

    class_prefix = name_top_class + "::"
    len_prefix = len(name_top_class.split("::"))
    max_depth_total = max_depth + len_prefix

    for sym in list_syms:
        if not sym.m_name.startswith(class_prefix):
            continue

        len_split = len(sym.m_splt)
        if len_split > max_depth_total:
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

            sym_nod = lib_uris.gUriGen.SymbolUri(sym.m_name, file_name)
            grph.add((sym_nod, lib_common.MakeProp("Version"), lib_util.NodeLiteral(sym.m_vers)))
            if len_split > 1:
                cls_nod = class_to_node(sym.m_splt, len_split - 1)
                grph.add((cls_nod, pc.property_symbol_defined, sym_nod))
            else:
                node_global_namespace = lib_uris.gUriGen.ClassUri("__global_namespace", file_name)
                grph.add((node_global_namespace, pc.property_symbol_defined, sym_nod))

    # TODO: Fix or check this when adding pc.property_member
    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_symbol_defined, pc.property_member])


if __name__ == '__main__':
    Main()
