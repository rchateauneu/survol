#!/usr/bin/env python

"""
DOxygen parsing
"""

import os
import sys
import lib_common
import lib_util
from lib_properties import pc
import lib_doxygen


def Usable(entity_type,entity_ids_arr):
    """Not a source file"""

    if not lib_util.check_program_exists("doxygen"):
        return False

    fil_nam = entity_ids_arr[0]
    fil_ext = os.path.splitext(fil_nam)[1]
    if fil_ext.lower() in lib_doxygen.file_extensions_dox:
        return True

    return os.path.isdir(fil_nam)


def Main():
    paramkey_recursive = "Recursive exploration"
    paramkey_explode_classes = "Explode classes members"

    cgiEnv = lib_common.ScriptEnvironment(
        parameters={paramkey_recursive: False, paramkey_explode_classes: False})

    param_explode_classes = int(cgiEnv.get_parameters(paramkey_explode_classes))

    file_param = cgiEnv.GetId()

    grph = cgiEnv.GetGraph()

    objects_by_location = lib_doxygen.DoxygenMain(False, file_param)

    directory_name = os.path.dirname(file_param)
    root_node = lib_common.gUriGen.FileUri(file_param)

    lib_doxygen.CreateObjs(grph, root_node, directory_name, objects_by_location, param_explode_classes)

    # TODO: THE GENERATED GRAPH SHOULD BE MORE SIMILAR TO DOXYGEN'S.

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_symbol_defined, pc.property_member])


if __name__ == '__main__':
    Main()
