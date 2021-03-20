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


def Usable(entity_type, entity_ids_arr):
    return lib_util.check_program_exists("doxygen")


def Main():
    paramkey_recursive = "Recursive exploration"
    paramkey_explode_classes = "Explode classes members"

    cgiEnv = lib_common.ScriptEnvironment(
        parameters={paramkey_recursive: False, paramkey_explode_classes: False})

    param_recursive_exploration = int(cgiEnv.get_parameters(paramkey_recursive))
    param_explode_classes = int(cgiEnv.get_parameters(paramkey_explode_classes))

    file_param = cgiEnv.GetId()

    grph = cgiEnv.GetGraph()

    objects_by_location = lib_doxygen.DoxygenMain(param_recursive_exploration, file_param)

    directory_name = file_param
    root_node = lib_common.gUriGen.DirectoryUri(directory_name)

    lib_doxygen.CreateObjs(grph, root_node, directory_name, objects_by_location, param_explode_classes)

    # TODO: THE GENERATED GRAPH SHOULD BE MORE SIMILAR TO DOXYGEN'S.

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_symbol_defined, pc.property_member])


if __name__ == '__main__':
    Main()
