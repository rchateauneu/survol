#!/usr/bin/env python

"""
Scan process for COM classes
"""

import os
import sys

import lib_uris
import lib_util
import lib_common
from lib_properties import pc
import lib_com_type_lib

from sources_types import CIM_Process
from sources_types.CIM_Process import memory_regex_search

SlowScript = True


def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    pidint = int(cgiEnv.GetId())

    grph = cgiEnv.GetGraph()

    node_process = lib_uris.gUriGen.PidUri(pidint)

    try:
        rgx_http = r"\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}"

        resu_com_classes = memory_regex_search.GetRegexMatches(pidint, rgx_http)

        prop_com_class = lib_common.MakeProp("COM class")
        for class_idx in resu_com_classes:
            com_class_id = resu_com_classes[class_idx]
            # On Python3, this is a bytes which must be converted to str.
            com_class_id = str(com_class_id)

            # comClass = "{DB7A405D-208F-4E88-BA0A-132ACFA0B5B6}" for example.
            typelib_node = lib_uris.gUriGen.ComRegisteredTypeLibUri(com_class_id)
            grph.add((node_process, prop_com_class, typelib_node))

    except Exception as exc:
        lib_common.ErrorMessageHtml("Error:%s. Protection ?" % str(exc))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()

