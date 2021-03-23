#!/usr/bin/env python

"""
Java processes
"""

import sys
import logging

import lib_uris
import lib_util
import lib_common
from sources_types import CIM_Process
from sources_types import java as survol_java
from lib_properties import pc


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    listVMs = survol_java.ListJavaProcesses()

    #listVMs = jvPckVM.list()
    logging.debug("VirtualMachine.list=:")
    for the_pid in listVMs:
        node_process = lib_uris.gUriGen.PidUri(the_pid)
        the_proc_obj = listVMs[the_pid]
        for the_key in the_proc_obj:
            theVal = the_proc_obj[the_key]
            if theVal is None:
                str_val = ""
            else:
                try:
                    str_val = str(theVal)
                except:
                    str_val = "No value"
            logging.debug("%s = %s", the_key, str_val)

            grph.add((node_process, lib_common.MakeProp(the_key), lib_util.NodeLiteral(str_val)))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()

