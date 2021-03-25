#!/usr/bin/env python

"""
Oracle databases accessed
"""

import os
import sys

import lib_uris
import lib_common
from lib_properties import pc
import lib_oracle


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    try:
        procid = int( cgiEnv.GetId() )
    except Exception:
        lib_common.ErrorMessageHtml("Must provide a pid")


    # For the moment, this is hard-coded.
    # It must list all databases to which the process is connected to.
    # For that:
    # - Try all databases in tnsnames.ora: very slow.
    # - Or snoop packets with Oracle protocol
    # - Or see, among the sockets helpd by the process, which ones are in the tnsnames.ora.


    # TODO: THIS IS NOT FINISHED.

    node_process = lib_uris.gUriGen.PidUri(procid)

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()





