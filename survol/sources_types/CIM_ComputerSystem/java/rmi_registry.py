#!/usr/bin/env python

"""
RMI registry
"""

import sys
import re
import socket
import psutil
import lib_util
import lib_common

# TODO: This script is not used yet.

from sources_types import java as survol_java

from lib_properties import pc


def Main():

    cgiEnv = lib_common.ScriptEnvironment( )
    hostname = cgiEnv.GetId()

    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    hostAddr = lib_util.GlobalGetHostByName(hostname)

    hostNode = lib_common.gUriGen.HostnameUri(hostname)

    for the_proc in psutil.process_iter():
        the_pid = the_proc.pid

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
