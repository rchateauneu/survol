#!/usr/bin/env python

"""
RMI registry
"""

import sys
import re
import socket
import psutil
import lib_util
import lib_uris
import lib_common

# TODO: Not implemented yet.
# TODO: The registry is used to locate the first remote object on which an application needs to invoke methods.
# TODO: The intention is to display these remote objects.
# TODO: See https://www.researchgate.net/publication/341271544_Remote_Method_Invocation_Using_Python

from sources_types import java as survol_java
from lib_properties import pc


def Main():

    cgiEnv = lib_common.ScriptEnvironment()
    hostname = cgiEnv.GetId()

    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    host_addr = lib_util.GlobalGetHostByName(hostname)

    host_node = lib_uris.gUriGen.HostnameUri(hostname)

    for the_proc in psutil.process_iter():
        the_pid = the_proc.pid

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
