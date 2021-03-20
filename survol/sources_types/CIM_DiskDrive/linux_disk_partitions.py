#!/usr/bin/env python

"""
Linux disk partitions
"""

import sys
import socket
import lib_util
import lib_common
from lib_properties import pc

Usable = lib_util.UsableLinux

# Must finish this.

def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
