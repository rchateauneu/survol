#!/usr/bin/env python

"""
fuser command.

Identify processes using files or sockets with Linux command fuser
"""

import os
import sys
import logging

import lib_uris
import lib_util
import lib_common
from lib_properties import pc

Usable = lib_util.UsableLinux


def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    file_name = cgiEnv.GetId()

    grph = cgiEnv.GetGraph()

    nodeFile = lib_uris.gUriGen.FileUri(file_name)

    logging.debug("Fuser file=%s", file_name)

    lib_common.ErrorMessageHtml("linux_fuser.py not implemented yet")

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
