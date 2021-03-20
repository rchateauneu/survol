#!/usr/bin/env python

"""
Windows sessions established on a server
"""

import sys
import lib_util
import lib_common
from lib_properties import pc

import lib_win32
import win32net

def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    hostname = cgiEnv.GetId()

    node_host = lib_common.gUriGen.HostnameUri(hostname)

    grph = cgiEnv.GetGraph()

    # Return the name of the computer, name of the user, and active and idle times for the session.
    # No special group membership is required for level 0 or level 10 calls.
    level = 10

    try:
        lib_win32.WNetAddConnect(hostname)

        session_list = win32net.NetSessionEnum(level, hostname)
    except Exception as exc:
        lib_common.ErrorMessageHtml("Hostname="+hostname+". Exception:"+str(exc))

    for elt_lst in session_list:
        for key_lst in elt_lst:
            val_lst = elt_lst[key_lst]
            grph.add((node_host, lib_common.MakeProp(key_lst), lib_util.NodeLiteral(val_lst)))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
