#!/usr/bin/env python

"""
Users
"""

import sys
import socket
import psutil
import lib_common
from lib_properties import pc


def Main():
    cgiEnv = lib_common.CgiEnv()

    grph = cgiEnv.GetGraph()

    try:
        # Something like [suser(name='John', terminal=None, host='0.246.33.0', started=1411052436.0)]
        users_list = psutil.users()
    except Exception as exc:
        lib_common.ErrorMessageHtml("psutil.users raised:%s" % exc)

    for user in users_list:
        usr_nam = lib_common.format_username(user.name)
        user_node = lib_common.gUriGen.UserUri(usr_nam)

        grph.add((lib_common.nodeMachine, pc.property_user, user_node))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
