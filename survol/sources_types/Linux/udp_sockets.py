#!/usr/bin/env python

"""
UDP sockets
"""

import lib_util
import lib_common

# $ netstat -ap -u
# Active Internet connections (servers and established)
# Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
# udp        0      0 localhost:39623         0.0.0.0:*                           2134/rygel
# udp        0      0 fedora22:39825          0.0.0.0:*                           2134/rygel
# udp        0      0 fedora22:46107          0.0.0.0:*                           2134/rygel

# TODO: NOT IMPLEMENTED YET


def Main():
    cgiEnv = lib_common.CgiEnv()
    grph = cgiEnv.GetGraph()

    lib_common.ErrorMessageHtml("Not implemented yet")

    cgiEnv.OutCgiRdf("LAYOUT_RECT")


if __name__ == '__main__':
    Main()


