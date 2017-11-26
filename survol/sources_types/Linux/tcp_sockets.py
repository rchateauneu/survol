#!/usr/bin/python

"""
TCP sockets
"""

# The Python module psutil is not needed

# $ netstat -ap -t
# Active Internet connections (servers and established)
# Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
# tcp        0      0 fedora22:41347          0.0.0.0:*               LISTEN      2134/rygel
# tcp        0      0 0.0.0.0:netbios-ssn     0.0.0.0:*               LISTEN      -
# tcp        0      0 fedora22:svrloc         0.0.0.0:*               LISTEN      -
# tcp        0      0 localhost:svrloc        0.0.0.0:*               LISTEN      -
# tcp        0      0 fedora22:41644          0.0.0.0:*               LISTEN      2134/rygel
# tcp        0      0 0.0.0.0:rfb             0.0.0.0:*               LISTEN      2139/vino-server
# tcp        0      0 fedora22:domain         0.0.0.0:*               LISTEN      -
# tcp        0      0 0.0.0.0:ftp             0.0.0.0:*               LISTEN      -
# tcp        0      0 0.0.0.0:ssh             0.0.0.0:*               LISTEN      -
# tcp        0      0 localhost:ipp           0.0.0.0:*               LISTEN      -
# tcp        0      0 localhost:44729         0.0.0.0:*               LISTEN      2134/rygel
# tcp        0      0 localhos:x11-ssh-offset 0.0.0.0:*               LISTEN      -
# tcp        0      0 0.0.0.0:microsoft-ds    0.0.0.0:*               LISTEN      -
# tcp        1      0 fedora22:39888          dg-in-f147.1e100.:https CLOSE_WAIT  4729/evolution-addr
# tcp        0      0 fedora22:41347          192.168.0.14:64278      ESTABLISHED 2134/rygel
