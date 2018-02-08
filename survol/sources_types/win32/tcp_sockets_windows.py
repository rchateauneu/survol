#!/usr/bin/python

"""
TCP Windows sockets with netstat
"""

# Many advantages compared to psutil:
#   The Python module psutil is not needed
#   psutil gives only sockets if the process is accessible.
#   It is much faster.



# C:\Users\rchateau>netstat -on
#
# Active Connections
#
#   Proto  Local Address          Foreign Address        State           PID
#   TCP    127.0.0.1:4369         127.0.0.1:51508        ESTABLISHED     3120
#   TCP    127.0.0.1:5357         127.0.0.1:54599        TIME_WAIT       0
#   TCP    [fe80::3c7a:339:64f0:2161%11]:1521  [fe80::3c7a:339:64f0:2161%11]:51769  ESTABLISHED     4316
#   TCP    [fe80::3c7a:339:64f0:2161%11]:51769  [fe80::3c7a:339:64f0:2161%11]:1521  ESTABLISHED     4776

asdfasdf

