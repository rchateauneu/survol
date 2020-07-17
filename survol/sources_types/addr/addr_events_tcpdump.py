#!/usr/bin/env python

"""
Socket content sniffing with tcpdump.
"""

import sys
import lib_util
import lib_common
import lib_wbem
from lib_properties import pc

# For the moment, it must not be usable.
# See process_events_system_calls.py for more explanations.
def Usable(entity_type,entity_ids_arr):
    """Disabled yet"""
    return False

def Main():
    cgiEnv = lib_common.CgiEnv()
    socketNam = cgiEnv.GetId()

    grph = cgiEnv.GetGraph()

    cgiEnv.OutCgiRdf()

if __name__ == '__main__':
    Main()



