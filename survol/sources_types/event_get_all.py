#!/usr/bin/python

"""
Get all dynamic events
"""

import sys
import lib_common
import lib_util
import lib_event

# See event_put.py for more explanations.
# This gets all received events and displays them.
# The type of these data is exactly what can be returned by any scripts.

def Main():

    # This can process remote hosts because it does not call any script, just shows them.
    cgiEnv = lib_common.CgiEnv()
    sys.stderr.write("event_get_all.py\n")
    # entity_id = cgiEnv.m_entity_id
    # entity_host = cgiEnv.GetHost()

    grph = cgiEnv.GetGraph()

    # rootNode = lib_util.RootUri()


    sys.stderr.write("event_get_all.py About to get events\n")
    arrTriples = lib_event.data_retrieve_all()
    for tripl in arrTriples:
        grph.add(tripl)

    cgiEnv.OutCgiRdf()

if __name__ == '__main__':
    Main()
