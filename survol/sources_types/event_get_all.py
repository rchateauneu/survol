#!/usr/bin/env python

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
    DEBUG("event_get_all.py")

    grph = cgiEnv.GetGraph()

    DEBUG("event_get_all.py About to get events")
    arrTriples = lib_event.data_retrieve_all()
    num_triples = 0
    for tripl in arrTriples:
        grph.add(tripl)
        num_triples += 1
    sys.stderr.write("%s num_triples=%d\n" % (__file__, num_triples))

    DEBUG("num_triples=%d" % num_triples)
    cgiEnv.OutCgiRdf()

if __name__ == '__main__':
    Main()
