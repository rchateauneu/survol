#!/usr/bin/env python

"""
Get all dynamic events
"""

import sys
import logging
import lib_common
import lib_util
import lib_kbase

# See event_put.py for more explanations.
# This gets all received events and displays them.
# The type of these data is exactly what can be returned by any scripts.


def Main():
    lib_common.set_events_credentials()

    # This can process remote hosts because it does not call any script, just shows them.
    cgiEnv = lib_common.ScriptEnvironment()
    logging.debug("Starting.")

    grph = cgiEnv.GetGraph()

    logging.debug("About to get events")
    num_triples = lib_kbase.retrieve_all_events_to_graph_then_clear(grph)

    logging.debug("num_triples=%d" % num_triples)
    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
