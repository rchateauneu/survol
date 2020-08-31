#!/usr/bin/env python

"""
Sends one event per second. Test purpose.
"""

import os
import sys
import time
import datetime
import lib_util
import lib_common
import lib_properties

def Main():
    # NE PAS EXECUTER CA SI LE DAEMON FONCTIONNE MAIS PLUTOT ALLER CHERCHER LES EVENEMENTS
    # QUE LE MEME SCRIPT, EXECUTE PAR LE DAEMON, A CREE. ET ENSUITE ON SORT.
    cgiEnv = lib_common.CgiEnv()

    grph = cgiEnv.GetGraph()
    timestamp_property = lib_properties.MakeProp("ticker_timestamp")
    current_pid = os.getpid()
    node_process = lib_common.gUriGen.PidUri(current_pid)

    datetime_now = datetime.now()
    timestamp_literal = datetime_now.strftime("%Y-%m-%d %H:%M:%S")
    # Ca va ecrire des events ou bien remplir
    grph.add((node_process, timestamp_property, lib_common.NodeLiteral(timestamp_literal)))

    cgiEnv.OutCgiRdf()

if __name__ == '__main__':
    if lib_util.is_snapshot_behaviour():
        Main()
    else:
        # Or any condition telling that it does not run as a CGI script, like mode == "daemon",
        # or the absence of HTTP environment variables.
        # The looping logic might be different but the ideas are
        # - to use a similar code for a snapshot and for an event loop.
        # - More importantly, write in a plain RDFLIB graph, flushed by OutCgiRdf().
        #   This greatly simplifies the code.
        while True:
            Main()



