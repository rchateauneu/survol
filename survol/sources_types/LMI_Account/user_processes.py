#!/usr/bin/env python

"""
User processes
"""


import sys
import psutil

import lib_uris
import lib_util
import lib_common
from lib_properties import pc

from sources_types import CIM_Process


Usable = lib_util.UsableLinux


def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    user_name_with_host = cgiEnv.GetId()

    # Usernames have the syntax user@host
    # Example: UK936025@LONW00052257.euro.net.intra
    user_split = user_name_with_host.split('@')
    user_name = user_split[0]

    # TODO: Should factorize this code.
    if len(user_split) > 1:
        user_host = user_split[1]
        if user_host != lib_util.currentHostname:
            # TODO: Should interrogate other host with "finger" protocol.
            lib_common.ErrorMessageHtml("Cannot get user properties on different host:" + user_host)

    grph = cgiEnv.GetGraph()

    # It will be possible to transform this into a Json tree by
    # selecting only the RDF predicate property_ppid.
    # This will be done in a gui cgi script which takes as input
    # parameter a CGI script, visible by SLP, stored in a bookmark page
    # or anything else.

    # See http://stackoverflow.com/questions/17967686/retrieving-specific-rdf-graph-triples-based-on-predicate-nodes
    # on how to select triples on a given predicate only.

    # But in the general case, we cannot know if the RDF graph will be a tree,
    # something similar to a CSV file (That is, flat) or a general graph.

    # So we might have to process the resulting graph on the fly, to see
    # which visualising methods are applicable.

    # Also, in the case of a tree, we must find ourselves what is its root.

    for proc in psutil.process_iter():
        proc_username = CIM_Process.PsutilProcToUser(proc)

        # proc_username=EURO\\UK936025 user_name=UK936025
        # proc_username=NT AUTHORITY\\NETWORK SERVICE
        # proc_username=NT AUTHORITY\\SYSTEM
        # proc_username=EURO\\UK936025
        # proc_username=NT AUTHORITY\\SYSTEM
        if proc_username != user_name:
            continue

        pid = proc.pid
        parent_pid = proc.ppid()

        # Built the same way in other RDF documents.
        node_process = lib_uris.gUriGen.PidUri(pid)
        parent_node_process = lib_uris.gUriGen.PidUri(parent_pid)

        # We avoid duplicating the edges. Why would the RFD merge do?
        grph.add((node_process, pc.property_ppid, parent_node_process))
        grph.add((node_process, pc.property_pid, lib_util.NodeLiteral(pid)))
        # grph.add((node_process, pc.property_information, lib_util.NodeLiteral(proc_username)))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
