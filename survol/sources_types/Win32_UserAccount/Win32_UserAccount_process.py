#!/usr/bin/env python

"""
User processes and subprocesses
"""

import sys
import psutil
import lib_util
import lib_uris
import lib_common
from lib_properties import pc

from sources_types import CIM_Process

# This restriction only because the class Win32_UserAccount exists only in WMI.
Usable = lib_util.UsableWindows

# This script can work locally only.

def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    # userNameWithHost = cgiEnv.GetId()
    # Usernames have the syntax user@host
    # Example: UK936025@LONW00052257.euro.net.intra

    user_name = cgiEnv.m_entity_id_dict["Name"]

    try:
        # Exception if local machine.
        user_host = cgiEnv.m_entity_id_dict["Domain"]
    except KeyError:
        user_host = lib_util.currentHostname

    if user_host:
        if not lib_util.is_local_address( user_host ):
            # TODO: Should interrogate other host with "finger" protocol.
            # Cannot get user properties on different host:mymachine than mymachine.home
            lib_common.ErrorMessageHtml("Cannot get user properties on different host:%s than %s"
                                       % (user_host, lib_util.currentHostname))

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
            # On Windows, second chance with only the second part of the user.
            try:
                user_short = proc_username.split('\\')[1]
            except IndexError:
                user_short = proc_username
            if user_short != user_name:
                continue

        pid = proc.pid
        parent_pid = proc.ppid()

        # Built the same way in other RDF documents.
        node_process = lib_uris.gUriGen.PidUri(pid)
        parent_node_process = lib_uris.gUriGen.PidUri(parent_pid)

        # We avoid duplicating the edges. Why would the RFD merge do?
        grph.add((node_process, pc.property_ppid, parent_node_process))
        grph.add((node_process, pc.property_pid, lib_util.NodeLiteral(pid)))
        # grph.add( ( node_process, pc.property_information, lib_util.NodeLiteral(proc_username) ) )

    # We avoid duplicating the edges. Why would the RFD merge do?
    ############ grph.add( ( node_process, pc.property_ppid, parent_node_process ) )

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
