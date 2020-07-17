#!/usr/bin/env python

"""
Monitor system calls with dockit.
"""

import sys
import lib_util
import lib_common
import lib_wbem
from lib_properties import pc

# For the moment, it must not be usable.
# This script can be used two ways:
# - Just one snapshot, like any other script.
# - Or start a subprocess running this script, and it will feed events, just like any other normal event.
# This mechanism must be more or less transparent.
# Ideally, any script could be called with these two ways.
# But there are subtle details:
# Most scripts can only return a snapshot. However, it is always possibvle to call them in a loop,
# with a given delay, and they will send each time new triples as events.
# The destruction of events must be managed, so probably some historical context should be stored somewhere.
# There are several machanisms allowing a script to asynchronously return events. For example:
# - tcpdump and strace/truss/ltrace display information to stdout.
# - WMI and WBEM can return events (How ?)
# - dockit wraps strace/ltrace on Linux, and pydbg on Windows, and create events to Survol events mechanism.

# A process is associated to each script and object (key-value pairs).
# For example, store the pid in an atomic file, in a directory tree similar to how events are stored.
# There would be one directory per script, this directory would contain the pids of processes
# associated to objects. The naming of the files would use the same mechanism as events files.

# Use cases:
# (1) See addr_events_tcpdump.py which is similar, but for sockets.
# (2) The package notify/inotify notifies of the creation/update of files in a given directory.
#      Subtle detail because it notifies of files creation/updates in a directory, so it does not only
#      apply to a directory but to its recursive content.
# (3) A kind of "virtual script" would use the same mechanism based on WMI:
#     One script would work for all type of CIM objects.
# Detection of processes creations and deletion: Again, subtle detail in that it does not apply
# to a specific process but to all processes in general. Maybe store it at the top ?

# Implementation:
# - Reuse the existing framework.
# - Instead of calling Main(), do something like "ManageScript(Main)" ?
# When called with "mode=events", it should create a process running Main(),
# then return. If there is no way to create a process, then return a snapshot, as usual.
#
# The process might have different behaviour, depending on ... something:
# - Call Main() in a loop, with a delay.
# - Or enter the script in a "special" mode.
# - Scripts which can naturally generate events might have a special function, like EventLoop().
#   Their Main() function, will just return a snapshot.
# - For "normal" script, a default "EventLoop"  which calls Main() at intervals.
#
# Real-Life Scenario: How would be this script called ?
# - When clicking on the URL, like in SVG document, nothing should change.
# - This script might give a quick snapshot, or maybe run a second, depending on the context.
#   This assumes mode=rdf,html etc... but not mode=event.

def Usable(entity_type, entity_ids_arr):
    """Disabled yet"""
    # This could possibly return a special value.
    # Maybe False if the process is running, so so the process is started only once ?
    return False

def Main():
    cgiEnv = lib_common.CgiEnv()
    pid = int( cgiEnv.GetId() )

    grph = cgiEnv.GetGraph()

    cgiEnv.OutCgiRdf()

if __name__ == '__main__':
    Main()
