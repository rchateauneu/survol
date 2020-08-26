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
# - Scripts which can naturally generate events might have a special function, like Daemon().
#   Their Main() function, will just return a snapshot.
# - For "normal" script, a default "Daemon"  which calls Main() at intervals.
#
# Real-Life Scenario: How would be this script called ?
# - When clicking on the URL, like in SVG document, nothing should change.
# - This script might give a quick snapshot, or maybe run a second, depending on the context.
#   This assumes mode=rdf,html etc... but not mode=event.

# Pass Daemon function to CgiEnv which will call Daemon in blocking or non-blocking mode.
# CgiEnv detects in a Daemon() function exists in the module of the caller.
# The caller knows that more data will come.
# The advantage of the non blocking mode is that no data is lost,
# and the creation of the returned objects is done in parallel.


# Old implementation: Instead of a multiprocessing.queue, it uses the general events storage.
# So, all events can be mixed together, and the content is persistent,
# and can be written to by all sorts of scripts, not only in Python.

# # def Daemon(blocking):
# # 	import multiprocessing
# #
# # 	if blocking:
# # 		# This can happen only
# #
# #
# # 		# If queue not there creates it.
# # 		try:
# # 			persistent_queue
# # 		except NameError:
# # 			# THIS MUST BE GLOBAL !!!
# # 			persistent_queue = multiprocessing.Queue()
# #
# # 		# If process not here starts it: The process reads incoming data
# # 		try:
# # 			tcpdump_process
# # 		except NameError:
# # 			# Il faut reellement creer un process pour ne pas rester en attente
# # 			# d'une entree-sortie. asyncio pas disponible en Python 2.
# #
# # 			class MyExec(threading.Thread):
# # 				def __init__(self):
# # 					pass
# #
# # 				def run(self):
# # 					output = SubProcess.start("tcpdump")
# # 					for lin in output:
# # 						persistent_queue.put_nowait(lin)
# # 					pass
# #
# # 			# THIS MUST BE GLOBAL !!!
# # 			tcpdump_process = MyExec()
# # 			tcpdump_process.start()
# #
# #
# # 		while True:
# # 			try:
# # 				yield persistent_queue.get_nowait()
# # 			except multiprocessing.Queue.Empty:
# # 				return
# # 	else:
# # 		# Starts the process, and transforms the output into triplets.
# # 		# This should not never block.
# # 		return []
#
#


# A quick note about scripts written in another language than Python.
#
# A possible architecture is to to create exexcutables, which are also Python module:
# That is, they export a function called "PyInit_something"
# for Python 3 and "initsomething" for Python2.
# Is it possible to use the same DLL for Python 2 and Python 3 ? This would simplify Survol installation.
# This file is used as a main program (A CGI script) and as a compiled Python extension, imported by Python.
# To behave like a normal Survol script, it must be able to generate RDF, DOT etc... using lib_common.
# The advantages of this solution is that:
# - It is transparent for the rest of Survol.
# - It uses the rets of Survol framework defined in lib_common to generate its output in various formats.
# The drawbacks are:
# - It must call Python, hence possibly slow.
# - It can only be written in C or C++, pratically.
#
# On the other hand, it is tempting to be able to use any stand-alone program as long as it can write data to stdout,
# so it would not need to call Python lib_common.
# When called as a script, it just needs to adapt its output to mode=rdf, json, html, svg.
# When Survol analyses available scripts, Survol must check if a script is executable, and wraps it into something.
#
# It should be able to call the generation of RDF or

# While we are at adding ideas:
# - Get firefox bookmarks from the web.
# - Create an installer in wxwidget for Apache, IIS etc.
# - At least an Apache setup.

def EventsGeneratorDaemon():
    raise Exception("Not implemented")

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
