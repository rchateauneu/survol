#!/usr/bin/python

"""Processes belonging to a user, and their subprocesses"""


import sys
import psutil
import rdflib
import lib_util
import lib_common
from lib_properties import pc

import lib_entities.lib_entity_CIM_Process as lib_entity_CIM_Process

cgiEnv = lib_common.CgiEnv("User processes")
userNameWithHost = cgiEnv.GetId()

if not lib_util.isPlatformWindows:
	lib_common.ErrorMessageHtml("Windows only")

# Usernames have the syntax user@host
# Example: UK936025@LONW00052257.euro.net.intra
userSplit = userNameWithHost.split('@')
userName = userSplit[0]

# TODO: Should factorize this code.
if len( userSplit ) > 1:
	userHost = userSplit[1]
	if userHost != lib_util.currentHostname:
		# TODO: Should interrogate other host with "finger" protocol.
		lib_common.ErrorMessageHtml("Cannot get user properties on different host:" + userHost)

grph = rdflib.Graph()

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

	procUsername = lib_entity_CIM_Process.PsutilProcToUser(proc)

	sys.stderr.write("procUsername=%s userName=%s\n" % ( procUsername, userName ) )
	# procUsername=EURO\\UK936025 userName=UK936025
	# procUsername=NT AUTHORITY\\NETWORK SERVICE
	# procUsername=NT AUTHORITY\\SYSTEM
	# procUsername=EURO\\UK936025
	# procUsername=NT AUTHORITY\\SYSTEM
	if procUsername != userName:
		# On Windows, second chance with only the second part of the user.
		try:
			userShort = procUsername.split('\\')[1]
		except IndexError:
			userShort = procUsername
		if userShort != userName:
			continue

	if lib_common.UselessProc(proc):
		continue

	procName = proc.name

	pid = proc.pid
	parent_pid = lib_entity_CIM_Process.PsutilProcToPPid(proc)

	# Built the same way in other RDF documents.
	node_process = lib_common.gUriGen.PidUri(pid)
	parent_node_process = lib_common.gUriGen.PidUri(parent_pid)

	# We avoid duplicating the edges. Why would the RFD merge do?
	grph.add( ( node_process, pc.property_ppid, parent_node_process ) )
	grph.add( ( node_process, pc.property_pid, rdflib.Literal(pid) ) )
	# grph.add( ( node_process, pc.property_information, rdflib.Literal(procUsername) ) )

# We avoid duplicating the edges. Why would the RFD merge do?
############ grph.add( ( node_process, pc.property_ppid, parent_node_process ) )

cgiEnv.OutCgiRdf(grph)

