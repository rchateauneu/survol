#!/usr/bin/python

import lib_common

import psutil
import socket
import rdflib
from lib_common import pc

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
	if lib_common.UselessProc(proc):
		continue

	procName = proc.name

	pid = proc.pid
	parent_pid = proc.ppid

	# Built the same way in other RDF documents.
	node_process = lib_common.PidUri(pid)
	parent_node_process = lib_common.PidUri(parent_pid)

	# We avoid duplicating the edges. Why would the RFD merge do?
	grph.add( ( node_process, pc.property_ppid, parent_node_process ) )

lib_common.OutCgiRdf(grph)

