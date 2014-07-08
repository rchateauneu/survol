#!/usr/bin/python

# List of open files for one process only.

import re
import sys
import cgi
import psutil
import rdflib

import lib_common
from lib_common import pc
from rdflib import URIRef, BNode, Literal

grph = rdflib.Graph()

arguments = cgi.FieldStorage()
top_pid = int( arguments["entity_id"].value )
# top_pid = 7584

proc_obj = psutil.Process(top_pid)
node_process = lib_common.PidUri(top_pid)

################################################################################

try:
	fillist = proc_obj.get_open_files()
except psutil._error.AccessDenied:
	lib_common.ErrorMessageHtml("Access denied")

for fil in fillist:
	# TODO: Resolve symbolic links. Do not do that if shared memory.
	# TODO: AVOIDS THESE TESTS FOR SHARED MEMORY !!!!
	if lib_common.MeaningLessFile(fil.path):
		continue

	fileNode = lib_common.FileUri( fil.path )
	grph.add( ( node_process, pc.property_open_file, fileNode ) )

lib_common.OutCgiRdf(grph)

