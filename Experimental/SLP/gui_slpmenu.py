#!/usr/bin/env python

# This displays in a JSON variable, the list of RDF URLs exposed by the SLP protocol.
# Because these queries are slow, there is a caching mechanism which can be controlled
# with a CGI parameter.

import os
import re
import cgi
import time
import glob
import math
import lib_common

# Writes to the file descriptor, the JSON variable.
def MakeCacheSlp(filDes):
	service_filter = "http.rdf"

	filDes.write( "Content-type: text/javascript\n\n" )

	# This variable name is used in the Javascript function FillSlpUrlsTable.
	# And also by some Javascript code in merge_rdf_inputs_graphviz_only.htm
	filDes.write( "var slps = [" )

	# Only the services we want. They are published by the slpd process of machines on the LAN.
	stream = os.popen("slptool findsrvs service:" + service_filter)
	# service:ftp.smallbox://192.168.100.1:21,65535
	lbl = 0
	for line in stream:
		# print "Li=" + line
		matchObj = re.match( r'service:([^:]*):/?/?([^,]*),?(.*)', line, re.M|re.I)
		if matchObj:
			filDes.write(	'[' \
				+ '"' + matchObj.group(1) + '",' \
				+ '"http://' + matchObj.group(2) + '",' \
				+ '"' + matchObj.group(3) + '",' \
				+ '"label_' + str(lbl)  + '"' \
				+ '],' )
			lbl = lbl + 1

	# print( '["a","b","c","d"]' )
	filDes.write( "];" )

# This generates a form containing the SLP urls in a variable.
# It manages a cache, because SLP queries are slow.

arguments = cgi.FieldStorage()

# Validity in seconds.
# HARDCODE_LIMIT
try:
	cache_validity = arguments["validity"].value
except KeyError:
	# Default, valid during one hour.
	cache_validity = 3600

nowSeconds = int( time.time() )

cache_directory = lib_common.TmpDir() + "/"

cache_prefix = "cache_slp."

glob_prefix = cache_directory + cache_prefix
possible_caches = glob.glob( glob_prefix + "*" )

best_cache = ''
best_stamp = 0

for fil in possible_caches:
	# print("fil=" + fil )
	# Reads the time-stamp at the end of the cache filename.
	timstamp_str = fil[ len(glob_prefix) : ]
	timstamp_int = int( timstamp_str )
	if timstamp_int > best_stamp:
		# Maybe removes the old cache.
		if best_stamp != 0 :
			os.remove(best_cache)
		best_stamp = timstamp_int
		best_cache = fil

if best_stamp < nowSeconds - cache_validity:
	# If a cache file was found, but is invalid, removes it.
	if best_stamp != 0 :
		os.remove(best_cache)
	best_cache = glob_prefix + str(nowSeconds)
	filDes = open(best_cache,'w')
	MakeCacheSlp(filDes)
	filDes.close()

# TODO: If the file is empty, maybe the validity could be shorter?

filDes = open(best_cache, 'r')
print( filDes.read() )

# The file descriptor might be stdout
# in case we cannot write to a temporary file.

# TODO
# We assume that some or all of these URLs are in fact bookmarks pages which contain
# the URLs that we want. The advantage is that when we create a dynamic CGI
# with a specific set of CGI parameters, it is not necessary to register it with
# SLP or any other exposing mechanism.
# 
# What must be done is:
#	- Expose bookmarks.
#	- Have a way to distinguish  normal URL from bookmarks.
#	- To make things cleaner: Maybe return categories of links.
#	This is necessary to show that an URL can be destroyed.
#
#
# Also: Create a cache so there is no need to make a SLP query at each call.
#
# Convention: the service "http.bookmark" indicates a bookmark of RDF cgis.
