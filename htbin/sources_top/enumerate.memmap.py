#!/usr/bin/python

"""
Shared memory segments.
"""

import os
import re
import sys
import psutil
import rdflib

import lib_common
from lib_properties import pc

import lib_entities.lib_entity_CIM_Process as lib_entity_CIM_Process

cgiEnv = lib_common.CgiEnv("Memory maps")

grph = rdflib.Graph()

################################################################################

# TODO: For clarity, this eliminates many memory maps.

uselessLinuxMaps = [ 
	'/usr/bin/kdeinit', 
	'/bin/bash', 
	'/usr/lib/gconv/gconv-modules.cache', 
	'[stack]', 
	'[vdso]', 
	'[heap]', 
	'[anon]' ]

def FilterPathLinux(path):

	# We could also check if this is really a shared library.
	# file /lib/libm-2.7.so: ELF 32-bit LSB shared object etc...
	if path.endswith(".so"):
		return False

	# Not sure about "M" and "I". Also: Should precompile regexes.
	# And if the shared file is read-only, not very interesting, probably (But it depends).
	if re.match( r'.*/lib/.*\.so\..*', path, re.M|re.I):
		return False

	if path.startswith('/usr/share/locale/'):
		return False

	if path.startswith('/usr/share/fonts/'):
		return False

	if path.startswith('/etc/locale/'):
		return False

	if path.startswith('/var/cache/fontconfig/'):
		return False

	# Specific to KDE.
	if re.match( r'/var/tmp/kdecache-.*/ksycoca', path, re.M|re.I):
		return False

	if re.match( r'/home/.*/.local/share/mime/mime.cache', path, re.M|re.I):
		return False

	if path.startswith('/usr/bin/perl'):
		return False

	if path in uselessLinuxMaps:
		return False

	return True

def GoodMap(path):

	# TODO: Should resolve symbolic links, first.
	if 'linux' in sys.platform:
		if not FilterPathLinux(path):
			return ""

	# DLL are not displayed, because there would be too many of them,
	# and they are read-only, therefore less interesting.
	# OLB: data types and constants referenced by MS Office components.
	# NLS: language translation information to convert between different character sets.
	# TODO: This list in a drop-down menu.
	if 'win' in sys.platform:
		fileExtension = os.path.splitext(path)[1]
		if fileExtension.upper() in [ ".DLL", ".EXE", ".PYD", ".TTF", ".TTC", ".NLS", ".OLB" ]:
			return ""

	# TODO: THIS DOES NOT WORK.
	#mtch_deleted = re.match( path, "^(.*) \(deleted\)$" )
	# mtch_deleted = re.match( path, "(.*)", re.M|re.I )
	#if mtch_deleted:
	#	path = "mtch_deleted.group(1)"
	#	# path = mtch_deleted.group(1)
	# path = "mtch_deleted.group(1)"
	# For Linux only.
	if path.endswith( "(deleted)" ):
		path = path[:-9]


	# BEWARE: THIS MIGHT BE A PROBLEM BECAUSE WE CANNOT FIND 
	# A MEMORY MAP FROM ITS NAME BECAUSE IT HAS BEEN DELETED.


	return path

################################################################################

# Taken from psutil

# http://code.google.com/p/psutil/issues/detail?id=444

# WILL BE ENHANCED LATER: IT WILL CONTAIN THE INODE.


################################################################################

# Not really useful.
grph.add( ( lib_common.nodeMachine, pc.property_hostname, rdflib.Literal( lib_common.hostName ) ) )

def FunctionProcess(mapToProc,proc):
	# The process might have left in the meantime.
	pid = proc.pid

	if lib_common.UselessProc(proc):
		return

	sys.stderr.write("Pid=%d\n" % pid )

	# BEWARE: THIS HANGS ON WINDOWS 7 FOR SOME PROCESSES !!!
	# MAYBE RELATED TO get_open_files() ALSO HANGING ?
	try:
		all_maps = proc.get_memory_maps()
	except:
		sys.stderr.write("Caught exception in get_memory_maps Pid=%d\n" % pid )
		return

	# This takes into account only maps accessed by several processes.
	# TODO: What about files on a shared drive?
	# To make things simple, for the moment mapped memory is processed like files.

	sys.stderr.write("NbMaps=%d\n" % len(all_maps) )

	for map in all_maps:
		sys.stderr.write("MapPath=%s\n" % map.path)
		cleanPath = GoodMap( map.path )
		if cleanPath == "":
			continue

		sys.stderr.write( "Adding cleanPath=%s\n" % cleanPath )
		try:
			theList = mapToProc[ cleanPath ]
			theList.append( pid )
		except KeyError:
			mapToProc[ cleanPath ] = [ pid ]

	sys.stderr.write( "Leaving maps enumeration\n" )
			
mapToProc = {}

for proc in psutil.process_iter():

	# TODO: Instead, should test psutil version !!!
	try:
		FunctionProcess(mapToProc,proc)
	except lib_entity_CIM_Process.AccessDenied:
		pass
	except Exception:
		lib_common.ErrorMessageHtml("Unexpected error:" + str( sys.exc_info()[0] ) )
sys.stderr.write( "Leaving processes enumeration\n" )

addedProcs = {}

# Now display only memory maps with more than one process linked to it.
for mapPath, procLst in list( mapToProc.items() ):
	if len(procLst) <= 0 :
		continue

	uriMemMap = lib_common.gUriGen.MemMapUri( mapPath )

	for pid in procLst:
		try:
			nodeProcess = addedProcs[pid]
		except KeyError:
			nodeProcess = lib_common.gUriGen.PidUri(pid)
			addedProcs[pid] = nodeProcess

		grph.add( ( nodeProcess, pc.property_memmap, uriMemMap ) )
sys.stderr.write( "Leaving second maps enumeration\n" )

for pid, nodeProcess in list( addedProcs.items() ):
	grph.add( ( nodeProcess, pc.property_pid, rdflib.Literal(pid) ) )


# TODO: Petit bug: Ca duplique les memmap. Forcement, l'affichage en tables
# suppose que c'est un arbre. Mais c'est plus rapide et plus clair.
# cgiEnv.OutCgiRdf(grph,"",[pc.property_memmap])
cgiEnv.OutCgiRdf(grph)

