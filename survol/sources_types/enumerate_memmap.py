#!/usr/bin/python

"""
Shared memory segments.

System-wide shared memory segments, plus properties. DLLs and fonts are excluded.
"""

import os
import re
import sys
import lib_util
import lib_common
from lib_properties import pc
from sources_types import CIM_Process

def FilterPathLinux(path):
	# TODO: For clarity, this eliminates many memory maps.
	uselessLinuxMaps = [
		'/usr/bin/kdeinit',
		'/bin/bash',
		'/usr/lib/gconv/gconv-modules.cache',
		'[stack]',
		'[vdso]',
		'[heap]',
		'[anon]' ]

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
	if lib_util.isPlatformLinux:
		if not FilterPathLinux(path):
			return ""

	# DLL are not displayed, because there would be too many of them,
	# and they are read-only, therefore less interesting.
	# OLB: data types and constants referenced by MS Office components.
	# NLS: language translation information to convert between different character sets.
	# TODO: This list in a drop-down menu.
	if lib_util.isPlatformWindows:
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

def FunctionProcess(mapToProc,proc):
	# The process might have left in the meantime.
	pid = proc.pid

	if lib_common.UselessProc(proc):
		return

	try:
		all_maps = CIM_Process.PsutilProcMemmaps(proc)
	except:
		exc = sys.exc_info()[1]
		WARNING("get_memory_maps Pid=%d. Caught %s", pid,str(exc))
		return

	# This takes into account only maps accessed by several processes.
	# TODO: What about files on a shared drive?
	# To make things simple, for the moment mapped memory is processed like files.

	# sys.stderr.write("NbMaps=%d\n" % len(all_maps) )

	for map in all_maps:
		cleanPath = GoodMap( map.path )
		if cleanPath == "":
			continue

		# sys.stderr.write( "Adding cleanPath=%s\n" % cleanPath )
		try:
			theList = mapToProc[ cleanPath ]
			theList.append( pid )
		except KeyError:
			mapToProc[ cleanPath ] = [ pid ]

	# sys.stderr.write( "Leaving maps enumeration\n" )
			
def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	# Not really useful.
	grph.add( ( lib_common.nodeMachine, pc.property_hostname, lib_common.NodeLiteral( lib_util.currentHostname ) ) )

	mapToProc = {}

	for proc in CIM_Process.ProcessIter():

		# TODO: Instead, should test psutil version !!!
		try:
			FunctionProcess(mapToProc,proc)
		except CIM_Process.AccessDenied:
			pass
		except Exception:
			lib_common.ErrorMessageHtml("Unexpected error:" + str( sys.exc_info()[0] ) )
	# sys.stderr.write( "Leaving processes enumeration\n" )

	addedProcs = {}

	# Now display only memory maps with more than one process linked to it.
	for mapPath, procLst in lib_util.six_iteritems( mapToProc ):
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
	# sys.stderr.write( "Leaving second maps enumeration\n" )

	# TODO: They could also be displayed based on the hierarchy of their
	# associated file in the directory tree.

	for pid, nodeProcess in lib_util.six_iteritems( addedProcs ):
		grph.add( ( nodeProcess, pc.property_pid, lib_common.NodeLiteral(pid) ) )


	# TODO: Petit bug: Ca duplique les memmap. Forcement, l'affichage en tables
	# suppose que c'est un arbre. Mais c'est plus rapide et plus clair.
	# cgiEnv.OutCgiRdf("",[pc.property_memmap])
	cgiEnv.OutCgiRdf("LAYOUT_SPLINE")

if __name__ == '__main__':
	Main()
