#!/usr/bin/python

import lib_common
import lib_util
import os
import re
import sys
import psutil
import socket
import rdflib
from lib_properties import pc

import lib_webserv
import lib_tabular

def Usable(entity_type,entity_ids_arr):
	"""Runs on Linux only, in asynchronous mode"""
	return lib_util.UsableLinux(entity_type,entity_ids_arr) and lib_util.UsableAsynchronousSource(entity_type,entity_ids_arr)

################################################################################

# Device:            tps   Blk_read/s   Blk_wrtn/s   Blk_read   Blk_wrtn
# sda               3,00         0,00        48,00          0         48
# sdb               0,00         0,00         0,00          0          0

# Contains the last header read.
iostat_header = []

# This runs in the HTTP server and uses the data from the queue.
# This reads a record from the queue and builds a RDF relation with it.
def IOStatDeserialize( log_strm, grph, tpl):
	global iostat_header
	log_strm.write( "Deserializing tpl=%s\n" % ( tpl[0] ) )
	if tpl[0] == 'Device:':
		iostat_header = tpl
		return

	deviceNode = lib_common.gUriGen.DiskUri( tpl[0] )

	# Experimental: We display all properties whatever they are.
	# Comme RDF n'accepte pas les doublons, on sera obliges
	# si on stocke dans RDF, de mettre un time-stamp.
	# Mais il est plus sur de stocker directement dans du CSV,
	# car de toute facon ca n'a pas de sens en RDF sauf peut
	# etre la derniere valeur, histoire d'afficher quelque chose.

	try:
		iostat_pairs = {}
		for idx in range(1,len(tpl)):
			# No idea why doubles are written with a comma. Maybe the locale?
			qty = float( tpl[idx].replace(",",".") )
			iostat_pairs[ iostat_header[idx] ] = qty
			# grph.add( ( deviceNode, iostat_header[idx], rdflib.Literal( qty ) ) )

		lib_tabular.AddData( log_strm, grph, deviceNode, "disk", tpl[0], iostat_pairs )
	except IndexError:
		pass

################################################################################

# This runs tcpdump, parses output data from it, then written in the queue.
# The communication queue is made of pairs of sockets.
def IOStatEngine(sharedTupleQueue,entityId):
	tmpFil = lib_common.TmpFile("IOStat","log")
	filNam = tmpFil.Name
	fil = open(filNam,"w")

	# TODO: The delay could be a parameter.
	iostat_cmd = "iostat -d 1"
	fil.write( "iostat_cmd=%s\n" % ( iostat_cmd ) )
	fil.flush()
	cnt = 0
	for lin in os.popen(iostat_cmd):
		sys.stderr.write("cnt=%d:%s\n" % ( cnt, lin ) )
		if lin:
			# We transfer also the header.
			spl = re.split(' +',lin)
			sharedTupleQueue.put( tuple( spl ) )

			if cnt % 100 == 0:
				fil.write("cnt=%d:%s" % ( cnt, lin ) )
				fil.flush()
			cnt += 1

	fil.write( "Leaving after %d iterations\n" % ( cnt ) )
	fil.close()

	return "Iostat execution end"

################################################################################

if __name__ == '__main__':
	img = "http://sectools.org/logos/tcpdump-80x70.png"
	lib_webserv.DoTheJob(IOStatEngine,IOStatDeserialize,__file__,"Disks iostat",img)

