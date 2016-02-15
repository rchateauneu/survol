#!/usr/bin/python

import sys
import rdflib
import lib_common
import lib_entities.lib_entity_CIM_Process as lib_entity_CIM_Process

cgiEnv = lib_common.CgiEnv("Socket connections")
pid = int( cgiEnv.GetId() )

grph = rdflib.Graph()

proc_obj = lib_entity_CIM_Process.PsutilGetProcObj(pid)

#[pconn(fd=115, family=2, type=1, laddr=('10.0.0.1', 48776), raddr=('93.186.135.91', 80), status='ESTABLISHED'),
# pconn(fd=117, family=2, type=1, laddr=('10.0.0.1', 43761), raddr=('72.14.234.100', 80), status='CLOSING'),
# pconn(fd=119, family=2, type=1, laddr=('10.0.0.1', 60759), raddr=('72.14.234.104', 80), status='ESTABLISHED'),

node_process = lib_common.gUriGen.PidUri(pid)

try:
	# Old psutil versions.
	connects = proc_obj.get_connections('all')
# Does not work on recent versions of psutil.
# except psutil._error.AccessDenied:
except Exception:
	# Version 3.2.2 at least.
	try:
		connects = proc_obj.connections('all')
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Error:"+str(exc))

lib_common.PsutilAddSocketToGraph(node_process,connects,grph)

cgiEnv.OutCgiRdf(grph)

