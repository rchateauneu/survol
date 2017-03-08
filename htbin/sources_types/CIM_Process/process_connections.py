#!/usr/bin/python

"""
Process socket connections
"""

import sys
import rdflib
import lib_common
from sources_types import CIM_Process
from sources_types import addr as survol_addr

def Main():
	cgiEnv = lib_common.CgiEnv()
	pid = int( cgiEnv.GetId() )

	grph = rdflib.Graph()

	proc_obj = CIM_Process.PsutilGetProcObj(pid)

	#[pconn(fd=115, family=2, type=1, laddr=('10.0.0.1', 48776), raddr=('93.186.135.91', 80), status='ESTABLISHED'),
	# pconn(fd=117, family=2, type=1, laddr=('10.0.0.1', 43761), raddr=('72.14.234.100', 80), status='CLOSING'),
	# pconn(fd=119, family=2, type=1, laddr=('10.0.0.1', 60759), raddr=('72.14.234.104', 80), status='ESTABLISHED'),

	node_process = lib_common.gUriGen.PidUri(pid)

	try:
		connects = CIM_Process.PsutilProcConnections(proc_obj,'all')
	except Exception:
		# Version 3.2.2 at least.
		try:
			connects = proc_obj.connections('all')
		except Exception:
			exc = sys.exc_info()[1]
			lib_common.ErrorMessageHtml("Error:"+str(exc))

	survol_addr.PsutilAddSocketToGraph(node_process,connects,grph)

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()

