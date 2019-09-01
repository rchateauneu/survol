#!/usr/bin/env python

"""
System-wide sockets
"""

import sys
import lib_common
from sources_types import CIM_Process
from sources_types import addr as survol_addr

from lib_properties import pc

def Main():
	paramkeyShowUnconnected = "Show unconnected sockets"

	# TODO: At the moment, only uses false default values for boolean parameters,
	# TODO: because CGI and the CGI lib do not send empty strings.
	cgiEnv = lib_common.CgiEnv(
		parameters = { paramkeyShowUnconnected : False }
	)

	flagShowUnconnected = bool(cgiEnv.GetParameters( paramkeyShowUnconnected ))

	grph = cgiEnv.GetGraph()

	for proc in CIM_Process.ProcessIter():
		try:
			if lib_common.UselessProc(proc):
				continue

			pid = proc.pid

			# TCP sockets only.
			all_connect = CIM_Process.PsutilProcConnections(proc)
			if all_connect:
				node_process = lib_common.gUriGen.PidUri(pid)

				# Trop lourd, ca ne sert a rien, dans la mesure ou les processes
				# ont le meme URI, donc ils DOIVENT etre fusionnes (A verifier).
				# A la limite, ca pourrait etre un attribut.
				# grph.add( ( node_process, pc.property_pid, Literal(pid) ) )

				# Not sure this is the best plmace to add this edge.
				grph.add( ( node_process, pc.property_host, lib_common.nodeMachine ) )
				grph.add( ( node_process, pc.property_pid, lib_common.NodeLiteral(pid) ) )

				# Les deux fonctionnent sous Linux mais verifier sous Windows.
				# Un peu plus lent en asynchrone si peu de sockets;
				# Ou il faudrait un parametre.
				# lib_common.PsutilAddSocketToGraph(node_process,all_connect,grph)
				# lib_common.PsutilAddSocketToGraphAsync(node_process,all_connect,grph,flagShowUnconnected)

				# TODO: MAYBE CREATES ALL THE PROCESSES AND RUN THE THREADS ON THE COMPLETE LIST ???
				survol_addr.PsutilAddSocketToGraphAsync(node_process,all_connect,grph,flagShowUnconnected)

		#except psutil.AccessDenied:
		#	pass
		#except psutil.NoSuchProcess:
		#	pass
		except Exception as exc:
			# This is for psutil.AccessDenied and psutil.NoSuchProcess but we do not want to import the module
			exc_str = str(exc)
			if (exc_str.find("AccessDenied") < 0) and (exc_str.find("NoSuchProcess") < 0):
				lib_common.ErrorMessageHtml("Caught:" + exc_str )
				raise

	cgiEnv.OutCgiRdf("LAYOUT_SPLINE")


if __name__ == '__main__':
	Main()
