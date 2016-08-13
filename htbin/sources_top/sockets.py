#!/usr/bin/python

"""
System-wide sockets
"""

import sys
import psutil
import rdflib
import lib_common
from sources_types import CIM_Process

from lib_properties import pc

def Main():
	paramkeyShowUnconnected = "Show unconnected sockets"

	# TODO: At the moment, only uses false default values for boolean parameters,
	# TODO: because CGI and the CGI lib do not send empty strings.
	cgiEnv = lib_common.CgiEnv(
		parameters = { paramkeyShowUnconnected : False }
	)

	flagShowUnconnected = bool(cgiEnv.GetParameters( paramkeyShowUnconnected ))

	grph = rdflib.Graph()

	for proc in psutil.process_iter():
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
				grph.add( ( node_process, pc.property_pid, rdflib.Literal(pid) ) )

				# Les deux fonctionnent sous Linux mais verifier sous Windows.
				# Un peu plus lent en asynchrone si peu de sockets;
				# Ou il faudrait un parametre.
				# lib_common.PsutilAddSocketToGraph(node_process,all_connect,grph)
				# TODO: MAYBE CREATES ALL THE PROCESSES AND RUN THE THREADS ON THE COMPLETE LIST ???
				lib_common.PsutilAddSocketToGraphAsync(node_process,all_connect,grph,flagShowUnconnected)

		except psutil.AccessDenied:
			pass
		except psutil.NoSuchProcess:
			pass
		except:
			exc = sys.exc_info()[1]
			lib_common.ErrorMessageHtml("Caught:" + str(exc) )
			raise

	cgiEnv.OutCgiRdf(grph,"LAYOUT_SPLINE")


if __name__ == '__main__':
	Main()
