#!/usr/bin/python

"""
Java processes
"""

import sys
import psutil
import rdflib
import lib_common
from sources_types import CIM_Process
from sources_types import java as survol_java
from lib_properties import pc

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = rdflib.Graph()

	listVMs = survol_java.ListJavaProcesses()

	#listVMs = jvPckVM.list()
	sys.stdout.write("VirtualMachine.list=:\n")
	for thePid in listVMs:
		node_process = lib_common.gUriGen.PidUri(thePid)
		theProcObj = listVMs[thePid]
		for theKey in theProcObj:
			theVal = theProcObj[theKey]
			if theVal is None:
				strVal = ""
			else:
				try:
					strVal = str(theVal)
				except:
					strVal = "No value"
			sys.stderr.write("\t%s = %s\n"%(theKey,strVal))

			grph.add( ( node_process, lib_common.MakeProp(theKey), rdflib.Literal(strVal) ) )

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
