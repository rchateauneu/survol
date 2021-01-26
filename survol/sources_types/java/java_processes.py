#!/usr/bin/env python

"""
Java processes
"""

import sys
import logging
import lib_util
import lib_common
from sources_types import CIM_Process
from sources_types import java as survol_java
from lib_properties import pc


def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	listVMs = survol_java.ListJavaProcesses()

	#listVMs = jvPckVM.list()
	logging.debug("VirtualMachine.list=:")
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
			logging.debug("%s = %s", theKey, strVal)

			grph.add( ( node_process, lib_common.MakeProp(theKey), lib_util.NodeLiteral(strVal) ) )

	cgiEnv.OutCgiRdf()


if __name__ == '__main__':
	Main()

