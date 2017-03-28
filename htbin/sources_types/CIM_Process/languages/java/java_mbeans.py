#!/usr/bin/python

"""
MBeans
"""

import sys
import psutil
import rdflib
import lib_common
from sources_types import CIM_Process
from sources_types import java as survol_java
from lib_properties import pc

# Not implemented yet.

def Main():
	cgiEnv = lib_common.CgiEnv()
	pidInt = int( cgiEnv.GetId() )

	grph = rdflib.Graph()

	node_process = lib_common.gUriGen.PidUri(pidInt)
	# proc_obj = psutil.Process(pidInt)

	jmxData = survol_java.GetJavaDataFromJmx(pidInt)



	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
    Main()
