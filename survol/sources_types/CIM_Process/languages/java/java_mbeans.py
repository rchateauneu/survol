#!/usr/bin/python

"""
Process MBeans
"""

import sys
import lib_common
from sources_types import CIM_Process
from sources_types import java as survol_java
from sources_types.java import mbean as survol_mbean
from lib_properties import pc

def Main():
	cgiEnv = lib_common.CgiEnv()
	pidInt = int( cgiEnv.GetId() )

	grph = cgiEnv.GetGraph()

	node_process = lib_common.gUriGen.PidUri(pidInt)
	# proc_obj = psutil.Process(pidInt)

	jmxData = survol_java.GetJavaDataFromJmx(pidInt)
	try:
		jmxDataMBeans = jmxData["allMBeans"]
	except KeyError:
		jmxDataMBeans = []

	propMBean = lib_common.MakeProp("MBean")

	for jmxMBean in jmxDataMBeans:
		clsNam = jmxMBean["className"]
		objNam = jmxMBean["objectName"]

		# "=sun.management.ManagementFactoryHelper$1[java.nio:type=BufferPool,name=mapped]"
		sys.stderr.write("jmxMBean=%s\n"%jmxMBean)

		# Not sure about the file name
		nodeClass = survol_mbean.MakeUri( pidInt, objNam)
		grph.add( ( nodeClass, lib_common.MakeProp("Class name"), lib_common.NodeLiteral(clsNam) ) )

		grph.add( ( node_process, propMBean, nodeClass ) )

	# sys.stderr.write("jmxData=%s\n"%jmxData)
	# cgiEnv.OutCgiRdf()
	cgiEnv.OutCgiRdf( "LAYOUT_RECT", [propMBean])

if __name__ == '__main__':
    Main()
