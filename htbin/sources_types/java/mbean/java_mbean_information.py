#!/usr/bin/python

"""
MBean information
"""

import sys
import psutil
import lib_common
from sources_types import CIM_Process
from sources_types import java as survol_java
from sources_types.java import mbean as survol_mbean
from lib_properties import pc

def Main():
	cgiEnv = lib_common.CgiEnv()
	pidInt = int( cgiEnv.GetId() )

	pidMBean = cgiEnv.m_entity_id_dict["Handle"]

	# TODO: Not convenient.
	# mbeanObjNam = cgiEnv.m_entity_id_dict["Name"].replace("*",",").replace("-","=")
	mbeanObjNam = cgiEnv.m_entity_id_dict["Name"]
	mbeanObjNam = mbeanObjNam.replace("*",",").replace("-","=")
	# mbeanObjNam = cgi.unescape(mbeanObjNam)

	grph = cgiEnv.GetGraph()

	node_process = lib_common.gUriGen.PidUri(pidInt)
	# proc_obj = psutil.Process(pidInt)


	jmxData = survol_java.GetJavaDataFromJmx(pidInt,mbeanObjNam)

	jmxDataMBeans = jmxData["allMBeans"]

	propMBean = lib_common.MakeProp("MBean")

	# There should be only one.
	for jmxMBean in jmxDataMBeans:
		clsNam = jmxMBean["className"]
		objNam = jmxMBean["objectName"]

		if objNam != mbeanObjNam:
			sys.stderr.write("THIS SHOULD NOT HAPPEN: %s != %s\n" % (objNam,mbeanObjNam))

		# "=sun.management.ManagementFactoryHelper$1[java.nio:type=BufferPool,name=mapped]"
		sys.stderr.write("jmxMBean=%s\n"%jmxMBean)

		# Not sure about the file name
		nodeClass = survol_mbean.MakeUri( pidInt, clsNam)
		grph.add( ( nodeClass, lib_common.MakeProp("Object name"), lib_common.NodeLiteral(objNam) ) )

		dictMBeanInfo = jmxMBean["info"]
		for keyInfo in dictMBeanInfo:
			valInfo = dictMBeanInfo[keyInfo]
			grph.add( ( nodeClass, lib_common.MakeProp(keyInfo), lib_common.NodeLiteral(valInfo) ) )

		grph.add( ( nodeClass, lib_common.MakeProp("Attributes"), lib_common.NodeLiteral(jmxMBean["attrs"]) ) )

		grph.add( ( node_process, propMBean, nodeClass ) )

	# sys.stderr.write("jmxData=%s\n"%jmxData)
	cgiEnv.OutCgiRdf()
	# cgiEnv.OutCgiRdf( "LAYOUT_RECT", [propMBean])

if __name__ == '__main__':
    Main()
