#!/usr/bin/python

"""
Java processes
"""

import sys
import lib_common
from sources_types import CIM_Process
from sources_types import java as survol_java
from lib_properties import pc

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	listVMs = survol_java.ListJavaProcesses()

	#listVMs = jvPckVM.list()
	sys.stderr.write("VirtualMachine.list=:\n")
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

			grph.add( ( node_process, lib_common.MakeProp(theKey), lib_common.NodeLiteral(strVal) ) )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()


# La generalisation est que des scripts nmap renvoient des informations relatives a tel ou tel module.
# On cree un script specifique qui utilise le script nmap et cree de ses resultats, des objets relatifs a
#
# https://nmap.org/nsedoc/scripts/rmi-dumpregistry.html
# Connects to a remote RMI registry and attempts to dump all of its objects.
# First it tries to determine the names of all objects bound in the registry,
# and then it tries to determine information about the objects,
# such as the the class names of the superclasses and interfaces.
# This may, depending on what the registry is used for, give valuable information about the service.
# E.g, if the app uses JMX (Java Management eXtensions), you should see an object called "jmxconnector" on it.
# It also gives information about where the objects are located, (marked with @<ip>:port in the output).
# Some apps give away the classpath, which this scripts catches in so-called "Custom data".
# Example Usage
# nmap --script rmi-dumpregistry -p 1098 <host>
# Script Output
# PORT     STATE SERVICE  REASON
# 1099/tcp open  java-rmi syn-ack
# | rmi-dumpregistry:
# |   cfassembler/default
# |     coldfusion.flex.rmi.DataServicesCFProxyServer_Stub
# |     @192.168.0.3:1271
# |     extends
# |       java.rmi.server.RemoteStub
# |       extends
# |         java.rmi.server.RemoteObject
# |     Custom data
# |       Classpath
# |         file:/C:/CFusionMX7/runtime/../lib/ant-launcher.jar
# |         file:/C:/CFusionMX7/runtime/../lib/ant.jar
# |         file:/C:/CFusionMX7/runtime/../lib/axis.jar
# |         file:/C:/CFusionMX7/runtime/../lib/backport-util-concurrent.jar
#
# https://www.optiv.com/blog/exploiting-jmx-rmi Exploiting JMX RMI
#
# http://docs.oracle.com/javase/8/docs/technotes/guides/management/agent.html
