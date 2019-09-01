#!/usr/bin/env python

"""
System Properties
"""

import sys
import lib_common
import lib_uris
from sources_types import CIM_Process
from sources_types import java as survol_java
from lib_properties import pc

def Main():
	cgiEnv = lib_common.CgiEnv()
	pidInt = int( cgiEnv.GetId() )

	grph = cgiEnv.GetGraph()

	node_process = lib_common.gUriGen.PidUri(pidInt)
	# proc_obj = psutil.Process(pidInt)

	jmxProps = survol_java.JavaJmxSystemProperties(pidInt)

	DEBUG("jmxProps=%s",str(jmxProps))

	try:
		pathSeparator = jmxProps["path.separator"]
	except KeyError:
		pathSeparator = None

	# The properties which should be displayed in matrices instead of individual nodes.
	propsMatrix = []

	propOrder = lib_common.MakeProp("Order")

	def ProcessPathes(keyJmxProp,valJmxProp,rdfProp):
		propsMatrix.append(rdfProp)
		pathSplit = valJmxProp.split(pathSeparator)
		idxPath = 1
		for dirNam in pathSplit:
			# TODO: It should be sorted.
			nodeDirectory = lib_common.gUriGen.DirectoryUri(dirNam)

			# TODO: There should be one matrix per box.
			# grph.add( ( nodeDirectory, lib_common.MakeProp("Property"), lib_common.NodeLiteral(keyJmxProp) ) )

			grph.add( ( nodeDirectory, propOrder, lib_common.NodeLiteral(idxPath) ) )
			grph.add( ( node_process, rdfProp, nodeDirectory ) )
			idxPath += 1

	for keyJmxProp in jmxProps:
		valJmxProp = jmxProps[keyJmxProp]
		rdfProp = lib_common.MakeProp(keyJmxProp)

		# These are list of directories separated by ";"
		if keyJmxProp in ["sun.boot.class.path","java.library.path","java.ext.dirs","java.endorsed.dirs","java.class.path"]:
			ProcessPathes(keyJmxProp,valJmxProp,rdfProp)
			continue

		# Some keys are not interesting.
		if keyJmxProp in ["path.separator","file.separator","line.separator",
						  "cpu.endian","sun.cpu.isalist","sun.cpu.endian","sun.arch.data.model",
						  "os.arch","os.name","os.version","sun.os.patch.level",
						  "user.country","user.language","user.script","user.timezone","user.variant",
						  "sun.awt.enableExtraMouseButtons","sun.desktop"]:
			continue

		# Redundancy, it prints quite often the same evalue.
		elif keyJmxProp in ["java.vendor","java.vm.vendor","java.vm.specification.vendor"] and valJmxProp == jmxProps["java.specification.vendor"]:
			continue

		# Redundancy, prints often the same value.
		if keyJmxProp in ["sun.jnu.encoding"] and valJmxProp == jmxProps["file.encoding"]:
			continue

		# These are individual directories.
		if keyJmxProp in ["user.dir","user.home","java.home","java.io.tmpdir","application.home","sun.boot.library.path"]:
			nodeDirectory = lib_common.gUriGen.DirectoryUri(valJmxProp)
			grph.add( ( node_process, rdfProp, nodeDirectory ) )
			continue

		# User name on this machine.
		if keyJmxProp in ["user.name"]:
			nodeUser = lib_common.gUriGen.UserUri( valJmxProp )
			grph.add( ( node_process, rdfProp, nodeUser ) )
			continue

		# HTTP URLs
		if keyJmxProp in ["java.vendor.url","java.vendor.url.bug"]:
			nodeJavaUrl = lib_common.NodeUrl( valJmxProp )
			grph.add( ( node_process, rdfProp, nodeJavaUrl ) )
			continue

		# Maybe a Java package ?????
		# "sun.java.command"

		grph.add( ( node_process, rdfProp, lib_common.NodeLiteral(valJmxProp) ) )

	cgiEnv.OutCgiRdf( "LAYOUT_RECT", propsMatrix)

if __name__ == '__main__':
	Main()
