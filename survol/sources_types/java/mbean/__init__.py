"""
Java MBean
"""

import cgi
import lib_util
import lib_common
import sys

def Graphic_colorbg():
	return "#FF3399"

def EntityOntology():
	return ( ["Handle","Name"],)

def EntityName(entity_ids_arr,entity_host):
	pid = entity_ids_arr[0]
	mbeanObjectName = entity_ids_arr[1]
	mbeanObjectName = mbeanObjectName.replace("*",",").replace("-","=")
	# mbeanObjectName = cgi.escape(mbeanObjectName)
	# mbeanObjectName = cgi.unescape(mbeanObjectName)
	return "%s:%s" % (pid,mbeanObjectName)

# PROBLEM: The MBean name has this structure: "java.nio:type=BufferPool,name=mapped"
# Therefore we must encode the "=" and "," signs.

def MakeUri(pid,mbeanObjectName):
	# mbeanObjectName = cgi.escape(mbeanObjectName)
	mbeanObjectName = mbeanObjectName.replace("=","-").replace(",","*")
	# return lib_common.gUriGen.UriMakeFromDict("java/mbean", { "Handle" : pid, "Name" : mbeanObjectName.replace("=","-").replace(",","*") })
	return lib_common.gUriGen.UriMakeFromDict("java/mbean", { "Handle" : pid, "Name" : mbeanObjectName })

#def AddInfo(grph,node,entity_ids_arr):
#	dsnNam = entity_ids_arr[0]
#	tabNam = entity_ids_arr[0]
#	nodeTable = odbc_table.MakeUri(dsnNam,tabNam)
#	grph.add( ( nodeTable, lib_common.MakeProp("ODBC table"), node ) )
