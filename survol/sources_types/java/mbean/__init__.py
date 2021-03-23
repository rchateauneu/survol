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
    return (["Handle", "Name"],)


def EntityName(entity_ids_arr):
    pid = entity_ids_arr[0]
    mbean_object_name = entity_ids_arr[1]
    mbean_object_name = mbean_object_name.replace("*", ",").replace("-", "=")
    return "%s:%s" % (pid, mbean_object_name)

# PROBLEM: The MBean name has this structure: "java.nio:type=BufferPool,name=mapped"
# Therefore we must encode the "=" and "," signs.

def MakeUri(pid, mbean_object_name):
    mbean_object_name = mbean_object_name.replace("=", "-").replace(",", "*")
    return lib_common.gUriGen.UriMakeFromDict("java/mbean", {"Handle": pid, "Name": mbean_object_name})


#def AddInfo(grph,node,entity_ids_arr):
#    dsnNam = entity_ids_arr[0]
#    tabNam = entity_ids_arr[0]
#    nodeTable = odbc_table.MakeUri(dsnNam,tabNam)
#    grph.add( ( nodeTable, lib_common.MakeProp("ODBC table"), node ) )
