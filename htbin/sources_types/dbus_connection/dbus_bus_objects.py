#!/usr/bin/python

import os
import sys
import rdflib
import dbus
import lib_common
import lib_util
import lib_dbus
from xml.etree import ElementTree
from lib_properties import pc

cgiEnv = lib_common.CgiEnv("Objects of a DBUS connection")

entity_type = "dbus_connection"
# entity_id = cgiEnv.m_entity_id
# entity_ids_arr = lib_util.EntityIdToArray( entity_type, entity_id )
# entity_ids_dict = lib_util.SplitMoniker(entity_id)

# busAddr = entity_ids_arr[0]
# connectName = entity_ids_arr[1]
busAddr = cgiEnv.m_entity_id_dict["Bus"]
connectName = cgiEnv.m_entity_id_dict["Connect"]

try:
	theBus = lib_dbus.MakeBusFromAddress( busAddr )
except Exception:
	exc = sys.exc_info()[1]
	lib_common.ErrorMessageHtml("busAddr=%s Caught:%s" % ( busAddr, str(exc) ) ) 	

connectNode = lib_util.EntityUri( entity_type, busAddr, connectName )

grph = rdflib.Graph()

localPropDbusPath = rdflib.Literal("dbus-path")

# http://unix.stackexchange.com/questions/203410/how-to-list-all-object-paths-under-a-dbus-service
def RecursiveObjWalk(object_path, rootNode):
	global grph
	sys.stderr.write("RecursiveObjWalk %s\n" % object_path)
	objNode = lib_util.EntityUri( "dbus_object", busAddr, connectName, object_path )
	grph.add( (rootNode, localPropDbusPath, objNode ) )

	obj = theBus.get_object(connectName, object_path)
	iface = dbus.Interface(obj, 'org.freedesktop.DBus.Introspectable')
	xml_string = iface.Introspect()

	if object_path == '/':
		object_path = ''
	for child in ElementTree.fromstring(xml_string):
		if child.tag == 'node':
			new_path = '/'.join((object_path, child.attrib['name']))
			RecursiveObjWalk( new_path, objNode)

try:
	RecursiveObjWalk( "/", connectNode )
except dbus.exceptions.DBusException as exc:
	exc = sys.exc_info()[1]
	lib_common.ErrorMessageHtml("Caught DBusException busAddr=%s %s" % ( busAddr, str(exc) ) ) 	
except dbus.proxies as exc:
	exc = sys.exc_info()[1]
	lib_common.ErrorMessageHtml("Caught proxies busAddr=%s %s" % ( busAddr, str(exc) ) ) 	


cgiEnv.OutCgiRdf(grph)
