#!/usr/bin/python

"""
DBus connection objects
"""

import os
import sys
import rdflib
import dbus
import lib_common
import lib_util
import lib_dbus
from xml.etree import ElementTree
from lib_properties import pc

Usable = lib_util.UsableLinux

# http://unix.stackexchange.com/questions/203410/how-to-list-all-object-paths-under-a-dbus-service
def RecursiveObjWalk(grph,object_path, rootNode):
	sys.stderr.write("RecursiveObjWalk %s\n" % object_path)
	objNode = lib_util.EntityUri( "dbus/object", Main.busAddr, Main.connectName, object_path )
	grph.add( (rootNode, Main.localPropDbusPath, objNode ) )

	obj = Main.theBus.get_object(Main.connectName, object_path)
	iface = dbus.Interface(obj, 'org.freedesktop.DBus.Introspectable')
	xml_string = iface.Introspect()

	if object_path == '/':
		object_path = ''
	for child in ElementTree.fromstring(xml_string):
		if child.tag == 'node':
			new_path = '/'.join((object_path, child.attrib['name']))
			RecursiveObjWalk( grph, new_path, objNode)

def Main():
	cgiEnv = lib_common.CgiEnv()

	entity_type = "dbus/connection"
	# entity_id = cgiEnv.m_entity_id
	# entity_ids_arr = lib_util.EntityIdToArray( entity_type, entity_id )
	# entity_ids_dict = lib_util.SplitMoniker(entity_id)

	# busAddr = entity_ids_arr[0]
	# connectName = entity_ids_arr[1]
	Main.busAddr = cgiEnv.m_entity_id_dict["Bus"]
	Main.connectName = cgiEnv.m_entity_id_dict["Connect"]

	try:
		Main.theBus = lib_dbus.MakeBusFromAddress( Main.busAddr )
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("busAddr=%s Caught:%s" % ( Main.busAddr, str(exc) ) )

	connectNode = lib_util.EntityUri( entity_type, Main.busAddr, Main.connectName )

	grph = cgiEnv.GetGraph()

	Main.localPropDbusPath = rdflib.Literal("dbus-path")

	try:
		RecursiveObjWalk( grph, "/", connectNode )
	except dbus.exceptions.DBusException as exc:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Caught DBusException busAddr=%s %s" % ( Main.busAddr, str(exc) ) )
	except dbus.proxies as exc:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Caught proxies busAddr=%s %s" % (Main. busAddr, str(exc) ) )


	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
