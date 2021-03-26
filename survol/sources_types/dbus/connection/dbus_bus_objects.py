#!/usr/bin/env python

"""
DBus connection objects
"""

import os
import sys
import logging

import dbus
from xml.etree import ElementTree

import lib_common
import lib_util
import lib_dbus
from lib_properties import pc

Usable = lib_util.UsableLinux


# http://unix.stackexchange.com/questions/203410/how-to-list-all-object-paths-under-a-dbus-service
def _recursive_obj_walk(grph, object_path, root_node):
    logging.debug("RecursiveObjWalk %s", object_path)
    obj_node = lib_util.EntityUri("dbus/object", Main.busAddr, Main.connectName, object_path)
    grph.add((root_node, Main.localPropDbusPath, obj_node))

    obj = Main.theBus.get_object(Main.connectName, object_path)
    iface = dbus.Interface(obj, 'org.freedesktop.DBus.Introspectable')
    xml_string = iface.Introspect()

    if object_path == '/':
        object_path = ''
    for child in ElementTree.fromstring(xml_string):
        if child.tag == 'node':
            new_path = '/'.join((object_path, child.attrib['name']))
            _recursive_obj_walk(grph, new_path, obj_node)


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    entity_type = "dbus/connection"

    Main.busAddr = cgiEnv.m_entity_id_dict["Bus"]
    Main.connectName = cgiEnv.m_entity_id_dict["Connect"]

    try:
        Main.theBus = lib_dbus.MakeBusFromAddress(Main.busAddr)
    except Exception as exc:
        lib_common.ErrorMessageHtml("busAddr=%s Caught:%s" % (Main.busAddr, str(exc)))

    connectNode = lib_util.EntityUri(entity_type, Main.busAddr, Main.connectName)

    grph = cgiEnv.GetGraph()

    Main.localPropDbusPath = lib_util.NodeLiteral("dbus-path")

    try:
        _recursive_obj_walk(grph, "/", connectNode)
    except dbus.exceptions.DBusException as exc:
        lib_common.ErrorMessageHtml("Caught DBusException busAddr=%s %s" % (Main.busAddr, str(exc)))
    except dbus.proxies as exc:
        lib_common.ErrorMessageHtml("Caught proxies busAddr=%s %s" % (Main. busAddr, str(exc)))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
