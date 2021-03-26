#!/usr/bin/env python

"""
DBus Bus connections
"""

import os
import sys
import dbus
import logging
import lib_common
import lib_util
import lib_dbus
from lib_properties import pc

Usable = lib_util.UsableLinux


def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    bus_addr = cgiEnv.GetId()

    grph = cgiEnv.GetGraph()

    try:
        the_bus = lib_dbus.MakeBusFromAddress(bus_addr)
    except Exception as exc:
        lib_common.ErrorMessageHtml("bus_addr=%s Caught:%s" % (bus_addr, str(exc)))

    node_bus = lib_util.EntityUri("dbus/bus", bus_addr)

    # This property should maybe stored at the central file.
    local_prop_dbus_connect = lib_common.MakeProp("dbus connect")
    local_prop_dbus_well_known = lib_common.MakeProp("well known")

    Main.connectNameToNode = dict()

    def get_connect_node(bus_addr, connect_name):
        try:
            return Main.connectNameToNode[connect_name]
        except KeyError:
            connectNode = lib_util.EntityUri("dbus/connection", bus_addr, connect_name)
            Main.connectNameToNode[connect_name] = connectNode
            return connectNode

    for connect_name in the_bus.list_names():
        connect_node = get_connect_node(bus_addr, connect_name )

        try:
            ownr_nam = the_bus.get_name_owner(connect_name)
            logging.debug("connect_name=%s ownr=%s", connect_name, ownr_nam)
            if connect_name != ownr_nam:
                ownr_node = get_connect_node(bus_addr, ownr_nam)
                logging.debug("TO CONNECT %s", connect_name)

                # TODO: BUG, Display does not work if "Well Known" property.
                # grph.add((ownr_node, local_prop_dbus_well_known, connect_node))
                grph.add((ownr_node, local_prop_dbus_connect, connect_node))
        except ValueError:
            logging.debug("22 CONNECT %s", connect_name)
            grph.add((node_bus, local_prop_dbus_connect, connect_node))

    # TODO: The ordering is: 1.1,1.11,1.2, so we should use natsort.

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [local_prop_dbus_connect, local_prop_dbus_well_known])


if __name__ == '__main__':
    Main()
