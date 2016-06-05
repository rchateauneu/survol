#!/usr/bin/python

"""
DBus buses
"""

import rdflib

import lib_common
import lib_util
from lib_properties import pc

Usable = lib_util.UsableLinux

# bus1 = dbus.bus.BusConnection("tcp:host=192.168.0.1,port=1234")
# Unix-domain socket are filesystem objects, and therefore they can be identified by a filename,
# so a valid address would be unix:path=/tmp/.hiddensocket.
# Both processes must pass the same address to their respective communications libraries
# to establish the D-Bus connection between them.
# An address can also provide additional data to the communications library
# in the form of comma-separated key=value pairs.
# This way, for example, it can provide authentication information
# to a specific type of connection that supports it.
# return dbus.bus.BusConnection(os.environ['DBUS_SYSTEM_BUS_ADDRESS'])
# return dbus.bus.BusConnection(os.environ['DBUS_SESSION_BUS_ADDRESS'])
# DBUS_SESSION_BUS_ADDRESS=unix:abstract=/tmp/dbus-u9kzz0bylJ,guid=8eb3fda03d60afbae2b1656656867e03
# cat /proc/self/environ | tr "\\0" "\n" | grep DBUS_SESSION_BUS_ADDRESS
# cat: /proc/9/environ: Permission denied
# DBUS_SESSION_BUS_ADDRESS=unix:abstract=/tmp/dbus-u9kzz0bylJ,guid=8eb3fda03d60afbae2b1656656867e03
# bus_obj=dbus.bus.BusConnection("tcp:host=localhost,port=12434")
# Pour le moment on fait comme ca mais on va rajouter les autres processes.

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = rdflib.Graph()

	listBuses = [ "system", "session" ]

	for busName in listBuses:
		uriBus = lib_util.EntityUri( "dbus/bus", busName )
		grph.add( ( lib_common.nodeMachine, lib_common.MakeProp("DBus"), uriBus ) )

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
