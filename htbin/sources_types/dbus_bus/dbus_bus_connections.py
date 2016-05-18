#!/usr/bin/python

import os
import sys
import rdflib
import dbus
import lib_common
import lib_util
import lib_dbus
from lib_properties import pc

Usable = lib_util.UsableLinux

def Main():
	cgiEnv = lib_common.CgiEnv("Bus connections")
	busAddr = cgiEnv.GetId()

	grph = rdflib.Graph()

	try:
		theBus = lib_dbus.MakeBusFromAddress( busAddr )
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("busAddr=%s Caught:%s" % ( busAddr, str(exc) ) )

	nodeBus = lib_util.EntityUri( "dbus_bus", busAddr )

	# This property should maybe stored at the central file.
	localPropDbusConnect = rdflib.Literal("dbus connect")
	localPropDbusWellKnown = rdflib.Literal("well known")

	Main.connectNameToNode = dict()

	def GetConnectNode(busAddr,connectName):
		try:
			return Main.connectNameToNode[ connectName ]
		except KeyError:
			connectNode = lib_util.EntityUri( "dbus_connection", busAddr, connectName )
			Main.connectNameToNode[ connectName ] = connectNode
			return connectNode

	for connectName in theBus.list_names():
		connectNode = GetConnectNode( busAddr, connectName )

		try:
			ownrNam = theBus.get_name_owner(connectName)
			# sys.stderr.write("connectName=%s ownr=%s\n" % (connectName,ownrNam))
			if connectName != ownrNam:
				ownrNode = GetConnectNode( busAddr, ownrNam )
				grph.add( (ownrNode, localPropDbusWellKnown, connectNode ) )
		except ValueError:
			grph.add( (nodeBus, localPropDbusConnect, connectNode ) )


	# TODO: The ordering is: 1.1,1.11,1.2, so we should have a special sort function.

	cgiEnv.OutCgiRdf(grph, "LAYOUT_RECT", [ localPropDbusConnect, localPropDbusWellKnown ])

if __name__ == '__main__':
	Main()
