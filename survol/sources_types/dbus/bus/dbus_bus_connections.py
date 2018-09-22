#!/usr/bin/python

"""
DBus Bus connections
"""

import os
import sys
import dbus
import lib_common
import lib_util
import lib_dbus
from lib_properties import pc

Usable = lib_util.UsableLinux

def Main():
	cgiEnv = lib_common.CgiEnv()
	busAddr = cgiEnv.GetId()

	grph = cgiEnv.GetGraph()

	try:
		theBus = lib_dbus.MakeBusFromAddress( busAddr )
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("busAddr=%s Caught:%s" % ( busAddr, str(exc) ) )

	nodeBus = lib_util.EntityUri( "dbus/bus", busAddr )

	# This property should maybe stored at the central file.
	localPropDbusConnect = lib_common.MakeProp("dbus connect")
	localPropDbusWellKnown = lib_common.MakeProp("well known")

	Main.connectNameToNode = dict()

	def GetConnectNode(busAddr,connectName):
		try:
			return Main.connectNameToNode[ connectName ]
		except KeyError:
			connectNode = lib_util.EntityUri( "dbus/connection", busAddr, connectName )
			Main.connectNameToNode[ connectName ] = connectNode
			return connectNode

	for connectName in theBus.list_names():
		connectNode = GetConnectNode( busAddr, connectName )

		try:
			ownrNam = theBus.get_name_owner(connectName)
			sys.stderr.write("connectName=%s ownr=%s\n" % (connectName,ownrNam))
			if connectName != ownrNam:
				ownrNode = GetConnectNode( busAddr, ownrNam )
				DEBUG("TO CONNECT %s", connectName)

				# TODO: BUG, Display does not work if "Well Known" property.
				# grph.add( (ownrNode, localPropDbusWellKnown, connectNode ) )
				grph.add( (ownrNode, localPropDbusConnect, connectNode ) )
		except ValueError:
			DEBUG("22 CONNECT %s", connectName)
			grph.add( (nodeBus, localPropDbusConnect, connectNode ) )


	# TODO: The ordering is: 1.1,1.11,1.2, so we should have a special sort function.

	cgiEnv.OutCgiRdf( "LAYOUT_RECT", [ localPropDbusConnect, localPropDbusWellKnown ])

if __name__ == '__main__':
	Main()
