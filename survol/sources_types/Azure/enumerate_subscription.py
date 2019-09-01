#!/usr/bin/env python

"""
Azure available subscriptions
"""

import sys
import socket
import lib_util
import lib_common
import lib_credentials

from sources_types.Azure import subscription as azure_subscription

Usable = lib_util.UsableWindows

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	rootNode = lib_common.nodeMachine
	subscriptions = lib_credentials.GetCredentialsNames( "Azure" )

	# This creates a node for each available Azure subscription,
	# as they are given, with password, in the credentials file.
	# From this node, it is possible to access to anything related to it.
	for subscriptionName in subscriptions:
		subscriptionNode = azure_subscription.MakeUri( subscriptionName )

		grph.add( ( rootNode, lib_common.MakeProp("Azure"), subscriptionNode ) )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()

