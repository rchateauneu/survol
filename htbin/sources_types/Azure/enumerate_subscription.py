#!/usr/bin/python

"""
Azure available subscriptions
"""

import sys
import socket
import rdflib
import psutil
import rdflib
import lib_util
import lib_common
import lib_credentials

from sources_types import Azure
from sources_types.Azure import subscription

Usable = lib_util.UsableWindows

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	rootNode = lib_common.nodeMachine
	subscriptions = lib_credentials.GetCredentialsNames( "Azure" )

	for subscriptionName in subscriptions:
		subscriptionNode = subscription.MakeUri( subscriptionName )

		grph.add( ( rootNode, lib_common.MakeProp("Azure"), subscriptionNode ) )

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()

