#!/usr/bin/env python

"""
Azure available subscriptions
"""

import sys

import lib_util
import lib_common
import lib_credentials
from sources_types.Azure import subscription as azure_subscription

Usable = lib_util.UsableWindows


def Main():
	cgiEnv = lib_common.ScriptEnvironment()

	grph = cgiEnv.GetGraph()

	root_node = lib_common.nodeMachine
	subscriptions = lib_credentials.get_credentials_names("Azure")

	# This creates a node for each available Azure subscription,
	# as they are given, with password, in the credentials file.
	# From this node, it is possible to access to anything related to it.
	for subscription_name in subscriptions:
		subscription_node = azure_subscription.MakeUri(subscription_name)

		grph.add((root_node, lib_common.MakeProp("Azure"), subscription_node))

	cgiEnv.OutCgiRdf()


if __name__ == '__main__':
	Main()

