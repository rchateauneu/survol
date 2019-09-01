#!/usr/bin/env python

"""
Get an event about a CIM object
"""

import sys
import lib_common
import lib_util
import lib_event

# See event_put.py for more explanations.
# This script is called with the CGI arguments of a CIM class and
# the arguments to define an object, just like entity.py.
# It then fetches data from the temp directory of events.
# The type of these data is exactly what can be returned by any scripts.

def Main():

	# This can process remote hosts because it does not call any script, just shows them.
	cgiEnv = lib_common.CgiEnv()
	entity_id = cgiEnv.m_entity_id
	# entity_host = cgiEnv.GetHost()

	( nameSpace, entity_type, entity_namespace_type ) = cgiEnv.GetNamespaceType()

	grph = cgiEnv.GetGraph()

	# rootNode = lib_util.RootUri()

	entity_ids_arr = lib_util.EntityIdToArray( entity_type, entity_id )

	arrTriples = lib_event.data_retrieve(entity_type,entity_ids_arr)
	for tripl in arrTriples:
		grph.add(tripl)

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()


# Processes which can be started per entity, and which create events:
# CIM_Process  : * dockit.py
# CIM_DataFile : * A process using inotify ou dnotify,
#                  and writes incoming events.
#                * tcpdump (If this is a socket)
#                * tail -f
# addr         : * tcpdump

