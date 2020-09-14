#!/usr/bin/env python

"""
Get an event about a CIM object
"""

import sys
import lib_common
import lib_util
import lib_event
import lib_kbase


# See event_put.py for more explanations.
# This script is called with the CGI arguments of a CIM class and
# the arguments to define an object, just like entity.py.
# It then fetches data from the temp directory of events.
# The type of these data is exactly what can be returned by any scripts.
def Main():
	lib_event.set_events_credentials()

	# This can process remote hosts because it does not call any script, just shows them.
	cgiEnv = lib_common.CgiEnv()
	entity_id = cgiEnv.m_entity_id

	name_space, entity_type = cgiEnv.get_namespace_type()

	grph = cgiEnv.GetGraph()

	if entity_type:
		lib_common.ErrorMessageHtml(__file__ + " objects events retrieval not supported yet.")

	lib_kbase.retrieve_all_events_to_graph_then_clear(grph)

	# This receives an object type stored as a string, and a string made of the concatenation
	# of key-value pairs, defining an object. It returns the array of property values,
	# in the proper order of the ontology of the type.

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

