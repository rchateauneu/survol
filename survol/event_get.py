#!/usr/bin/env python

"""
Get an event about a CIM object
"""

import sys
import lib_common
import lib_kbase

# See event_put.py for more explanations.
# This script is called with the CGI arguments of a CIM class and
# the arguments to define an object, just like entity.py.
# It then fetches data from the temp directory of events.
# The type of these data is exactly what can be returned by any scripts.
def Main():
	lib_common.set_events_credentials()

	# This can process remote hosts because it does not call any script, just shows them.
	cgiEnv = lib_common.CgiEnv()
	entity_id = cgiEnv.m_entity_id

	name_space, entity_type = cgiEnv.get_namespace_type()

	grph = cgiEnv.GetGraph()

	if entity_type:
		lib_common.ErrorMessageHtml(__file__ + " objects events retrieval not supported yet.")

	entity_node = lib_common.gUriGen.UriMake(entity_type, *entity_id)

	num_triples = lib_kbase.retrieve_events_to_graph(grph, entity_node)
	sys.stderr.write("%s num_triples=%d\n" % (__file__, num_triples))

	cgiEnv.OutCgiRdf()


if __name__ == '__main__':
	Main()
