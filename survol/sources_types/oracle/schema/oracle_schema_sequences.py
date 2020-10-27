#!/usr/bin/env python

"""
Oracle sequences
"""

import sys
from lib_properties import pc
import lib_oracle
import lib_common

from sources_types.oracle import schema as oracle_schema
from sources_types.oracle import sequence as oracle_sequence


def Main():
	cgiEnv = lib_oracle.OracleEnv()

	ora_schema = cgiEnv.m_entity_id_dict["Schema"]

	grph = cgiEnv.GetGraph()

	sql_query = "SELECT OBJECT_NAME,STATUS,CREATED FROM ALL_OBJECTS WHERE OBJECT_TYPE = 'SEQUENCE' AND OWNER = '" + ora_schema + "'"
	DEBUG("sql_query=%s", sql_query)

	node_oraschema = oracle_schema.MakeUri(cgiEnv.m_oraDatabase, ora_schema)

	result = lib_oracle.ExecuteQuery(cgiEnv.ConnectStr(), sql_query)

	for row in result:
		sequence_name = str(row[0])
		node_sequence = oracle_sequence.MakeUri(cgiEnv.m_oraDatabase , ora_schema, sequence_name)
		grph.add((node_oraschema, pc.property_oracle_sequence, node_sequence))

		lib_oracle.AddLiteralNotNone(grph, node_sequence, "Status", row[1])
		lib_oracle.AddLiteralNotNone(grph, node_sequence, "Creation", row[2])

	# It cannot work if there are too many views.
	# cgiEnv.OutCgiRdf("LAYOUT_RECT")
	cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_oracle_sequence])


if __name__ == '__main__':
	Main()
