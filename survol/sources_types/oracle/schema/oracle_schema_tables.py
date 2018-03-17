#!/usr/bin/python

"""
Oracle tables
"""

import sys
import lib_common
from lib_properties import pc
import lib_oracle

from sources_types.oracle import schema as oracle_schema
from sources_types.oracle import table as oracle_table

def Main():
	cgiEnv = lib_oracle.OracleEnv()

	oraSchema = cgiEnv.m_entity_id_dict["Schema"]

	grph = cgiEnv.GetGraph()

	sql_query = "SELECT OBJECT_NAME,STATUS,CREATED FROM ALL_OBJECTS WHERE OBJECT_TYPE = 'TABLE' AND OWNER = '" + oraSchema + "'"
	sys.stderr.write("sql_query=%s\n" % sql_query )

	node_oraschema = oracle_schema.MakeUri( cgiEnv.m_oraDatabase, oraSchema )

	result = lib_oracle.ExecuteQuery( cgiEnv.ConnectStr(), sql_query)

	for row in result:
		tableName = str(row[0])
		# sys.stderr.write("tableName=%s\n" % tableName )
		nodeTable = oracle_table.MakeUri( cgiEnv.m_oraDatabase , oraSchema, tableName )
		grph.add( ( node_oraschema, pc.property_oracle_table, nodeTable ) )

		lib_oracle.AddLiteralNotNone(grph,nodeTable,"Status",row[1])
		lib_oracle.AddLiteralNotNone(grph,nodeTable,"Creation",row[2])

	# It cannot work if there are too many tables.
	# cgiEnv.OutCgiRdf("LAYOUT_RECT")
	cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_oracle_table])

if __name__ == '__main__':
	Main()
