#!/usr/bin/env python

"""
Oracle procedures in schema
"""

import sys
from lib_properties import pc
import lib_oracle
import lib_common

from sources_types.oracle import schema as oracle_schema
from sources_types.oracle import procedure as oracle_procedure

def Main():
	cgiEnv = lib_oracle.OracleEnv()

	oraSchema = cgiEnv.m_entity_id_dict["Schema"]

	grph = cgiEnv.GetGraph()

	sql_query = "SELECT OBJECT_NAME,STATUS,CREATED FROM ALL_OBJECTS WHERE OBJECT_TYPE = 'PROCEDURE' AND OWNER = '" + oraSchema + "'"
	DEBUG("sql_query=%s", sql_query )

	node_oraschema = oracle_schema.MakeUri( cgiEnv.m_oraDatabase, oraSchema )

	result = lib_oracle.ExecuteQuery( cgiEnv.ConnectStr(), sql_query)

	for row in result:
		procedureName = str(row[0])
		nodeProcedure = oracle_procedure.MakeUri( cgiEnv.m_oraDatabase , oraSchema, procedureName )
		grph.add( ( node_oraschema, pc.property_oracle_procedure, nodeProcedure ) )

		lib_oracle.AddLiteralNotNone(grph,nodeProcedure,"Status",row[1])
		lib_oracle.AddLiteralNotNone(grph,nodeProcedure,"Creation",row[2])

	cgiEnv.OutCgiRdf("LAYOUT_RECT",[pc.property_oracle_procedure])

if __name__ == '__main__':
	Main()
