#!/usr/bin/python

"""
Oracle functions in schema
"""

import sys
from lib_properties import pc
import lib_oracle
import lib_common

from sources_types.oracle import schema as oracle_schema
from sources_types.oracle import function as oracle_function

def Main():
	cgiEnv = lib_oracle.OracleEnv()

	oraSchema = cgiEnv.m_entity_id_dict["Schema"]

	grph = cgiEnv.GetGraph()

	sql_query = "SELECT OBJECT_NAME,STATUS,CREATED FROM ALL_OBJECTS WHERE OBJECT_TYPE = 'FUNCTION' AND OWNER = '" + oraSchema + "'"
	DEBUG("sql_query=%s", sql_query )

	node_oraschema = oracle_schema.MakeUri( cgiEnv.m_oraDatabase, oraSchema )

	result = lib_oracle.ExecuteQuery( cgiEnv.ConnectStr(), sql_query)

	for row in result:
		functionName = str(row[0])
		nodeFunction = oracle_function.MakeUri( cgiEnv.m_oraDatabase , oraSchema, functionName )
		grph.add( ( node_oraschema, pc.property_oracle_function, nodeFunction ) )

		lib_oracle.AddLiteralNotNone(grph,nodeFunction,"Status",row[1])
		lib_oracle.AddLiteralNotNone(grph,nodeFunction,"Creation",row[2])

	cgiEnv.OutCgiRdf("LAYOUT_RECT",[pc.property_oracle_function])

if __name__ == '__main__':
	Main()
