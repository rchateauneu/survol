#!/usr/bin/python

"""
Oracle libraries in schema
"""

import sys
from lib_properties import pc
import lib_oracle
import rdflib

from sources_types.oracle import schema as oracle_schema
from sources_types.oracle import library as oracle_library

def Main():
	cgiEnv = lib_oracle.OracleEnv()

	oraSchema = cgiEnv.m_entity_id_dict["Schema"]

	grph = cgiEnv.GetGraph()

	sql_query = "SELECT OBJECT_NAME,STATUS,CREATED FROM DBA_OBJECTS WHERE OBJECT_TYPE = 'LIBRARY' AND OWNER = '" + oraSchema + "'"
	sys.stderr.write("sql_query=%s\n" % sql_query )

	node_oraschema = oracle_schema.MakeUri( cgiEnv.m_oraDatabase, oraSchema )

	result = lib_oracle.ExecuteQuery( cgiEnv.ConnectStr(), sql_query)

	for row in result:
		libraryName = str(row[0])
		nodeLibrary = oracle_library.MakeUri( cgiEnv.m_oraDatabase , oraSchema, libraryName )
		grph.add( ( node_oraschema, pc.property_oracle_library, nodeLibrary ) )

		lib_oracle.AddLiteralNotNone(grph,nodeLibrary,"Status",row[1])
		lib_oracle.AddLiteralNotNone(grph,nodeLibrary,"Creation",row[2])

	cgiEnv.OutCgiRdf("LAYOUT_RECT",[pc.property_oracle_library])

if __name__ == '__main__':
	Main()
