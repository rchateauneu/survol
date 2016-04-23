#!/usr/bin/python

import re
import sys
import lib_common
from lib_properties import pc
import lib_oracle
import rdflib

def Main():
	cgiEnv = lib_oracle.OracleEnv( "Oracle views" )

	# BEWARE: There is an implicit dependency on the structure of Oracle schema URI.
	# ( oraSchema , oraDatabase ) = cgiEnv.GetId().split('@')
	oraSchema = cgiEnv.m_entity_id_dict["Schema"]
	# oraDatabase = cgiEnv.m_entity_id_dict["Db"]

	grph = rdflib.Graph()

	sql_query = "SELECT OBJECT_NAME,STATUS,CREATED FROM DBA_OBJECTS WHERE OBJECT_TYPE = 'VIEW' AND OWNER = '" + oraSchema + "'"
	sys.stderr.write("sql_query=%s\n" % sql_query )

	node_oraschema = lib_common.gUriGen.OracleSchemaUri( cgiEnv.m_oraDatabase, oraSchema )

	result = lib_oracle.ExecuteQuery( cgiEnv.ConnectStr(), sql_query)

	for row in result:
		viewName = str(row[0])
		nodeView = lib_common.gUriGen.OracleViewUri( cgiEnv.m_oraDatabase , oraSchema, viewName )
		grph.add( ( node_oraschema, pc.property_oracle_view, nodeView ) )

		lib_oracle.AddLiteralNotNone(grph,nodeView,"Status",row[1])
		lib_oracle.AddLiteralNotNone(grph,nodeView,"Creation",row[2])

	cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT")

if __name__ == '__main__':
	Main()
