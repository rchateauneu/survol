#!/usr/bin/python

"""
Oracle view dependencies
"""

import re
import sys
import lib_common
from lib_properties import pc
import lib_oracle
import rdflib
from sources_types.oracle import schema as oracle_schema
from sources_types.oracle import view as oracle_view

def Main():
	cgiEnv = lib_oracle.OracleEnv()

	oraView = cgiEnv.m_entity_id_dict["View"]
	oraSchema = cgiEnv.m_entity_id_dict["Schema"]
	oraDatabase = cgiEnv.m_entity_id_dict["Db"]

	grph = cgiEnv.GetGraph()

	node_oraView = oracle_view.MakeUri( oraDatabase, oraSchema, oraView )

	node_oraSchema = oracle_schema.MakeUri( oraDatabase, oraSchema )
	grph.add( ( node_oraSchema, pc.property_oracle_view, node_oraView ) )

	# TYPE = "VIEW", "TABLE", "PACKAGE BODY"
	sql_query = "select owner,name,type from dba_dependencies where REFERENCED_TYPE = 'VIEW' AND REFERENCED_NAME = '" + oraView + "' and referenced_owner='" + oraSchema + "'"
	sys.stderr.write("sql_query=%s\n" % sql_query )
	result = lib_oracle.ExecuteQuery( cgiEnv.ConnectStr(), sql_query)

	for row in result:
		lib_oracle.AddDependency( grph, row, node_oraView, oraDatabase, True )

	sql_query_inv = "select referenced_owner,referenced_name,referenced_type from dba_dependencies where type='VIEW' and NAME = '" + oraView + "' and OWNER='" + oraSchema + "'"
	sys.stderr.write("sql_query_inv=%s\n" % sql_query_inv )
	result_inv = lib_oracle.ExecuteQuery( cgiEnv.ConnectStr(), sql_query_inv)

	for row in result_inv:
		lib_oracle.AddDependency( grph, row, node_oraView, oraDatabase, False )

	cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT")

if __name__ == '__main__':
	Main()

