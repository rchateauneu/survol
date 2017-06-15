#!/usr/bin/python

"""
Oracle package dependencies
"""

import sys
from lib_properties import pc
import lib_oracle
import rdflib
from sources_types.oracle import package as oracle_package
from sources_types.oracle import schema as oracle_schema

def Main():
	cgiEnv = lib_oracle.OracleEnv()

	oraPackage = cgiEnv.m_entity_id_dict["Package"]
	oraSchema = cgiEnv.m_entity_id_dict["Schema"]

	grph = cgiEnv.GetGraph()

	node_oraPackage = oracle_package.MakeUri( cgiEnv.m_oraDatabase, oraSchema, oraPackage )

	node_oraSchema = oracle_schema.MakeUri( cgiEnv.m_oraDatabase, oraSchema )
	grph.add( ( node_oraSchema, pc.property_oracle_package, node_oraPackage ) )

	# TYPE = "VIEW", "TABLE", "PACKAGE BODY"
	sql_query = "select owner,name,type from dba_dependencies where REFERENCED_TYPE = 'PACKAGE' AND REFERENCED_NAME = '"\
				+ oraPackage + "' and referenced_owner='" + oraSchema + "'"
	sys.stderr.write("sql_query=%s\n" % sql_query )
	result = lib_oracle.ExecuteQuery( cgiEnv.ConnectStr(), sql_query)

	for row in result:
		lib_oracle.AddDependency( grph, row, node_oraPackage, cgiEnv.m_oraDatabase, True )

	sql_query_inv = "select referenced_owner,referenced_name,referenced_type from dba_dependencies where type='PACKAGE' and NAME = '"\
					+ oraPackage + "' and OWNER='" + oraSchema + "'"
	sys.stderr.write("sql_query_inv=%s\n" % sql_query_inv )
	result_inv = lib_oracle.ExecuteQuery( cgiEnv.ConnectStr(), sql_query_inv)

	for row in result_inv:
		lib_oracle.AddDependency( grph, row, node_oraPackage, cgiEnv.m_oraDatabase, False )

	cgiEnv.OutCgiRdf(grph,"LAYOUT_SPLINE")

if __name__ == '__main__':
	Main()
