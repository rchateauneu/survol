#!/usr/bin/env python

"""
Oracle package body dependencies
"""

import sys
from lib_properties import pc
import lib_oracle
import lib_common
from sources_types.oracle import package_body as oracle_package_body
from sources_types.oracle import schema as oracle_schema

def Main():
	cgiEnv = lib_oracle.OracleEnv()

	oraPackageBody = cgiEnv.m_entity_id_dict["PackageBody"]
	oraSchema = cgiEnv.m_entity_id_dict["Schema"]

	grph = cgiEnv.GetGraph()

	node_oraPackageBody = oracle_package_body.MakeUri( cgiEnv.m_oraDatabase, oraSchema, oraPackageBody )

	node_oraSchema = oracle_schema.MakeUri( cgiEnv.m_oraDatabase, oraSchema )
	grph.add( ( node_oraSchema, pc.property_oracle_package_body, node_oraPackageBody ) )

	# TYPE = "VIEW", "TABLE", "PACKAGE BODY"
	sql_query = "select owner,name,type from all_dependencies where REFERENCED_TYPE = 'PACKAGE BODY' AND REFERENCED_NAME = '"\
				+ oraPackageBody + "' and referenced_owner='" + oraSchema + "'"
	DEBUG("sql_query=%s", sql_query )
	result = lib_oracle.ExecuteQuery( cgiEnv.ConnectStr(), sql_query)

	for row in result:
		lib_oracle.AddDependency( grph, row, node_oraPackageBody, cgiEnv.m_oraDatabase, True )

	sql_query_inv = "select referenced_owner,referenced_name,referenced_type from all_dependencies where type='PACKAGE BODY' and NAME = '"\
					+ oraPackageBody + "' and OWNER='" + oraSchema + "'"
	DEBUG("sql_query_inv=%s", sql_query_inv )
	result_inv = lib_oracle.ExecuteQuery( cgiEnv.ConnectStr(), sql_query_inv)

	for row in result_inv:
		lib_oracle.AddDependency( grph, row, node_oraPackageBody, cgiEnv.m_oraDatabase, False )

	cgiEnv.OutCgiRdf("LAYOUT_SPLINE")

if __name__ == '__main__':
	Main()
