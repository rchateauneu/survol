#!/usr/bin/python

"""
Oracle package body dependencies
"""

import sys
import lib_common
from lib_properties import pc
import lib_oracle
import rdflib

def Main():
	cgiEnv = lib_oracle.OracleEnv()

	oraPackageBody = cgiEnv.m_entity_id_dict["Package"]
	oraSchema = cgiEnv.m_entity_id_dict["Schema"]

	grph = rdflib.Graph()

	node_oraPackageBody = lib_common.gUriGen.OraclePackageBodyUri( cgiEnv.m_oraDatabase, oraSchema, oraPackageBody )

	node_oraSchema = lib_common.gUriGen.OracleSchemaUri( cgiEnv.m_oraDatabase, oraSchema )
	grph.add( ( node_oraSchema, pc.property_oracle_package_body, node_oraPackageBody ) )

	# TYPE = "VIEW", "TABLE", "PACKAGE BODY"
	sql_query = "select owner,name,type from dba_dependencies where REFERENCED_TYPE = 'PACKAGE BODY' AND REFERENCED_NAME = '" + oraPackageBody + "' and referenced_owner='" + oraSchema + "'"
	sys.stderr.write("sql_query=%s\n" % sql_query )
	result = lib_oracle.ExecuteQuery( cgiEnv.ConnectStr(), sql_query)

	for row in result:
		lib_oracle.AddDependency( grph, row, node_oraPackageBody, cgiEnv.m_oraDatabase, True )

	sql_query_inv = "select referenced_owner,referenced_name,referenced_type from dba_dependencies where type='PACKAGE BODY' and NAME = '" + oraPackageBody + "' and OWNER='" + oraSchema + "'"
	sys.stderr.write("sql_query_inv=%s\n" % sql_query_inv )
	result_inv = lib_oracle.ExecuteQuery( cgiEnv.ConnectStr(), sql_query_inv)

	for row in result_inv:
		lib_oracle.AddDependency( grph, row, node_oraPackageBody, cgiEnv.m_oraDatabase, False )

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
