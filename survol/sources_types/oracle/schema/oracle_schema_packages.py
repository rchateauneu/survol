#!/usr/bin/env python

"""
Oracle packages
"""

import sys
from lib_properties import pc
import lib_oracle
import lib_common

from sources_types.oracle import schema as oracle_schema
from sources_types.oracle import package as oracle_package

def Main():
	cgiEnv = lib_oracle.OracleEnv()

	# BEWARE: There is an implicit dependency on the structure of Oracle schema URI.
	oraSchema = cgiEnv.m_entity_id_dict["Schema"]

	grph = cgiEnv.GetGraph()

	sql_query = "SELECT OBJECT_NAME,STATUS,CREATED FROM ALL_OBJECTS WHERE OBJECT_TYPE = 'PACKAGE' AND OWNER = '" + oraSchema + "'"
	DEBUG("sql_query=%s", sql_query )

	node_oraschema = oracle_schema.MakeUri( cgiEnv.m_oraDatabase, oraSchema )

	result = lib_oracle.ExecuteQuery( cgiEnv.ConnectStr(), sql_query)

	for row in result:
		packageName = str(row[0])
		# sys.stderr.write("tableName=%s\n" % tableName )
		nodePackage = oracle_package.MakeUri( cgiEnv.m_oraDatabase , oraSchema, packageName )
		grph.add( ( node_oraschema, pc.property_oracle_package, nodePackage ) )

		lib_oracle.AddLiteralNotNone(grph,nodePackage,"Status",row[1])
		lib_oracle.AddLiteralNotNone(grph,nodePackage,"Creation",row[2])

	# It cannot work if there are too many tables.
	# cgiEnv.OutCgiRdf("LAYOUT_RECT")
	cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_oracle_package])

if __name__ == '__main__':
	Main()
