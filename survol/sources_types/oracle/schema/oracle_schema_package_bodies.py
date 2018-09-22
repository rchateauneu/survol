#!/usr/bin/python

"""
Oracle package bodies
"""

import sys
from lib_properties import pc
import lib_oracle
import lib_common

from sources_types.oracle import schema as oracle_schema
from sources_types.oracle import package_body as oracle_package_body

def Main():
	cgiEnv = lib_oracle.OracleEnv()

	oraSchema = cgiEnv.m_entity_id_dict["Schema"]

	grph = cgiEnv.GetGraph()

	sql_query = "SELECT OBJECT_NAME,STATUS,CREATED FROM ALL_OBJECTS WHERE OBJECT_TYPE = 'PACKAGE BODY' AND OWNER = '" + oraSchema + "'"
	DEBUG("sql_query=%s", sql_query )

	node_oraschema = oracle_schema.MakeUri( cgiEnv.m_oraDatabase, oraSchema )

	result = lib_oracle.ExecuteQuery( cgiEnv.ConnectStr(), sql_query)
	num_package_bodies=len(result)
	DEBUG("num_package_bodies=%d", num_package_bodies )

	for row in result:
		packageBodyName = str(row[0])
		# sys.stderr.write("tableName=%s\n" % tableName )
		nodePackageBody = oracle_package_body.MakeUri( cgiEnv.m_oraDatabase , oraSchema, packageBodyName )
		grph.add( ( node_oraschema, pc.property_oracle_package_body, nodePackageBody ) )

		lib_oracle.AddLiteralNotNone(grph,nodePackageBody,"Status",row[1])
		lib_oracle.AddLiteralNotNone(grph,nodePackageBody,"Creation",row[2])

	# It cannot work if there are too many tables.
	# cgiEnv.OutCgiRdf("LAYOUT_RECT")
	cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_oracle_package_body])

if __name__ == '__main__':
	Main()
