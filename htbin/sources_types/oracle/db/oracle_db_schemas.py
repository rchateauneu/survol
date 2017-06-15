#!/usr/bin/python

"""
Oracle database'schemas
"""

#import re
import sys
#import lib_common
from lib_properties import pc
import lib_oracle
import rdflib
from sources_types.oracle import db as oracle_db
from sources_types.oracle import schema as oracle_schema

def Main():
	cgiEnv = lib_oracle.OracleEnv()

	grph = cgiEnv.GetGraph()

	sql_query = "select username, user_id, account_status, lock_date, expiry_date from dba_users"

	node_oradb = oracle_db.MakeUri( cgiEnv.m_oraDatabase )

	result = lib_oracle.ExecuteQuery( cgiEnv.ConnectStr(),sql_query)

	for row in result:
		# row=('ORACLE_OCM', 21, 'EXPIRED & LOCKED')
		sys.stderr.write("row=" + str(row) + "\n")
		nodeSchema = oracle_schema.MakeUri( cgiEnv.m_oraDatabase, str(row[0]) )
		grph.add( ( node_oradb, pc.property_oracle_schema, nodeSchema ) )

		lib_oracle.AddLiteralNotNone(grph,nodeSchema,"Schema-id",row[1])
		lib_oracle.AddLiteralNotNone(grph,nodeSchema,"Status",row[2])
		lib_oracle.AddLiteralNotNone(grph,nodeSchema,"Lock date",row[3])
		lib_oracle.AddLiteralNotNone(grph,nodeSchema,"Expiry date",row[4])

	cgiEnv.OutCgiRdf("LAYOUT_RECT")

if __name__ == '__main__':
	Main()
