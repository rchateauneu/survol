#!/usr/bin/env python

"""
Oracle database schemas
"""

import sys
import lib_common
from lib_properties import pc
import lib_oracle
from sources_types.oracle import db as oracle_db
from sources_types.oracle import schema as oracle_schema


def ListDbaUsers(cgiEnv,node_oradb,grph):
	# SQL> desc dba_users
	#  Name                                      Null?    Type
	#  ----------------------------------------- -------- ----------------------------
	#  USERNAME                                  NOT NULL VARCHAR2(30)
	#  USER_ID                                   NOT NULL NUMBER
	#  PASSWORD                                           VARCHAR2(30)
	#  ACCOUNT_STATUS                            NOT NULL VARCHAR2(32)
	#  LOCK_DATE                                          DATE
	#  EXPIRY_DATE                                        DATE
	#  DEFAULT_TABLESPACE                        NOT NULL VARCHAR2(30)
	#  TEMPORARY_TABLESPACE                      NOT NULL VARCHAR2(30)
	#  CREATED                                   NOT NULL DATE
	#  PROFILE                                   NOT NULL VARCHAR2(30)
	#  INITIAL_RSRC_CONSUMER_GROUP                        VARCHAR2(30)
	#  EXTERNAL_NAME                                      VARCHAR2(4000)
	#  PASSWORD_VERSIONS                                  VARCHAR2(8)
	#  EDITIONS_ENABLED                                   VARCHAR2(1)
	#  AUTHENTICATION_TYPE                                VARCHAR2(8)

	qryDbaUsers = "select username, user_id, account_status, lock_date, expiry_date from dba_users"
	result = lib_oracle.ExecuteQueryThrow( cgiEnv.ConnectStr(),qryDbaUsers)

	for row in result:
		# row=('ORACLE_OCM', 21, 'EXPIRED & LOCKED')
		DEBUG("row=" + str(row))
		nodeSchema = oracle_schema.MakeUri( cgiEnv.m_oraDatabase, str(row[0]) )
		grph.add( ( node_oradb, pc.property_oracle_schema, nodeSchema ) )

		lib_oracle.AddLiteralNotNone(grph,nodeSchema,"Schema-id",row[1])
		lib_oracle.AddLiteralNotNone(grph,nodeSchema,"Status",row[2])
		lib_oracle.AddLiteralNotNone(grph,nodeSchema,"Lock date",row[3])
		lib_oracle.AddLiteralNotNone(grph,nodeSchema,"Expiry date",row[4])

def ListAllUsers(cgiEnv,node_oradb,grph):
	# SQL> desc all_users
	#  Name                                      Null?    Type
	#  ----------------------------------------- -------- ----------------------------
	#  USERNAME                                  NOT NULL VARCHAR2(30)
	#  USER_ID                                   NOT NULL NUMBER
	#  CREATED                                   NOT NULL DATE


	qryDbaUsers = "select username, user_id, created from all_users"
	result = lib_oracle.ExecuteQueryThrow( cgiEnv.ConnectStr(),qryDbaUsers)

	for row in result:
		DEBUG("row=" + str(row))
		nodeSchema = oracle_schema.MakeUri( cgiEnv.m_oraDatabase, str(row[0]) )
		grph.add( ( node_oradb, pc.property_oracle_schema, nodeSchema ) )

		lib_oracle.AddLiteralNotNone(grph,nodeSchema,"Schema-id",row[1])
		lib_oracle.AddLiteralNotNone(grph,nodeSchema,"Created",row[2])

def Main():
	cgiEnv = lib_oracle.OracleEnv()

	grph = cgiEnv.GetGraph()
	node_oradb = oracle_db.MakeUri( cgiEnv.m_oraDatabase )

	try:
		ListDbaUsers(cgiEnv,node_oradb,grph)
	except:
		try:
			ListAllUsers(cgiEnv,node_oradb,grph)
		except:
			exc = sys.exc_info()[1]
			lib_common.ErrorMessageHtml("ExecuteQuery exception:%s"% ( str(exc) ) )


	cgiEnv.OutCgiRdf("LAYOUT_RECT")

if __name__ == '__main__':
	Main()
