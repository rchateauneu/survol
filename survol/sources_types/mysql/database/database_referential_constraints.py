#!/usr/bin/env python

"""
Referential constraints
"""

import sys
import re
import socket
import logging
import lib_util
import lib_common
import lib_credentials

from lib_properties import pc

from sources_types import mysql as survol_mysql
from sources_types.mysql import database as survol_mysql_database
from sources_types.mysql import table as survol_mysql_table

# mysql> select * from information_schema.referential_constraints;
# +--------------------+-------------------+---------------------------+---------------------------+--------------------------+-------
# -----------------+--------------+-------------+-------------+-----------------+-----------------------+
# | CONSTRAINT_CATALOG | CONSTRAINT_SCHEMA | CONSTRAINT_NAME           | UNIQUE_CONSTRAINT_CATALOG | UNIQUE_CONSTRAINT_SCHEMA | UNIQUE
# _CONSTRAINT_NAME | MATCH_OPTION | UPDATE_RULE | DELETE_RULE | TABLE_NAME      | REFERENCED_TABLE_NAME |
# +--------------------+-------------------+---------------------------+---------------------------+--------------------------+-------
# -----------------+--------------+-------------+-------------+-----------------+-----------------------+
# | def                | sakila            | fk_address_city           | def                       | sakila                   | PRIMAR
# Y                | NONE         | CASCADE     | RESTRICT    | address         | city                  |


def Main():

	cgiEnv = lib_common.CgiEnv( )
	# hostname = cgiEnv.GetId()

	instanceName = cgiEnv.m_entity_id_dict["Instance"]
	dbNam = cgiEnv.m_entity_id_dict["Database"]

	(hostname,hostport) = survol_mysql.InstanceToHostPort(instanceName)

	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	hostAddr = lib_util.GlobalGetHostByName(hostname)

	# BEWARE: The rule whether we use the host name or the host IP is not very clear !
	# The IP address would be unambiguous but less clear.
	hostNode = lib_common.gUriGen.HostnameUri(hostname)

	# BEWARE: This is duplicated.
	propDb = lib_common.MakeProp("Mysql database")

	nodeMysqlDatabase = survol_mysql_database.MakeUri(instanceName,dbNam)
	grph.add( ( hostNode, propDb, nodeMysqlDatabase ) )

	aCred = lib_credentials.GetCredentials("MySql", instanceName)

	connMysql = survol_mysql.MysqlConnect(instanceName,aUser = aCred[0],aPass=aCred[1])

	cursorMysql = connMysql.cursor()

	cursorMysql.execute("select * from information_schema.TABLES where TABLE_SCHEMA='%s'" %dbNam)

	propTable = lib_common.MakeProp("Mysql table")

	cursorMysql.execute("select TABLE_NAME, REFERENCED_TABLE_NAME, CONSTRAINT_NAME "
	" from information_schema.referential_constraints"
	" where CONSTRAINT_SCHEMA='%s' " %(dbNam))

	propConstraint = lib_common.MakeProp("Table type")

	# There should be only one row, maximum.
	for constraintInfo in cursorMysql:
		logging.debug("constraintInfo=%s",str(constraintInfo))
		tableNam = constraintInfo[0]
		tableNamRef = constraintInfo[1]
		propConstraint = lib_common.MakeProp(constraintInfo[2])
		logging.debug("tableNam=%s",tableNam)

		nodeMysqlTable = survol_mysql_table.MakeUri(hostname,dbNam, tableNam)
		nodeMysqlTableRef = survol_mysql_table.MakeUri(hostname,dbNam, tableNamRef)

		grph.add( (nodeMysqlTable, propConstraint, nodeMysqlTableRef ) )

		#grph.add( ( nodeMysqlDatabase, propTable, nodeMysqlTable ) )

	cursorMysql.close()
	connMysql.close()

	cgiEnv.OutCgiRdf("LAYOUT_SPLINE" )


if __name__ == '__main__':
	Main()
