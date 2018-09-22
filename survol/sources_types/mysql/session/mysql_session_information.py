#!/usr/bin/python

"""
Information about a mysql session
"""

import sys
import re
import socket
import lib_util
import lib_common
import lib_credentials

from lib_properties import pc

from sources_types import mysql as survol_mysql
from sources_types.mysql import instance as survol_mysql_instance
from sources_types.mysql import session as survol_mysql_session
from sources_types.mysql import query as survol_mysql_query

def Main():

	cgiEnv = lib_common.CgiEnv( )

	instanceName = cgiEnv.m_entity_id_dict["Instance"]
	sessionId = cgiEnv.m_entity_id_dict["Id"]

	instanceNode = survol_mysql_instance.MakeUri(instanceName)

	(hostname,hostport) = survol_mysql.InstanceToHostPort(instanceName)

	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	hostAddr = lib_util.GlobalGetHostByName(hostname)

	# BEWARE: The rule whether we use the host name or the host IP is not very clear !
	# The IP address would be unambiguous but less clear.
	hostNode = lib_common.gUriGen.HostnameUri(hostname)

	# BEWARE: This is duplicated.
	propDb = lib_common.MakeProp("Mysql database")

	#nodeMysqlDatabase = survol_mysql_database.MakeUri(instanceName,dbNam)
	#grph.add( ( hostNode, propDb, nodeMysqlDatabase ) )

	aCred = lib_credentials.GetCredentials("MySql", instanceName)

	connMysql = survol_mysql.MysqlConnect(instanceName,aUser = aCred[0],aPass=aCred[1])

	cursorMysql = connMysql.cursor()

	# mysql> select * from information_schema.processlist;
	# +--------+------------------+------------------+------+---------+------+-----------+----------------------------------------------+
	# | ID     | USER             | HOST             | DB   | COMMAND | TIME | STATE     | INFO                                         |
	# +--------+------------------+------------------+------+---------+------+-----------+----------------------------------------------+
	# | 439768 | primhilltcsrvdb1 | 10.2.123.9:52146 | NULL | Query   |    0 | executing | select * from information_schema.processlist |
	# | 439765 | primhilltcsrvdb1 | 10.2.123.9:52062 | NULL | Sleep   |   13 |           | NULL                                         |
	# +--------+------------------+------------------+------+---------+------+-----------+----------------------------------------------+

	cursorMysql.execute("select * from information_schema.processlist where ID=%s"%sessionId)

	propTable = lib_common.MakeProp("Mysql table")

	grph.add( ( hostNode, lib_common.MakeProp("Mysql instance"), instanceNode ) )

	# There should be one row only.
	for sessInfo in cursorMysql:
		DEBUG("sessInfo=%s",str(sessInfo))

		mysqlSessionId = sessInfo[0]
		mysqlUser = sessInfo[1]

		sessionNode = survol_mysql_session.MakeUri(instanceName,mysqlSessionId)

		# If there is a proper socket, then create a name for it.
		mysqlSocket = sessInfo[2]
		try:
			(mysqlSocketHost,mysqlSocketPort) = mysqlSocket.split(":")
			socketNode = lib_common.gUriGen.AddrUri( mysqlSocketHost, mysqlSocketPort )
			grph.add( (sessionNode, lib_common.MakeProp("Connection socket"), socketNode ) )
		except:
			pass

		mysqlDB = sessInfo[3]
		grph.add( (sessionNode, lib_common.MakeProp("Database"), lib_common.NodeLiteral(mysqlDB) ) )

		mysqlTime = sessInfo[5]
		grph.add( (sessionNode, lib_common.MakeProp("Time"), lib_common.NodeLiteral(mysqlTime) ) )

		# If there is a running query, then display it.
		mysqlCommand = sessInfo[4]
		mysqlState = sessInfo[6]
		if (mysqlCommand == "Query") and (mysqlState == "executing"):
			mysqlQuery = sessInfo[7]

			nodeQuery = survol_mysql_query.MakeUri(instanceName,mysqlQuery)
			grph.add( (sessionNode, lib_common.MakeProp("Mysql query"), nodeQuery ) )

		grph.add( (sessionNode, lib_common.MakeProp("Command"), lib_common.NodeLiteral(mysqlCommand) ) )

		grph.add( (sessionNode, lib_common.MakeProp("State"), lib_common.NodeLiteral(mysqlState) ) )

		grph.add( (sessionNode, lib_common.MakeProp("User"), lib_common.NodeLiteral(mysqlUser) ) )

		grph.add( ( sessionNode, lib_common.MakeProp("Mysql session"), instanceNode ) )


	cursorMysql.close()
	connMysql.close()


	cgiEnv.OutCgiRdf("LAYOUT_SPLINE")


if __name__ == '__main__':
	Main()
