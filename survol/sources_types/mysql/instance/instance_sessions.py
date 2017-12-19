#!/usr/bin/python

"""
Sessions in a MySql instance
"""


import sys
import re
import socket
import lib_util
import lib_common
import lib_credentials

from lib_properties import pc

from sources_types import mysql as survol_mysql
#from sources_types.mysql import database as survol_mysql_database
#from sources_types.mysql import table as survol_mysql_table

def Main():

	cgiEnv = lib_common.CgiEnv( )

	instanceName = cgiEnv.m_entity_id_dict["Instance"]

	(hostname,hostport) = survol_mysql.InstanceToHostPort(instanceName)

	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	hostAddr = socket.gethostbyname(hostname)

	# BEWARE: The rule whether we use the host name or the host IP is not very clear !
	# The IP address would be unambiguous but less clear.
	hostNode = lib_common.gUriGen.HostnameUri(hostname)

	# BEWARE: This is duplicated.
	propDb = lib_common.MakeProp("Mysql database")

	nodeMysqlDatabase = survol_mysql_database.MakeUri(instanceName,dbNam)
	grph.add( ( hostNode, propDb, nodeMysqlDatabase ) )

	aCred = lib_credentials.GetCredentials("MySql", instanceName)

	connMysql = survol_mysql.MysqlConnect(hostname,aUser = aCred[0],aPass=aCred[1])

	connMysql = survol_mysql.MysqlConnect(instanceName,aUser = aCred[0],aPass=aCred[1])

	cursorMysql = connMysql.cursor()

	# mysql> select * from information_schema.processlist;
	# +--------+------------------+------------------+------+---------+------+-----------+----------------------------------------------+
	# | ID     | USER             | HOST             | DB   | COMMAND | TIME | STATE     | INFO                                         |
	# +--------+------------------+------------------+------+---------+------+-----------+----------------------------------------------+
	# | 439768 | primhilltcsrvdb1 | 10.2.123.9:52146 | NULL | Query   |    0 | executing | select * from information_schema.processlist |
	# | 439765 | primhilltcsrvdb1 | 10.2.123.9:52062 | NULL | Sleep   |   13 |           | NULL                                         |
	# +--------+------------------+------------------+------+---------+------+-----------+----------------------------------------------+

	cursorMysql.execute("select * from information_schema.processlist")

	propTable = lib_common.MakeProp("Mysql table")

	for sessInfo in cursorMysql:
		sys.stderr.write("sessInfo=%s\n"%str(sessInfo))

		mysqlUser = sessInfo[1]

		# If there is a proper socket, the create a name for it.
		mysqlSocket = sessInfo[2]
		try:
			(mysqlSocketPort,mysqlSocketHost) = mysqlSocket.split(":")
			then what
		except:
			pass

		# If there is a running query, then display it.
		mysqlCommand = sessInfo[4]
		mysqlState = sessInfo[5]
		if (mysqlCommand == "Query") and (mysqlState == "executing"):
			mysqlQuery = sessInfo[7]

			then what

		#nodeMysqlTable = survol_mysql_table.MakeUri(hostname,dbNam, tableNam)

		#grph.add( (nodeMysqlTable, lib_common.MakeProp("Engine"), lib_common.NodeLiteral(tabInfo[4]) ) )
		#grph.add( (nodeMysqlTable, pc.property_information, lib_common.NodeLiteral(tabInfo[20]) ) )

		#grph.add( ( nodeMysqlDatabase, propTable, nodeMysqlTable ) )

	cursorMysql.close()
	connMysql.close()


	cgiEnv.OutCgiRdf("LAYOUT_SPLINE")


if __name__ == '__main__':
	Main()
