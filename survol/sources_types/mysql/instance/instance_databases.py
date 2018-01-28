#!/usr/bin/python

"""
Databases in a MySql instance
"""


import sys
import re
import socket
import lib_util
import lib_common
import lib_credentials

from lib_properties import pc

from sources_types import mysql as survol_mysql
from sources_types.mysql import database as survol_mysql_database
from sources_types.mysql import instance as survol_mysql_instance

def Main():

	cgiEnv = lib_common.CgiEnv( )

	instanceName = cgiEnv.m_entity_id_dict["Instance"]
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

	aCred = lib_credentials.GetCredentials("MySql", instanceName)

	# If user/password incorrect, nothing we can do.
	try:
		aUser = aCred[0]
		connMysql = survol_mysql.MysqlConnect(instanceName,aUser,aPass=aCred[1])
	except :
		exc = sys.exc_info()
		lib_common.ErrorMessageHtml("Cannot connect to instance=%s user=%s:%s"%(instanceName,aUser,str(exc)))

	cursorMysql = connMysql.cursor()

	cursorMysql.execute("show databases")

	propDb = lib_common.MakeProp("Mysql database")

	grph.add( ( hostNode, lib_common.MakeProp("Mysql instance"), instanceNode ) )

	for dbInfo in cursorMysql:
		#('information_schema',)
		#('primhilltcsrvdb1',)
		sys.stderr.write("dbInfo=%s\n"%str(dbInfo))
		dbNam = dbInfo[0]

		nodeMysqlDatabase = survol_mysql_database.MakeUri(instanceName,dbNam)

		# Create a node for each database.
		grph.add( ( nodeMysqlDatabase, pc.property_user, lib_common.NodeLiteral(aCred[0]) ) )
		grph.add( ( instanceNode, propDb, nodeMysqlDatabase ) )

	cursorMysql.close()
	connMysql.close()

	cgiEnv.OutCgiRdf("LAYOUT_SPLINE")

if __name__ == '__main__':
	Main()
