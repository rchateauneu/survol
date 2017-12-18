#!/usr/bin/python

"""
MySql databases on a server
"""

# TODO: Is is accessible from the first page on the current machine ?


import sys
import re
import socket
import lib_util
import lib_common
import lib_credentials

from lib_properties import pc

from sources_types import mysql as survol_mysql
from sources_types.mysql import database as survol_mysql_database

try:
	import mysql.connector
	def MysqlConnect(aHost,aUser,aPass):
		# conn = mysql.connector.connect (user='primhilltcsrvdb1', password='xxx', host='primhilltcsrvdb1.mysql.db',buffered=True)
		conn = mysql.connector.connect (user=aUser, password=aPass, host=aHost,buffered=True)
		return conn
except ImportError:
	import MySQLdb
	def MysqlConnect(aHost,aUser,aPass):
		conn =  MySQLdb.connect(user=aUser, passwd=aPass, host=aHost)
		return conn

def Main():

	cgiEnv = lib_common.CgiEnv( )
	hostname = cgiEnv.GetId()

	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	hostAddr = socket.gethostbyname(hostname)

	# BEWARE: The rule whether we use the host name or the host IP is not very clear !
	# The IP address would be unambiguous but less clear.
	hostNode = lib_common.gUriGen.HostnameUri(hostname)

	aCred = lib_credentials.GetCredentials("MySql", hostname)

	connMysql = MysqlConnect(hostname,aUser = aCred[0],aPass=aCred[1])

	cursorMysql = connMysql.cursor()

	cursorMysql.execute("show databases")

	propDb = lib_common.MakeProp("Mysql database")

	for dbInfo in cursorMysql:
		#('information_schema',)
		#('primhilltcsrvdb1',)
		sys.stderr.write("dbInfo=%s\n"%str(dbInfo))
		dbNam = dbInfo[0]

		nodeMysqlDatabase = survol_mysql_database.MakeUri(hostname,dbNam)

		# Create a node for each database.
		# grph.add( ( nodeMysqlDatabase, pc.property_user, lib_common.NodeLiteral(aCred[0]) ) )
		grph.add( ( hostNode, propDb, nodeMysqlDatabase ) )

	cursorMysql.close()
	connMysql.close()


	cgiEnv.OutCgiRdf("LAYOUT_SPLINE")


if __name__ == '__main__':
	Main()
