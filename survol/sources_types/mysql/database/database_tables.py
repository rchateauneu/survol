#!/usr/bin/python

"""
Tables in a MySql database
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
from sources_types.mysql import table as survol_mysql_table

def Main():

	cgiEnv = lib_common.CgiEnv( )
	hostname = cgiEnv.GetId()


	hostNam = cgiEnv.m_entity_id_dict["Hostname"]
	dbNam = cgiEnv.m_entity_id_dict["Database"]

	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	hostAddr = socket.gethostbyname(hostname)

	# BEWARE: The rule whether we use the host name or the host IP is not very clear !
	# The IP address would be unambiguous but less clear.
	hostNode = lib_common.gUriGen.HostnameUri(hostname)

	# BEWARE: This is duplicated.
	propDb = lib_common.MakeProp("Mysql database")

	nodeMysqlDatabase = survol_mysql_database.MakeUri(hostname,dbNam)
	grph.add( ( hostNode, propDb, nodeMysqlDatabase ) )

	aCred = lib_credentials.GetCredentials("MySql", hostname)

	connMysql = survol_mysql.MysqlConnect(hostname,aUser = aCred[0],aPass=aCred[1])

	cursorMysql = connMysql.cursor()

	cursorMysql.execute("select * from information_schema.TABLES where TABLE_SCHEMA='%s'" %dbNam)


	propTable = lib_common.MakeProp("Mysql table")

	# >>> conn =  MySQLdb.connect(user="primhilltcsrvdb1",passwd="?????",host="primhilltcsrvdb1.mysql.db")
	# >>> curs=conn.cursor()
	# >>> curs.execute("select * from information_schema.TABLES where TABLE_SCHEMA='primhilltcsrvdb1'")
	# >>> for x in curs:

	# TABLE_CATALOG	 	def
	# TABLE_SCHEMA	Table_...	 
	# TABLE_NAME	Table_...	 
	# TABLE_TYPE	 	 
	# ENGINE	Engine	MySQL extension
	# VERSION	Version	The version number of the table's .frm file, MySQL extension
	# ROW_FORMAT	Row_format	MySQL extension
	# TABLE_ROWS	Rows	MySQL extension
	# AVG_ROW_LENGTH	Avg_row_length	MySQL extension
	# DATA_LENGTH	Data_length	MySQL extension
	# MAX_DATA_LENGTH	Max_data_length	MySQL extension
	# INDEX_LENGTH	Index_length	MySQL extension
	# DATA_FREE	Data_free	MySQL extension
	# AUTO_INCREMENT	Auto_increment	MySQL extension
	# CREATE_TIME	Create_time	MySQL extension
	# UPDATE_TIME	Update_time	MySQL extension
	# CHECK_TIME	Check_time	MySQL extension
	# TABLE_COLLATION	Collation	MySQL extension
	# CHECKSUM	Checksum	MySQL extension
	# CREATE_OPTIONS	Create_options	MySQL extension
	# TABLE_COMMENT	Comment	MySQL extension

	# ...     print(x)
	# (	'def', 'primhilltcsrvdb1', 'Test_Table', 'BASE TABLE', 'InnoDB', 
	#	10L, 'Compact', 2L, 8192L, 16384L, 
	#	0L, 0L, 0L, None, datetime.datetime(2017, 12, 13, 8, 59, 24), 
	#	None, None, 'latin1_swedish_ci', None, '', 
	#	'Comment about this test table.')

	for tabInfo in cursorMysql:
		sys.stderr.write("tabInfo=%s\n"%str(tabInfo))
		tableNam = tabInfo[2]

		nodeMysqlTable = survol_mysql_table.MakeUri(hostname,dbNam, tableNam)


		grph.add( (nodeMysqlTable, lib_common.MakeProp("Engine"), lib_common.NodeLiteral(tabInfo[4]) ) )
		grph.add( (nodeMysqlTable, pc.property_information, lib_common.NodeLiteral(tabInfo[20]) ) )

		grph.add( ( nodeMysqlDatabase, propTable, nodeMysqlTable ) )

	cursorMysql.close()
	connMysql.close()


	cgiEnv.OutCgiRdf("LAYOUT_SPLINE")


if __name__ == '__main__':
	Main()
