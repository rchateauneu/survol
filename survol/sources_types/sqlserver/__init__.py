"""
SqlServer objects
"""

# https://www.haidongji.com/2010/10/25/list-all-database-files-in-a-sql-server-instance-with-python-and-pyodbc/
# List all database files in a SQL Server instance with Python and pyodbc

import pyodbc
from sources_types import odbc as survol_odbc

def Graphic_shape():
	return "none"

def Graphic_colorfill():
	return "#99BB88"

def Graphic_colorbg():
	return "#99BB88"

def Graphic_border():
	return 2

def Graphic_is_rounded():
	return True


# "ODBC": {
# 		"MyOracleDataSource" : [ "system", "xxx" ],
# 		"OraSysDataSrc" : [ "system", "yyy" ]
# 	},

# We list ODBC sources because this is the only we have, to connect to sqlserver databases.
# We do not list Oracle dbs so they have to be filtered out.

#
def DatabaseEnvParams(processId):
	# TODO: We could use the process id to check if the process executable is linked
	# with the SQLServer shareable library.

	# We do not list sources in lib_credentials because some ODBC sources
	# can be accessed without pass word (With Windows validation).
	sources = pyodbc.dataSources()
	# {
	# 	'MyNativeSqlServerDataSrc': 'SQL Server Native Client 11.0',
	# 	'Excel Files': 'Microsoft Excel Driver (*.xls, *.xlsx, *.xlsm, *.xlsb)',
	# 	'SqlSrvNativeDataSource': 'SQL Server Native Client 11.0',
	# 	'mySqlServerDataSource': 'SQL Server',
	# 	'MyOracleDataSource': 'Oracle in XE',
	# 	'SysDataSourceSQLServer': 'SQL Server',
	# 	'dBASE Files': 'Microsoft Access dBASE Driver (*.dbf, *.ndx, *.mdx)',
	# 	'OraSysDataSrc' : 'Oracle in XE',
	# 	'MS Access Database': 'Microsoft Access Driver (*.mdb, *.accdb)'
	# }

	dsnList = ( { survol_odbc.CgiPropertyDsn(): "DSN=" + dsn } for dsn in sources )

	# Maybe this must be adjusted as key-value pairs ??
	return ( "sqlserver/query", dsnList )

# TODO: Add a link to https://sqlwebadmin.codeplex.com/ sqlwebadmin