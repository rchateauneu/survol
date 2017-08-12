"""
SqlServer objects
"""

import pyodbc

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

def DatabaseEnvParams(processId):
	# lstCredNams = lib_credentials.GetCredentialsNames('Oracle')

	# TODO: We could use the process id to check if the process executable is linked
	# with the SQLServer shareable library.

	# We do not list sources in lib_credentials because some ODBC sources
	# can be accessed without pass word (With Windows validation).
	sources = pyodbc.dataSources()
	dsnList = ( { "Dsn":dsn } for dsn in sources )

	# Maybe this must be adjusted as key-value pairs ??
	return ( "sqlserver/query", dsnList )

# TODO: Add a link to https://sqlwebadmin.codeplex.com/ sqlwebadmin