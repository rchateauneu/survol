"""
ODBC Data Source Name
"""

import sys
import lib_common
import lib_util
import lib_credentials
import pyodbc
from lib_properties import pc
from sources_types import odbc as survol_odbc
from sources_types.sqlserver import dsn as survol_sqlserver_dsn
from sources_types.oracle import db as oracle_db

def Graphic_colorfill():
	return "#CCFF11"

def Graphic_colorbg():
	return "#CCFF11"


def EntityOntology():
	return ( [ survol_odbc.CgiPropertyDsn() ], )

def MakeUri(dsnName):
	# sys.stderr.write("MakeUri dsnName=%s\n"%dsnName)
	return lib_common.gUriGen.UriMakeFromDict("odbc/dsn", { survol_odbc.CgiPropertyDsn() : dsnName })

def EntityName(entity_ids_arr,entity_host):
	# sys.stderr.write("EntityName entity_ids_arr=%s\n"%str(entity_ids_arr))
	return survol_odbc.CgiPropertyDsn().ValueDisplay(entity_ids_arr[0])

# This expects a DSN as a simple string.
def MakeOdbcConnectionStringFromDsn(dsnNam):
	pairUsrnamPass = lib_credentials.GetCredentials("ODBC",dsnNam)
	# With SqlServer, there is some implicit connection if this is the local machine.
	if pairUsrnamPass[0] == "":
		# Maybe we could add ";Trusted_Connection=yes"
		connectStr = "DSN=%s" % dsnNam
	else:
		connectStr = "DSN=%s;UID=%s;PWD=%s" % (dsnNam,pairUsrnamPass[0],pairUsrnamPass[1])

	return connectStr


# This can be just a string, a DSN. Or a connection string.
# This function is very tolerant.
def MakeOdbcConnectionString(dsnNam):
	# sys.stderr.write("MakeOdbcConnectionString dsnNam=%s\n"%dsnNam)
	splitTokens = [ strpTok.strip().split("=") for strpTok in dsnNam.split(";") ]

	# Maybe this is a single string, so we add "DSN" and look for username/password.
	if len(splitTokens) == 1:
		if len(splitTokens[0]) == 1:
			return MakeOdbcConnectionStringFromDsn(splitTokens[0][0])

	# Otherwise it assumes that it contains all needed connection parameters: User, password.
	# This might be checked, or if it contains FileDsn=... etc.

	# Otherwise it assumes a connection string, returned "as is".
	return dsnNam

def GetDatabaseEntityTypeFromConnection(cnxn):
	# "Oracle", "Microsoft SQL Server"
	prm_value = cnxn.getinfo(pyodbc.SQL_DBMS_NAME)

	dictDbToEntity = {
		"Oracle":"oracle",
		"Microsoft SQL Server": "sqlserver"
	}

	try:
		return dictDbToEntity[prm_value]
	except KeyError:
		# TODO: Or maybe return "sql" to be consistent with the concept of vendor-neutral database.
		return ""

def GetDatabaseEntityType(dsnNam):
	ODBC_ConnectString = MakeOdbcConnectionString(dsnNam)

	cnxn = pyodbc.connect(ODBC_ConnectString)

	return GetDatabaseEntityTypeFromConnection(cnxn)

# This displays abort link to the Oracle database, but not seen from ODBC,
# so we can have more specific queries.
def AddInfo(grph,node,entity_ids_arr):
	dsnNam = entity_ids_arr[0]

	ODBC_ConnectString = MakeOdbcConnectionString(dsnNam)

	try:
		cnxn = pyodbc.connect(ODBC_ConnectString)
	except:
		exc = sys.exc_info()[1]
		grph.add( ( node, pc.property_information, lib_common.NodeLiteral(str(exc)) ) )
		return

	dbEntityType = GetDatabaseEntityTypeFromConnection(cnxn)

	sys.stderr.write("AddInfo dbEntityType=%s\n" % dbEntityType )
	if dbEntityType == "oracle":
		# For example "XE".
		server_name = cnxn.getinfo(pyodbc.SQL_SERVER_NAME)
		node_oradb = oracle_db.MakeUri( server_name )

		grph.add( ( node, pc.property_oracle_db, node_oradb ) )

	elif dbEntityType == "sqlserver":
		# We stick to the DSN because it encloses all the needed information.
		node_sqlserverdb = survol_sqlserver_dsn.MakeUri( dsnNam )

		grph.add( ( node, pc.property_sqlserver_db, node_sqlserverdb ) )
		sys.stderr.write("AddInfo dbEntityType=%s ADDING NODE\n" % dbEntityType )

		#grph.add( ( node, pc.property_pid, lib_common.NodeLiteral(pidProc) ) )

# TODO: Maybe should decode ????
def GetDsnNameFromCgi(cgiEnv):
	keyWordDsn = survol_odbc.CgiPropertyDsn()
	dsnCoded = cgiEnv.m_entity_id_dict[keyWordDsn]
	dsnDecoded = keyWordDsn.ValueDecode(dsnCoded)

	# sys.stderr.write("GetDsnNameFromCgi dsnCoded=%s dsnDecoded=%s\n"%(dsnCoded,dsnDecoded))
	return dsnDecoded

def DatabaseEnvParams(processId):
	# TODO: We could use the process id to check if the process executable is linked
	# with the SQLServer shareable library.

	# We do not list sources in lib_credentials because some ODBC sources
	# can be accessed without pass word (With Windows validation).
	sourcesData = pyodbc.dataSources()

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

	dsnList = ( { survol_odbc.CgiPropertyDsn(): "DSN=" + dsn } for dsn in sourcesData )

	return ( "sqlserver/query", dsnList )

