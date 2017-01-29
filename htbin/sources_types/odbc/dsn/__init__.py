"""
ODBC Data Source Name
"""

import sys
import lib_common
import lib_util
import lib_credentials
import pyodbc
from lib_properties import pc
from sources_types.sqlserver import dsn as survol_sqlserver_dsn
from sources_types.oracle import db as oracle_db
import rdflib

def Graphic_colorfill():
	return "#CCFF11"

def Graphic_colorbg():
	return "#CCFF11"

def EntityOntology():
	return ( ["Dsn"], )

def MakeUri(dsnName):
	return lib_common.gUriGen.UriMakeFromDict("odbc/dsn", { "Dsn" : lib_util.EncodeUri(dsnName) })

def MakeOdbcConnectionString(dsnNam):
	pairUsrnamPass = lib_credentials.GetCredentials("ODBC",dsnNam)
	# With SqlServer, there is some implicit connection if this is the local machine.
	if pairUsrnamPass[0] == "":
		connectStr = "DSN=%s" % dsnNam
	else:
		connectStr = "DSN=%s;UID=%s;PWD=%s" % (dsnNam,pairUsrnamPass[0],pairUsrnamPass[1])

	return connectStr

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
		grph.add( ( node, pc.property_information, rdflib.Literal(str(exc)) ) )
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

		#grph.add( ( node, pc.property_pid, rdflib.Literal(pidProc) ) )
