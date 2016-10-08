import lib_common
import lib_credentials
import pyodbc
from lib_properties import pc

# from sources_types import odbc as survol_odbc


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

	cnxn = pyodbc.connect(ODBC_ConnectString)

	dbEntityType = GetDatabaseEntityTypeFromConnection(cnxn)

	if dbEntityType == "oracle":
		# For example "XE".
		server_name = cnxn.getinfo(pyodbc.SQL_SERVER_NAME)
		node_oradb = lib_common.gUriGen.OracleDbUri( server_name )

		grph.add( ( node, pc.property_oracle_db, node_oradb ) )

		# sys.stderr.write("AddInfo entity_id=%s\n" % pidProc )
		#grph.add( ( node, pc.property_pid, rdflib.Literal(pidProc) ) )

#	return


