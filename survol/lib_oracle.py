import lib_common
from lib_properties import pc

import sys
import lib_util
import lib_credentials

from sources_types.oracle import table as oracle_table
from sources_types.oracle import view as oracle_view
from sources_types.oracle import package as oracle_package
from sources_types.oracle import package_body as oracle_package_body

from sources_types.oracle import function as oracle_function
from sources_types.oracle import library as oracle_library
from sources_types.oracle import procedure as oracle_procedure
from sources_types.oracle import sequence as oracle_sequence
from sources_types.oracle import synonym as oracle_synonym
from sources_types.oracle import trigger as oracle_trigger
from sources_types.oracle import type as oracle_type

# http://stackoverflow.com/questions/13589683/interfaceerror-unable-to-acquire-oracle-environment-handle-oracle-home-is-corr
# InterfaceError: Unable to acquire Oracle environment handle

import cx_Oracle

def GetOraConnect(conn_str):
	try:
		return cx_Oracle.connect(conn_str)
	# except cx_Oracle.InterfaceError:
	# except cx_Oracle.DatabaseError:
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("cx_Oracle.connect conn_str="+conn_str+" Err="+str(exc))

# TODO: Check that there is only one query, and exclusively a select,
# to avoid SQL injections.
def ExecuteSafeQuery(aCursor,sql_query):
	if not sql_query.upper().startswith("SELECT "):
		raise Exception("Unsafe query:%s"%sql_query)
	aCursor.execute(sql_query)

def ExecuteQueryThrow(conn_str,sql_query):
	result = []
	conn = GetOraConnect(conn_str)
	aCursor = conn.cursor()

	sys.stderr.write("ExecuteQuery %s\n" % sql_query)

	ExecuteSafeQuery(aCursor,sql_query)
	try:
		# This could be faster by returning a cursor
		# or a generator, but this is not important now.
		for row in aCursor:
			# Use yield ? Or return c ?
			result.append( row )

	except cx_Oracle.DatabaseError:
		pass
	conn.close()

	return result

def ExecuteQuery(conn_str,sql_query):
	try:
		return ExecuteQueryThrow(conn_str,sql_query)
	except cx_Oracle.DatabaseError:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("CallbackQuery exception:%s in %s"% ( str(exc), sql_query ) )



# Faster because no object copy, and also mandatory if LOBs are returned,
# because they disappear when the cursor is deleted.
def CallbackQuery(conn_str,sql_query,callback):
	conn = GetOraConnect(conn_str)

	aCursor = conn.cursor()

	ExecuteSafeQuery(aCursor,sql_query)
	try:
		for row in aCursor:
			callback(row)

	except cx_Oracle.DatabaseError:
		pass
	conn.close()

# BEWARE: There is an implicit dependency on the structure of Oracle schema URI.
# https://docs.oracle.com/cd/A91202_01/901_doc/server.901/a90125/sql_elements10.htm
# CREATE SYNONYM emp_table FOR oe.employees@remote.us.oracle.com;
# schema.object_name.object_part@dblink
#def OraUri( entity_type, ora_db, ora_part = "", ora_object = "", ora_schema = ""):
#	return lib_util.EntityUri( entity_type, ora_schema + "." + ora_object + "." + ora_part + "@" + ora_db )

class OracleEnv (lib_common.CgiEnv):
	def __init__( self ):
		lib_common.CgiEnv.__init__( self )

		self.m_oraDatabase = self.m_entity_id_dict["Db"]

	def ConnectStr(self):
		# TODO: This can be parsed from the schema.

		(oraUser,oraPwd) = lib_credentials.GetCredentials( "Oracle", self.m_oraDatabase )
		return oraUser + "/" + oraPwd + "@" + self.m_oraDatabase

	def MakeUri(self, entity_type, **kwArgs ):
		return lib_util.EntityUri( entity_type, { "Db": self.m_oraDatabase }, **kwArgs )

	def OracleSchema(self):
		# TODO: This could call GetCredentials once only.
		(oraUser,oraPwd) = lib_credentials.GetCredentials( "Oracle", self.m_oraDatabase )
		return oraUser

# This displays the content of the Oracle table dba_dependencies.
def AddDependency( grph, row, nodeRoot, oraDatabase, direction ):
	depOwner = str(row[0])
	depName = str(row[1])
	depType = str(row[2])

	if depType == "TABLE":
		nodeObject = oracle_table.MakeUri( oraDatabase , depOwner, depName )
	elif depType == "VIEW":
		nodeObject = oracle_view.MakeUri( oraDatabase , depOwner, depName )
	elif depType == "PACKAGE":
		nodeObject = oracle_package.MakeUri( oraDatabase , depOwner, depName )
	elif depType == "PACKAGE BODY":
		nodeObject = oracle_package_body.MakeUri( oraDatabase , depOwner, depName )
	elif depType == "SYNONYM":
		nodeObject = oracle_synonym.MakeUri( oraDatabase , depOwner, depName )
	elif depType == "TYPE":
		nodeObject = oracle_type.MakeUri( oraDatabase , depOwner, depName )
	elif depType == "SEQUENCE":
		nodeObject = oracle_sequence.MakeUri( oraDatabase , depOwner, depName )
	elif depType == "LIBRARY":
		nodeObject = oracle_library.MakeUri( oraDatabase , depOwner, depName )
	elif depType == "PROCEDURE":
		nodeObject = oracle_procedure.MakeUri( oraDatabase , depOwner, depName )
	elif depType == "FUNCTION":
		nodeObject = oracle_function.MakeUri( oraDatabase , depOwner, depName )
	elif depType == "TRIGGER":
		nodeObject = oracle_trigger.MakeUri( oraDatabase , depOwner, depName )
	else:
		lib_common.ErrorMessageHtml("Unknown dependency depType=%s depName=%s" % ( depType, depName ) )
		return

	if direction == True:
		grph.add( ( nodeRoot, pc.property_oracle_depends, nodeObject ) )
	else:
		grph.add( ( nodeObject, pc.property_oracle_depends, nodeRoot ) )


def AddLiteralNotNone(grph,node,txt,data):
	if data != None:
		grph.add( ( node, lib_common.MakeProp(txt), lib_common.NodeLiteral(data) ) )

# This returns an IP address.
def OraMachineToIp(oraMachine):
	# Maybe different on Linux ???  "WORKGROUP\RCHATEAU-HP"
	user_machine = lib_util.GlobalGetHostByName( oraMachine.split("\\")[-1] )
	return user_machine
