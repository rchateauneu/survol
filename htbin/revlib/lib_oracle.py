import lib_common
import socket
from lib_properties import pc

import rdflib
import sys
import lib_util
import lib_credentials

logo = "http://docs.oracle.com/javase/7/docs/webnotes/tsg/TSG-VM/html/graphics/smallOracleLogo.gif";

# http://stackoverflow.com/questions/13589683/interfaceerror-unable-to-acquire-oracle-environment-handle-oracle-home-is-corr
# InterfaceError: Unable to acquire Oracle environment handle

import cx_Oracle
#try:
#except ImportError:
## No error signalling because we need some data about Oracle,
## even if the lib is not here.
#if lib_common.GuessDisplayMode(sys.stderr) != "info":
#	exc = sys.exc_info()[1]
#	lib_common.ErrorMessageHtml("Cannot import module cx_Oracle:"+str(exc))

def GetOraConnect(conn_str):
	try:
		return cx_Oracle.connect(conn_str)
	# except cx_Oracle.InterfaceError:
	# except cx_Oracle.DatabaseError:
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("cx_Oracle.connect conn_str="+conn_str+" Err="+str(exc))

def ExecuteQuery(conn_str,sql_query):
	result = []
	conn = GetOraConnect(conn_str)
	c = conn.cursor()

	sys.stderr.write("ExecuteQuery %s\n" % sql_query)
	c.execute(sql_query)

	try:
		# This could be much faster but not important now.
		for row in c:
			# Use yield ? Or return c ?
			result.append( row )

	except cx_Oracle.DatabaseError:
		pass
	conn.close()

	return result
	
# Faster because no object copy, and also mandatory if LOBs are returned,
# because they disappear when the cursor is deleted.
def CallbackQuery(conn_str,sql_query,callback):
	conn = GetOraConnect(conn_str)

	c = conn.cursor()

	c.execute(sql_query)

	try:
		for row in c:
			callback(row)

	except cx_Oracle.DatabaseError:
		pass
	conn.close()



# BEWARE: There is an implicit dependency on the structure of Oracle schema URI.
# https://docs.oracle.com/cd/A91202_01/901_doc/server.901/a90125/sql_elements10.htm
# CREATE SYNONYM emp_table FOR oe.employees@remote.us.oracle.com;
# schema.object_name.object_part@dblink
def OraUri( entity_type, ora_db, ora_part = "", ora_object = "", ora_schema = ""):
	return lib_util.EntityUri( entity_type, ora_schema + "." + ora_object + "." + ora_part + "@" + ora_db )

class OracleEnv (lib_common.CgiEnv):
	def __init__( self, title ):
		# Problem of old-style vs new-style class.

		# This used to work I think with Python 3
		# super( OracleEnv, self ).__init__( title, logo )

		lib_common.CgiEnv.__init__( self, title, logo )

		self.m_oraDatabase = self.m_entity_id_dict["Db"]

	def ConnectStr(self ):
		# TODO: This can be parsed from the schema.

		(oraUser,oraPwd) = lib_credentials.GetCredentials( "Oracle", self.m_oraDatabase )
		return oraUser + "/" + oraPwd + "@" + self.m_oraDatabase

	def MakeUri(self, entity_type, **kwArgs ):
		return lib_util.EntityUri( entity_type, { "Db": self.m_oraDatabase }, **kwArgs )


def AddDependency( grph, row, nodeRoot, oraDatabase, direction ):
	depOwner = str(row[0])
	depName = str(row[1])
	depType = str(row[2])

	if depType == "TABLE":
		nodeObject = lib_common.gUriGen.OracleTableUri( oraDatabase , depOwner, depName )
	elif depType == "VIEW":
		nodeObject = lib_common.gUriGen.OracleViewUri( oraDatabase , depOwner, depName )
	elif depType == "PACKAGE":
		nodeObject = lib_common.gUriGen.OraclePackageUri( oraDatabase , depOwner, depName )
	elif depType == "PACKAGE BODY":
		nodeObject = lib_common.gUriGen.OraclePackageBodyUri( oraDatabase , depOwner, depName )
	elif depType == "SYNONYM":
		nodeObject = lib_common.gUriGen.OracleSynonymUri( oraDatabase , depOwner, depName )
	elif depType == "TYPE":
		# TODO: Create a type.
		grph.add( ( nodeRoot, lib_common.MakeProp("Type"), rdflib.Literal( depOwner + ":" + depName) ) )
		return
	elif depType == "SEQUENCE":
		# TODO: Create a type.
		grph.add( ( nodeRoot, lib_common.MakeProp("Sequence"), rdflib.Literal( depOwner + ":" + depName) ) )
		return
	elif depType == "LIBRARY":
		# TODO: Create a type.
		grph.add( ( nodeRoot, lib_common.MakeProp("Library"), rdflib.Literal( depOwner + ":" + depName) ) )
		return
	else:
		lib_common.ErrorMessageHtml("Unknown dependency depType=%s depName=%s" % ( depType, depName ) )
		return

	if direction == True:
		grph.add( ( nodeRoot, pc.property_oracle_depends, nodeObject ) )
	else:
		grph.add( ( nodeObject, pc.property_oracle_depends, nodeRoot ) )


def AddLiteralNotNone(grph,node,txt,data):
	if data != None:
		grph.add( ( node, lib_common.MakeProp(txt), rdflib.Literal(data) ) )

# This returns an IP address.
def OraMachineToIp(oraMachine):
	# Maybe different on Linux ???  "WORKGROUP\RCHATEAU-HP"
	user_machine = socket.gethostbyname( oraMachine.split("\\")[-1] )
	return user_machine
