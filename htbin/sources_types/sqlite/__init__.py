import os
import sys
import rdflib
import lib_common
from lib_properties import pc

import sqlite3
from sources_types.sqlite import table as sqlite_table
from sources_types.sqlite import view as sqlite_view
from sources_types import CIM_Process

# Tells if a file is a sqlite databse.
def IsSqliteDatabase(filNam):
	# TODO: Checking the file extension may not be enough and we should check the content.
	filExt = os.path.splitext(filNam)[1]
	return filExt.upper() in [".SQLITE",".SQLITE2",".SQLITE3",".DB"]

# This basically returns a list of the sqlite files accessed by the process.
# It is used to deduce which sqlite file is accessed by a query.
def DatabaseEnvParams(processId):
	sys.stderr.write("\nDatabaseEnvParams processId=%s\n"%(str(processId)))
	# Get the list of files open by the process.
	try:
		proc_obj = CIM_Process.PsutilGetProcObj(int(processId))
		fillist = CIM_Process.PsutilProcOpenFiles( proc_obj )
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Caught:"+str(exc)+": processId="+str(processId))

	listArgs = []
	for filObj in fillist:
		filNam = filObj.path
		sys.stderr.write("DatabaseEnvParams processId=%s filNam=%s\n"%(str(processId),filNam))
		if IsSqliteDatabase(filNam):
			sys.stderr.write("    DatabaseEnvParams ADDING filNam=%s\n"%(filNam))
			filNamClean = filNam.replace("\\","/")
			filDef = { "File" : filNamClean }
			listArgs.append(filDef)

	sys.stderr.write("DatabaseEnvParams len=%d\n\n"%(len(listArgs) ))

	return ( "sqlite/query", listArgs )

def AddNodesTablesViews(grph,filNode,dbFilNam):
	sys.stderr.write("AddNodesTablesViews dbFilNam=%s\n"%(dbFilNam ))
	try:
		con = sqlite3.connect(dbFilNam)
		cursor = con.cursor()
		# type TEXT,
		# name TEXT,
		# tbl_name TEXT,
		# rootpage INTEGER,
		# sql TEXT
		cursor.execute("SELECT * FROM sqlite_master WHERE type='table' or type='view';")

		#[(u'table', u'tz_schema_version', u'tz_schema_version', 2, u'CREATE TABLE tz_schema_version (version INTEGER)'),

		for theRow in cursor.fetchall():
			theType = theRow[0]
			theName = theRow[1]
			if theType == 'table':
				nameNod = sqlite_table.MakeUri(dbFilNam,theName)
				grph.add( ( filNode, lib_common.MakeProp("Table"), nameNod ) )
			elif theType == 'view':
				nameNod = sqlite_view.MakeUri(dbFilNam,theName)
				grph.add( ( filNode, lib_common.MakeProp("View"), nameNod ) )
			else:
				continue

			theRootpage = theRow[3]
			grph.add( ( nameNod, lib_common.MakeProp("Root page"), rdflib.Literal(theRootpage) ) )
			grph.add( ( nameNod, lib_common.MakeProp("Type"), rdflib.Literal(theType) ) )

			# Do not print too much information in case there are too many tables.
			#theCmd = theRow[4]
			#grph.add( ( tabNod, pc.property_information, rdflib.Literal(theCmd) ) )
	except sqlite3.DatabaseError:
		lib_common.ErrorMessageHtml("Sqlite file:%s Caught:%s" % ( dbFilNam, str( sys.exc_info() ) ) )
	except:
		exc = sys.exc_info()[0]
		lib_common.ErrorMessageHtml("Sqlite file:%s Unexpected error:%s" % ( dbFilNam, str( exc ) ) )

