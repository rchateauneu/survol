#!/usr/bin/python

"""
Parse Sqlite database
"""

#import os
#import os.path
import sys
import rdflib
import lib_common
from lib_properties import pc
import sqlite3
from sources_types import sqlite
from sources_types.sqlite import table as sqlite_table

def Usable(entity_type,entity_ids_arr):
	"""Can run on a Sqlite database only"""
	filNam = entity_ids_arr[0]
	return sqlite.IsSqliteDatabase(filNam)

def Main():
	cgiEnv = lib_common.CgiEnv()

	dbFilNam = cgiEnv.GetId()

	# sys.stderr.write("dbFilNam=%s\n"%dbFilNam)

	grph = rdflib.Graph()

	filNode = lib_common.gUriGen.FileUri(dbFilNam )


	try:
		con = sqlite3.connect(dbFilNam)
		cursor = con.cursor()
		cursor.execute("SELECT * FROM sqlite_master WHERE type='table';")

		#[(u'table', u'tz_schema_version', u'tz_schema_version', 2, u'CREATE TABLE tz_schema_version (version INTEGER)'),

		for theRow in cursor.fetchall():
			theTab = theRow[1]
			tabNod = sqlite_table.MakeUri(dbFilNam,theTab)
			grph.add( ( filNode, lib_common.MakeProp("Table"), tabNod ) )
			theNum = theRow[3]
			grph.add( ( tabNod, pc.property_information, rdflib.Literal(theNum) ) )
			# Do not print too much information in case there are too many tables.
			#theCmd = theRow[4]
			#grph.add( ( tabNod, pc.property_information, rdflib.Literal(theCmd) ) )
	except sqlite3.DatabaseError:
		lib_common.ErrorMessageHtml("Sqlite file:%s Caught:%s" % ( dbFilNam, str( sys.exc_info() ) ) )
	except:
		exc = sys.exc_info()[0]
		lib_common.ErrorMessageHtml("Sqlite file:%s Unexpected error:%s" % ( dbFilNam, str( exc ) ) )

	cgiEnv.OutCgiRdf(grph,"LAYOUT_SPLINE")

if __name__ == '__main__':
	Main()
