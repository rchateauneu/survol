#!/usr/bin/python

"""
Parse Sqlite database
"""

import os
import os.path
import sys
import rdflib
import lib_util
import lib_win32
import lib_common
from lib_properties import pc
import sqlite3

def Usable(entity_type,entity_ids_arr):
	"""Can run on a Sqlite database only"""

	filNam = entity_ids_arr[0]

	# But probably it is not enough and we should try to open it.
	filExt = os.path.splitext(filNam)[1]
	return filExt.upper() in [".SQLITE",".DB"]

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
			tabNod = lib_common.gUriGen.SqliteTableUri(dbFilNam,theTab)
			grph.add( ( filNode, lib_common.MakeProp("Table"), tabNod ) )
			theNum = theRow[3]
			grph.add( ( tabNod, pc.property_information, rdflib.Literal(theNum) ) )
			# Do not print too much information in case there are too many tables.
			#theCmd = theRow[4]
			#grph.add( ( tabNod, pc.property_information, rdflib.Literal(theCmd) ) )
	except:
		exc = sys.exc_info()[0]
		lib_common.ErrorMessageHtml("Sqlite file:%s Unexpected error:%s" % ( dbFilNam, str( exc ) ) )

	cgiEnv.OutCgiRdf(grph,"LAYOUT_SPLINE")

if __name__ == '__main__':
	Main()
