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

	tableName = cgiEnv.m_entity_id_dict["Table"]
	dbFilNam = cgiEnv.m_entity_id_dict["File"]

	# sys.stderr.write("dbFilNam=%s\n"%dbFilNam)

	grph = rdflib.Graph()

	filNode = lib_common.gUriGen.FileUri(dbFilNam )
	tabNod = lib_common.gUriGen.SqliteTableUri(dbFilNam,tableName)
	grph.add( ( filNode, lib_common.MakeProp("Table"), tabNod ) )

	con = sqlite3.connect(dbFilNam)
	cursor = con.cursor()

	#>>> eta = curs.execute("PRAGMA table_info('tz_data')")
	#(0, u'tzid', u'TEXT', 0, None, 0)
	#(1, u'alias', u'TEXT', 0, None, 0)

	cursor.execute("PRAGMA table_info('%s')" % tableName )

	propColumn = lib_common.MakeProp("Column")
	propType = lib_common.MakeProp("Type")
	for theRow in cursor.fetchall():
		columnNam = theRow[1]
		columnNod = lib_common.gUriGen.SqliteColumnUri(dbFilNam,tableName,columnNam)
		grph.add( ( tabNod, propColumn, columnNod ) )
		typeNam = theRow[2]
		grph.add( ( columnNod, propType, rdflib.Literal(typeNam) ) )

	cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT",[propColumn])

if __name__ == '__main__':
	Main()
