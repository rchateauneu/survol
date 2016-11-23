#!/usr/bin/python

"""
Columns of Sqlite table.
"""

import os
import os.path
import sys
import rdflib
import lib_common
import sqlite3
from sources_types import sqlite
from sources_types.sqlite import table as sqlite_table
from sources_types.sqlite import column as sqlite_column

def Usable(entity_type,entity_ids_arr):
	"""Can run on a Sqlite database only"""
	filNam = entity_ids_arr[0]
	return sqlite.IsSqliteDatabase(filNam)

def Main():
	cgiEnv = lib_common.CgiEnv()

	tableName = cgiEnv.m_entity_id_dict["Table"]
	dbFilNam = cgiEnv.m_entity_id_dict["File"]

	# sys.stderr.write("dbFilNam=%s\n"%dbFilNam)

	grph = rdflib.Graph()

	filNode = lib_common.gUriGen.FileUri(dbFilNam )
	tabNod = sqlite_table.MakeUri(dbFilNam,tableName)
	grph.add( ( tabNod, lib_common.MakeProp("Table"), filNode ) )

	con = sqlite3.connect(dbFilNam)
	cursor = con.cursor()

	#>>> eta = curs.execute("PRAGMA table_info('tz_data')")
	#(0, u'tzid', u'TEXT', 0, None, 0)
	#(1, u'alias', u'TEXT', 0, None, 0)

	try:
		cursor.execute("PRAGMA table_info('%s')" % tableName )

		propColumn = lib_common.MakeProp("Column")
		propType = lib_common.MakeProp("Type")
		for theRow in cursor.fetchall():
			columnNam = theRow[1]
			columnNod = sqlite_column.MakeUri(dbFilNam,tableName,columnNam)
			grph.add( ( tabNod, propColumn, columnNod ) )
			typeNam = theRow[2]
			grph.add( ( columnNod, propType, rdflib.Literal(typeNam) ) )
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Error %s:%s"%(dbFilNam,str(exc)))


	cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT",[propColumn])

if __name__ == '__main__':
	Main()
