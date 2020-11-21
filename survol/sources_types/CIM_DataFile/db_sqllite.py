#!/usr/bin/env python

"""
Parse Sqlite database
"""

import sys
import lib_common
from sources_types import sqlite
from sources_types.sqlite import file as sqlite_file

def Usable(entity_type,entity_ids_arr):
	"""Can run on a Sqlite database only"""
	filNam = entity_ids_arr[0]
	return sqlite.IsSqliteDatabase(filNam)


# We could simply in AddInfo, add a link to "sqlite/file".
def Main():
	cgiEnv = lib_common.CgiEnv()

	dbFilNam = cgiEnv.GetId()

	DEBUG("dbFilNam=%s",dbFilNam)

	grph = cgiEnv.GetGraph()

	filNode = lib_common.gUriGen.FileUri(dbFilNam )
	sqliteNode = sqlite_file.MakeUri(dbFilNam)

	grph.add( ( sqliteNode, lib_common.MakeProp("Storage file"), filNode ) )

	sqlite.AddNodesTablesViews(grph,sqliteNode,dbFilNam)

	cgiEnv.OutCgiRdf("LAYOUT_SPLINE")

if __name__ == '__main__':
	Main()
