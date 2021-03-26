#!/usr/bin/env python

"""
Parse Sqlite database
"""

import sys
import logging

import lib_uris
import lib_common
from sources_types import sqlite
from sources_types.sqlite import file as sqlite_file


def Usable(entity_type, entity_ids_arr):
	"""Can run on a Sqlite database only"""
	fil_nam = entity_ids_arr[0]
	return sqlite.IsSqliteDatabase(fil_nam)


# We could simply in AddInfo, add a link to "sqlite/file".
def Main():
	cgiEnv = lib_common.ScriptEnvironment()

	db_fil_nam = cgiEnv.GetId()

	logging.debug("db_fil_nam=%s", db_fil_nam)

	grph = cgiEnv.GetGraph()

	fil_node = lib_uris.gUriGen.FileUri(db_fil_nam)
	sqlite_node = sqlite_file.MakeUri(db_fil_nam)

	grph.add((sqlite_node, lib_common.MakeProp("Storage file"), fil_node))

	sqlite.AddNodesTablesViews(grph,sqlite_node, db_fil_nam)

	cgiEnv.OutCgiRdf("LAYOUT_SPLINE")


if __name__ == '__main__':
	Main()
