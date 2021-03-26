#!/usr/bin/env python

"""
Columns of Sqlite table.
"""

import os
import os.path
import sys

import sqlite3

import lib_uris
import lib_util
import lib_common
from sources_types import sqlite
from sources_types.sqlite import table as sqlite_table
from sources_types.sqlite import column as sqlite_column


def Usable(entity_type,entity_ids_arr):
    """Can run on a Sqlite database only"""
    fil_nam = entity_ids_arr[0]
    return sqlite.IsSqliteDatabase(fil_nam)


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    table_name = cgiEnv.m_entity_id_dict["Table"]
    db_fil_nam = cgiEnv.m_entity_id_dict["File"]

    grph = cgiEnv.GetGraph()

    fil_node = lib_uris.gUriGen.FileUri(db_fil_nam)
    tab_nod = sqlite_table.MakeUri(db_fil_nam, table_name)
    grph.add((tab_nod, lib_common.MakeProp("Table"), fil_node))

    con = sqlite3.connect(db_fil_nam)
    cursor = con.cursor()

    #>>> eta = curs.execute("PRAGMA table_info('tz_data')")
    #(0, u'tzid', u'TEXT', 0, None, 0)
    #(1, u'alias', u'TEXT', 0, None, 0)

    try:
        cursor.execute("PRAGMA table_info('%s')" % table_name)

        prop_column = lib_common.MakeProp("Column")
        prop_type = lib_common.MakeProp("Type")
        for the_row in cursor.fetchall():
            column_nam = the_row[1]
            column_nod = sqlite_column.MakeUri(db_fil_nam, table_name, column_nam)
            grph.add((tab_nod, prop_column, column_nod))
            type_nam = the_row[2]
            grph.add((column_nod, prop_type, lib_util.NodeLiteral(type_nam)))
    except Exception as exc:
        lib_common.ErrorMessageHtml("Error %s:%s" % (db_fil_nam, str(exc)))

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [prop_column])


if __name__ == '__main__':
    Main()
