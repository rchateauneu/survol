"""
sqlite objects
"""

import os
import sys
import logging
import lib_common
import lib_util
from lib_properties import pc

import sqlite3

def Graphic_shape():
    return "none"


def Graphic_colorfill():
    return "#EEAAAA"


def Graphic_colorbg():
    return "#FFCC66"


def Graphic_border():
    return 2


def Graphic_is_rounded():
    return True


# Tells if a file is a sqlite databse.
def IsSqliteDatabase(fil_nam):
    # TODO: Checking the file extension may not be enough and we should check the content.
    filExt = os.path.splitext(fil_nam)[1]
    return filExt.upper() in [".SQLITE",".SQLITE2",".SQLITE3",".DB"]


# This basically returns a list of the sqlite files accessed by the process.
# It is used to deduce which sqlite file is accessed by a query.
def DatabaseEnvParams(process_id):
    # This is imported here to avoid circular references.
    from sources_types import CIM_Process

    logging.debug("\nDatabaseEnvParams process_id=%s", str(process_id))
    # Get the list of files open by the process.
    try:
        proc_obj = CIM_Process.PsutilGetProcObj(int(process_id))
        fillist = proc_obj.open_files()
    except Exception as exc:
        lib_common.ErrorMessageHtml("Caught:" + str(exc) +": process_id=" + str(process_id))

    list_args = []
    for fil_obj in fillist:
        fil_nam = fil_obj.path
        logging.debug("DatabaseEnvParams process_id=%s fil_nam=%s", str(process_id), fil_nam)
        if IsSqliteDatabase(fil_nam):
            logging.debug("DatabaseEnvParams ADDING fil_nam=%s", fil_nam)
            filNamClean = lib_util.standardized_file_path(fil_nam)
            filDef = {"File": filNamClean}
            list_args.append(filDef)

    logging.debug("DatabaseEnvParams len=%d\n", len(list_args))

    return ("sqlite/query", list_args)


def AddNodesTablesViews(grph, fil_node, db_fil_nam):

    # This is imported here to avoid circular references of packages including themselves.
    from sources_types.sqlite import table as sqlite_table
    from sources_types.sqlite import view as sqlite_view

    logging.debug("AddNodesTablesViews db_fil_nam=%s", db_fil_nam)
    try:
        con = sqlite3.connect(db_fil_nam)
        cursor = con.cursor()
        # type TEXT,
        # name TEXT,
        # tbl_name TEXT,
        # rootpage INTEGER,
        # sql TEXT
        cursor.execute("SELECT * FROM sqlite_master WHERE type='table' or type='view';")

        #[(u'table', u'tz_schema_version', u'tz_schema_version', 2, u'CREATE TABLE tz_schema_version (version INTEGER)'),

        for the_row in cursor.fetchall():
            the_type = the_row[0]
            the_name = the_row[1]
            if the_type == 'table':
                name_nod = sqlite_table.MakeUri(db_fil_nam, the_name)
                grph.add((fil_node, lib_common.MakeProp("Table"), name_nod))
            elif the_type == 'view':
                name_nod = sqlite_view.MakeUri(db_fil_nam, the_name)
                grph.add((fil_node, lib_common.MakeProp("View"), name_nod))
            else:
                continue

            theRootpage = the_row[3]
            grph.add((name_nod, lib_common.MakeProp("Root page"), lib_util.NodeLiteral(theRootpage)))
            grph.add((name_nod, lib_common.MakeProp("Type"), lib_util.NodeLiteral(the_type)))

            # Do not print too much information in case there are too many tables.
            #theCmd = the_row[4]
            #grph.add( ( tabNod, pc.property_information, lib_util.NodeLiteral(theCmd) ) )
    except sqlite3.DatabaseError as exc:
        lib_common.ErrorMessageHtml("Sqlite file:%s Caught:%s" % (db_fil_nam, str(exc)))
    except Exception as exc:
        lib_common.ErrorMessageHtml("Sqlite file:%s Unexpected error:%s" % (db_fil_nam, str(exc)))


# Because sqlite filename are very long so we shorten name when displaying.
def ShortenSqliteFilename(file_name):
    return os.path.basename(file_name)
