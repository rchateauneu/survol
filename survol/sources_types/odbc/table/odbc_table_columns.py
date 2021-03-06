#!/usr/bin/env python

"""
ODBC table columns
"""

import sys
import logging

import lib_util
import lib_common
from lib_properties import pc
from sources_types.odbc import dsn as survol_odbc_dsn
from sources_types.odbc import table as survol_odbc_table
from sources_types.odbc import column as survol_odbc_column

try:
    import pyodbc
except ImportError:
    lib_common.ErrorMessageHtml("pyodbc Python library not installed")


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    dsn_nam = survol_odbc_dsn.GetDsnNameFromCgi(cgiEnv)
    tab_nam = cgiEnv.m_entity_id_dict["Table"]

    logging.debug("dsn=%s tab_nam=%s", dsn_nam, tab_nam)

    nodTab = survol_odbc_table.MakeUri( dsn_nam, tab_nam)

    # ('C:\\Program Files (x86)\\Microsoft Visual Studio 8\\Crystal Reports\\Samples\\en\\Databases\\xtreme', None, 'MSysAccessObjects', 'SYSTEM TABLE', None)

    odbc_connect_string = survol_odbc_dsn.MakeOdbcConnectionString(dsn_nam)

    try:
        cnxn = pyodbc.connect(odbc_connect_string)
        logging.debug("Connected: %s", dsn_nam)
        cursor = cnxn.cursor()

        cursor.columns(table=tab_nam)
        logging.debug("Tables OK: %s", dsn_nam)
        rows = cursor.fetchall()

        # http://pyodbc.googlecode.com/git/web/docs.html
        #
        # table_cat
        # table_schem
        # table_name
        # column_name
        # data_type
        # type_name
        # column_size
        # buffer_length
        # decimal_digits
        # num_prec_radix
        # nullable
        # remarks
        # column_def
        # sql_data_type
        # sql_datetime_sub
        # char_octet_length
        # ordinal_position
        # is_nullable: One of SQL_NULLABLE, SQL_NO_NULLS, SQL_NULLS_UNKNOWN.

        # or a data source-specific type name.
        col_list = ("Catalog", "Schema", "Table", "Column", "Data type",
                    "Type","Size","Length","Digits", "Radix",
                    "Nullable","Remarks", "Column def", "Sql type", "Datetime sub",
                    "char octet length", "Ordinal", "is nullable")

        for row in rows:
            # TODO: What are the other properties ??
            tab_nam = row.table_name

            nod_column = survol_odbc_column.MakeUri(dsn_nam, tab_nam, row[3])
            grph.add((nodTab, pc.property_odbc_column, nod_column))

            for idx_col in (5, 11, 12, 13, 17):
                grph.add((nod_column, lib_common.MakeProp(col_list[idx_col]), lib_util.NodeLiteral(row[idx_col])))

    except Exception as exc:
        lib_common.ErrorMessageHtml("dsn_nam=%s Unexpected error:%s" % (dsn_nam, str(exc)))

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_odbc_column])


if __name__ == '__main__':
    Main()

# http://www.easysoft.com/developer/languages/python/pyodbc.html
