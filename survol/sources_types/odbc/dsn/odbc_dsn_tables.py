#!/usr/bin/env python

"""
Tables for ODBC DSN
"""

import sys
import logging
import lib_util
import lib_common
from lib_properties import pc
from sources_types.odbc import dsn as survol_odbc_dsn
from sources_types.odbc import table as survol_odbc_table

try:
    import pyodbc
except ImportError:
    lib_common.ErrorMessageHtml("pyodbc Python library not installed")


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    dsn_nam = survol_odbc_dsn.GetDsnNameFromCgi(cgiEnv)

    logging.debug("dsn=(%s)", dsn_nam)

    node_dsn = survol_odbc_dsn.MakeUri(dsn_nam)

    odbc_connect_string = survol_odbc_dsn.MakeOdbcConnectionString(dsn_nam)

    try:
        cnxn = pyodbc.connect(odbc_connect_string)
        logging.debug("Connected: %s", dsn_nam)
        cursor = cnxn.cursor()

        # http://pyodbc.googlecode.com/git/web/docs.html
        # Type: 'TABLE','VIEW','SYSTEM TABLE','GLOBAL TEMPORARY','LOCAL TEMPORARY','ALIAS','SYNONYM',
        # or a data source-specific type name.
        map_index_to_prop = {
             0: pc.property_odbc_catalog,
             1: pc.property_odbc_schema,
             # 3: pc.property_odbc_table,
             3: pc.property_odbc_type }

        # This avoids cursor.fetchall()
        for row in cursor.tables():
            # TODO: What are the other properties ??
            tab_nam = row.table_name

            nod_tab = survol_odbc_table.MakeUri(dsn_nam, tab_nam)
            grph.add((node_dsn, pc.property_odbc_table, nod_tab))

            # This prints only some columns.
            for idx_col in map_index_to_prop:
                predicate_node = map_index_to_prop[idx_col]
                grph.add((nod_tab, predicate_node, lib_util.NodeLiteral(row[idx_col])))

    except Exception as exc:
        lib_common.ErrorMessageHtml("node_dsn=%s Unexpected error:%s" % (dsn_nam, str(exc)))

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_odbc_table] )


if __name__ == '__main__':
	Main()

# http://www.easysoft.com/developer/languages/python/pyodbc.html
