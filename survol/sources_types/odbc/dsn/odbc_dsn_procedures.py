#!/usr/bin/env python

"""
Procedures for ODBC DSN
"""

import sys
import logging
import lib_util
import lib_common
from lib_properties import pc
from sources_types.odbc import dsn as survol_odbc_dsn
from sources_types.odbc import procedure as survol_odbc_procedure

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
        # colList = ( "Catalog", "Schema", "Procedure", "Inputs", "Outputs", "Result", "Remarks", "Type")

        # http://pyodbc.googlecode.com/git/web/docs.html
        # Type: 'TABLE','VIEW','SYSTEM TABLE','GLOBAL TEMPORARY','LOCAL TEMPORARY','ALIAS','SYNONYM',
        # or a data source-specific type name.
        map_index_to_prop = {
             #0: pc.property_odbc_catalog,
             #1: pc.property_odbc_schema,
             #2: pc.property_odbc_procedure,
             3: pc.property_odbc_inputs,
             4: pc.property_odbc_outputs,
             5: pc.property_odbc_result,
             6: pc.property_odbc_remarks,
             7: pc.property_odbc_type }

        # This avoids cursor.fetchall()
        for row in cursor.procedures():
            # TODO: What are the other properties ??
            proc_nam = row[2]

            nod_proc = survol_odbc_procedure.MakeUri(dsn_nam, proc_nam)
            grph.add((node_dsn, pc.property_odbc_procedure, nod_proc))

            # This prints only some columns.
            for idxcol in map_index_to_prop:
                predicate_node = map_index_to_prop[idxcol]
                grph.add((nod_proc, predicate_node, lib_util.NodeLiteral(row[idxcol])))

    except Exception as exc:
        lib_common.ErrorMessageHtml("node_dsn=%s Unexpected error:%s" % (dsn_nam, str(exc)))

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_odbc_procedure])


if __name__ == '__main__':
    Main()

# http://www.easysoft.com/developer/languages/python/pyodbc.html
