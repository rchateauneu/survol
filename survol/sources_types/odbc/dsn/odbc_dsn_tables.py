#!/usr/bin/env python

"""
Tables for ODBC DSN
"""

import sys
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
    cgiEnv = lib_common.CgiEnv()

    grph = cgiEnv.GetGraph()

    dsnNam = survol_odbc_dsn.GetDsnNameFromCgi(cgiEnv)

    DEBUG("dsn=(%s)", dsnNam )

    nodeDsn = survol_odbc_dsn.MakeUri( dsnNam )

    ODBC_ConnectString = survol_odbc_dsn.MakeOdbcConnectionString(dsnNam)

    try:
        cnxn = pyodbc.connect(ODBC_ConnectString)
        DEBUG("Connected: %s", dsnNam)
        cursor = cnxn.cursor()

        # http://pyodbc.googlecode.com/git/web/docs.html
        # Type: 'TABLE','VIEW','SYSTEM TABLE','GLOBAL TEMPORARY','LOCAL TEMPORARY','ALIAS','SYNONYM',
        # or a data source-specific type name.
        mapIndexToProp = {
             0: pc.property_odbc_catalog,
             1: pc.property_odbc_schema,
             # 3: pc.property_odbc_table,
             3: pc.property_odbc_type }

        # This avoids cursor.fetchall()
        for row in cursor.tables():
            # TODO: What are the other properties ??
            tabNam = row.table_name

            nodTab = survol_odbc_table.MakeUri( dsnNam, tabNam )
            grph.add( (nodeDsn, pc.property_odbc_table, nodTab ) )

            # This prints only some columns.
            for idxCol in mapIndexToProp:
                predicateNode = mapIndexToProp[idxCol]
                grph.add( (nodTab, predicateNode, lib_common.NodeLiteral(row[idxCol]) ) )

    except Exception:
        WARNING("tabNam=%s", str(sys.exc_info()))
        exc = sys.exc_info()[0]
        lib_common.ErrorMessageHtml("nodeDsn=%s Unexpected error:%s" % ( dsnNam, str( sys.exc_info() ) ) )


    # cgiEnv.OutCgiRdf()
    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_odbc_table] )

if __name__ == '__main__':
	Main()



# http://www.easysoft.com/developer/languages/python/pyodbc.html
