#!/usr/bin/python

"""
Tables for ODBC DSN
"""

import sys
import lib_util
import lib_common
from lib_properties import pc
# from sources_types import odbc as survol_odbc
from sources_types.odbc import dsn as survol_odbc_dsn
from sources_types.odbc import table as survol_odbc_table

try:
    import pyodbc
except ImportError:
    lib_common.ErrorMessageHtml("pyodbc Python library not installed")

def Main():
    cgiEnv = lib_common.CgiEnv()

    grph = cgiEnv.GetGraph()

    dsnNam = cgiEnv.m_entity_id_dict["Dsn"]

    sys.stderr.write("dsn=(%s)\n" % dsnNam )

    nodeDsn = survol_odbc_dsn.MakeUri( dsnNam )

    ODBC_ConnectString = survol_odbc_dsn.MakeOdbcConnectionString(dsnNam)

    try:
        cnxn = pyodbc.connect(ODBC_ConnectString)
        sys.stderr.write("Connected: %s\n" % dsnNam)
        cursor = cnxn.cursor()

        # http://pyodbc.googlecode.com/git/web/docs.html
        # Type: 'TABLE','VIEW','SYSTEM TABLE','GLOBAL TEMPORARY','LOCAL TEMPORARY','ALIAS','SYNONYM',
        # or a data source-specific type name.
        colList = ( "Catalog", "Schema", "Table", "Type")

        # This avoids cursor.fetchall()
        for row in cursor.tables():
            # TODO: What are the other properties ??
            tabNam = row.table_name
            # sys.stderr.write("tabNam=%s\n" % tabNam)

            nodTab = survol_odbc_table.MakeUri( dsnNam, tabNam )
            grph.add( (nodeDsn, pc.property_odbc_table, nodTab ) )

            for idxCol in ( 0, 1, 3):
                grph.add( (nodTab, lib_common.NodeLiteral(colList[idxCol]), lib_common.NodeLiteral(row[idxCol]) ) )

    except Exception:
        sys.stderr.write("tabNam=%s\n" % str(sys.exc_info()))
        exc = sys.exc_info()[0]
        lib_common.ErrorMessageHtml("nodeDsn=%s Unexpected error:%s" % ( dsnNam, str( sys.exc_info() ) ) )


    # cgiEnv.OutCgiRdf()
    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_odbc_table] )

if __name__ == '__main__':
	Main()



# http://www.easysoft.com/developer/languages/python/pyodbc.html
