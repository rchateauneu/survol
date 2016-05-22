#!/usr/bin/python

"""
Tables for ODBC DSN
"""

import sys
import rdflib
import lib_util
import lib_common
from lib_properties import pc

try:
    import pyodbc
except ImportError:
    lib_common.ErrorMessageHtml("pyodbc Python library not installed")

def Main():
    cgiEnv = lib_common.CgiEnv()

    grph = rdflib.Graph()

    dsnNam = cgiEnv.m_entity_id_dict["Dsn"]

    sys.stderr.write("dsn=(%s)\n" % dsnNam )

    nodeDsn = lib_common.gUriGen.OdbcDsnUri( dsnNam )

    # ('C:\\Program Files (x86)\\Microsoft Visual Studio 8\\Crystal Reports\\Samples\\en\\Databases\\xtreme', None, 'MSysAccessObjects', 'SYSTEM TABLE', None)

    try:
        cnxn = pyodbc.connect("DSN=%s" % dsnNam)
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

            nodTab = lib_common.gUriGen.OdbcTableUri( dsnNam, tabNam )
            grph.add( (nodeDsn, pc.property_odbc_table, nodTab ) )

            for idxCol in ( 0, 1, 3):
                grph.add( (nodTab, rdflib.Literal(colList[idxCol]), rdflib.Literal(row[idxCol]) ) )

    except Exception:
        exc = sys.exc_info()[0]
        lib_common.ErrorMessageHtml("nodeDsn=%s Unexpected error:%s" % ( dsnNam, str( sys.exc_info()[0] ) ) )


    # cgiEnv.OutCgiRdf(grph)
    cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT", [pc.property_odbc_table] )

if __name__ == '__main__':
	Main()



# http://www.easysoft.com/developer/languages/python/pyodbc.html
