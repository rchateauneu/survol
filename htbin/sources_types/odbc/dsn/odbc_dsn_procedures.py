#!/usr/bin/python

"""
Procedures for ODBC DSN
"""

import sys
import rdflib
import lib_util
import lib_common
from lib_properties import pc
from sources_types import odbc as survol_odbc
from sources_types.odbc import dsn as survol_dsn

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

    ODBC_ConnectString = survol_dsn.MakeOdbcConnectionString(dsnNam)

    try:
        cnxn = pyodbc.connect(ODBC_ConnectString)
        sys.stderr.write("Connected: %s\n" % dsnNam)
        cursor = cnxn.cursor()

        # http://pyodbc.googlecode.com/git/web/docs.html
        colList = ( "Catalog", "Schema", "Procedure", "Inputs", "Outputs", "Result", "Remarks", "Type")

        # This avoids cursor.fetchall()
        for row in cursor.procedures():
            # TODO: What are the other properties ??
            procNam = row[2]
            # sys.stderr.write("tabNam=%s\n" % tabNam)

            nodProc = lib_common.gUriGen.OdbcProcedureUri( dsnNam, procNam )
            grph.add( (nodeDsn, pc.property_odbc_procedure, nodProc ) )

            for idxCol in (3, 4, 5, 6, 7):
                grph.add( (nodProc, rdflib.Literal(colList[idxCol]), rdflib.Literal(row[idxCol]) ) )

    except Exception:
        exc = sys.exc_info()[0]
        lib_common.ErrorMessageHtml("nodeDsn=%s Unexpected error:%s" % ( dsnNam, str( sys.exc_info()[0] ) ) )


    # cgiEnv.OutCgiRdf(grph)
    cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT", [pc.property_odbc_procedure] )

if __name__ == '__main__':
	Main()



# http://www.easysoft.com/developer/languages/python/pyodbc.html
