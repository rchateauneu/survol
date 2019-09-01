#!/usr/bin/env python

"""
Procedures for ODBC DSN
"""

import sys
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
        # colList = ( "Catalog", "Schema", "Procedure", "Inputs", "Outputs", "Result", "Remarks", "Type")

        # http://pyodbc.googlecode.com/git/web/docs.html
        # Type: 'TABLE','VIEW','SYSTEM TABLE','GLOBAL TEMPORARY','LOCAL TEMPORARY','ALIAS','SYNONYM',
        # or a data source-specific type name.
        mapIndexToProp = {
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
            procNam = row[2]
            # sys.stderr.write("tabNam=%s\n" % tabNam)

            nodProc = survol_odbc_procedure.MakeUri( dsnNam, procNam )
            grph.add( (nodeDsn, pc.property_odbc_procedure, nodProc ) )

            # This prints only some columns.
            for idxCol in mapIndexToProp:
                predicateNode = mapIndexToProp[idxCol]
                grph.add( (nodProc, predicateNode, lib_common.NodeLiteral(row[idxCol]) ) )

    except Exception:
        exc = sys.exc_info()[0]
        lib_common.ErrorMessageHtml("nodeDsn=%s Unexpected error:%s" % ( dsnNam, str( sys.exc_info() ) ) )


    # cgiEnv.OutCgiRdf()
    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_odbc_procedure] )

if __name__ == '__main__':
	Main()



# http://www.easysoft.com/developer/languages/python/pyodbc.html
