#!/usr/bin/python

"""
ODBC table columns
"""

import sys
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
    cgiEnv = lib_common.CgiEnv()

    grph = cgiEnv.GetGraph()

    dsnNam = survol_odbc_dsn.GetDsnNameFromCgi(cgiEnv)
    tabNam = cgiEnv.m_entity_id_dict["Table"]

    sys.stderr.write("dsn=%s tabNam=%s\n" % (dsnNam, tabNam ) )

    nodeDsn = survol_odbc_dsn.MakeUri( dsnNam )
    nodTab = survol_odbc_table.MakeUri( dsnNam, tabNam )

    # ('C:\\Program Files (x86)\\Microsoft Visual Studio 8\\Crystal Reports\\Samples\\en\\Databases\\xtreme', None, 'MSysAccessObjects', 'SYSTEM TABLE', None)

    ODBC_ConnectString = survol_odbc_dsn.MakeOdbcConnectionString(dsnNam)

    try:
        cnxn = pyodbc.connect(ODBC_ConnectString)
        DEBUG("Connected: %s", dsnNam)
        cursor = cnxn.cursor()

        cursor.columns(table=tabNam)
        sys.stderr.write("Tables OK: %s\n" % dsnNam)
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
        colList = ( "Catalog", "Schema", "Table", "Column", "Data type",
                    "Type","Size","Length","Digits", "Radix",
                    "Nullable","Remarks", "Column def", "Sql type", "Datetime sub",
                    "char octet length", "Ordinal", "is nullable")

        for row in rows:
            # TODO: What are the other properties ??
            tabNam = row.table_name
            # sys.stderr.write("tabNam=%s\n" % tabNam)

            nodColumn = survol_odbc_column.MakeUri( dsnNam, tabNam, row[3] )
            grph.add( (nodTab, pc.property_odbc_column, nodColumn ) )

            for idxCol in ( 5, 11, 12, 13, 17):
                # grph.add( (nodColumn, lib_common.NodeLiteral(colList[idxCol]), lib_common.NodeLiteral(row[idxCol]) ) )
                grph.add( (nodColumn, lib_common.MakeProp(colList[idxCol]), lib_common.NodeLiteral(row[idxCol]) ) )

    except Exception:
        exc = sys.exc_info()[0]
        lib_common.ErrorMessageHtml("nodeDsn=%s Unexpected error:%s" % ( dsnNam, str( exc ) ) )


    # cgiEnv.OutCgiRdf()
    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_odbc_column] )

if __name__ == '__main__':
	Main()

# http://www.easysoft.com/developer/languages/python/pyodbc.html
