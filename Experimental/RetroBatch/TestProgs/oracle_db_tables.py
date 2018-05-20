#!/usr/bin/python

# When run with this strace command:
# strace -q -qq -f -tt -T -s 20 -y -yy -e trace=desc,ipc,process,network,memory python TestProgs/oracle_db_schemas.py
# it issues the error message:
# "ORA-12547: TNS:lost contact"
#
# A possible cause is the "-f" flag for following subprocesses.
#
# It also happens with the ltrace command, even without the "-f" option:
#
# ltrace -tt -T -S -s 200 -e -*+getenv+*@SYS python TestProgs/oracle_db_schemas.py
#
# No explanation yet.

import sys
import cx_Oracle

def ExecuteQuery(conn_str,sql_query):
    result = []

    conn = cx_Oracle.connect(conn_str)

    c = conn.cursor()

    c.execute(sql_query)

    try:
        # This could be much faster but not important now.
        for row in c:
            result.append( row )

    except cx_Oracle.DatabaseError:
        pass
    conn.close()

    return result

strConnect = "scott/tiger"

sql_query_tables = "select table_name,tablespace_name from all_tables"
result_tables = ExecuteQuery( strConnect,sql_query_tables)

sys.stdout.write("About to display tables\n")
for reqtab in result_tables:
    tabnam = reqtab[0]
    sys.stdout.write("tabnam=%s\n"%str(tabnam))
    sql_query_one_tab = "select data_type,column_name,data_length from all_tab_columns where TABLE_NAME = '%s'" % tabnam
    result_cols = ExecuteQuery( strConnect,sql_query_one_tab)
    for colnam,dattyp,datlen in result_cols:
        sys.stdout.write("    colnam=%s dattyp=%s datlen=%s \n"%(colnam,dattyp,datlen))

