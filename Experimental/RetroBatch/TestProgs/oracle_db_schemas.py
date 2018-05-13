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

    sys.stderr.write("ExecuteQuery %s\n" % sql_query)
    c.execute(sql_query)

    try:
        # This could be much faster but not important now.
        for row in c:
            # Use yield ? Or return c ?
            result.append( row )

    except cx_Oracle.DatabaseError:
        pass
    conn.close()

    return result


strConnect = "scott/tiger"

sql_query = "select username, user_id from all_users"
result = ExecuteQuery( strConnect,sql_query)

for row in result:
    sys.stderr.write("row=" + str(row) + "\n")

