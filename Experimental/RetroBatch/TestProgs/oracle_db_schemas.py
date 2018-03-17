#!/usr/bin/python

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

