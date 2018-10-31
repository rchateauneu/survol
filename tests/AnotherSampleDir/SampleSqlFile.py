# This scripts theoretically runs a SQL query.
# It is used for two types of tests:
# - Searching for SQL queries stored in files.
# - Searching for SQL queries in the memory of a process.

import sys

sqlQuery1 = "select * from 'AnyTable'"
sqlQuery2 = "select a,b,c from 'AnyTable'"
sqlQuery3 = "select A.x,B.y from AnyTable A, OtherTable B"

sqlQuery4 = b"select * from 'AnyTable'"

sys.stdout.write("Starting subprocess %s\n"%__file__)
sys.stdout.flush()

xx = sys.stdin.read()

print(sqlQuery1,sqlQuery2,sqlQuery3,sqlQuery4)

exit(123)