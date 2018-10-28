# This scripts theoretically runs a SQL query.
# It is used for two types of tests:
# - Searching for SQL queries stored in files.
# - Searching for SQL queries in the memory of a process.

import sys

print("Subprocess ",__file__)

sqlQuery1 = "select * from 'AnyTable'"
sqlQuery2 = "select a,b,c from 'AnyTable'"
sqlQuery3 = "select A.x,B.y from AnyTable A, OtherTable B"

if sys.version_info >= (3,):
	input("Press return to stop")
else:
	raw_input("Press return to stop")
