# This scripts theoretically runs a SQL query.
# It is used for two types of tests:
# - Searching for SQL queries stored in files.
# - Searching for SQL queries in the memory of a process.

import os
import sys
import time

# This filename must appear in the process memory.
filepath_a = os.path.join(os.path.dirname(sys.executable), "this_is_a_file_name_with_slashes.cpp").replace("\\", "/")

sqlQuery1 = "select * from 'AnyTable'"
sqlQuery2 = "select a,b,c from 'AnyTable'"
sqlQuery3 = "select A.x,B.y from AnyTable A, OtherTable B"

sqlQuery4 = b"select * from 'AnyTable'"

sys.stdout.write("select something from somewhere\n")
sys.stdout.write("Starting subprocess: %s\n"%__file__)
sys.stdout.flush()

print(sqlQuery1,sqlQuery2,sqlQuery3,sqlQuery4)

# Short delay: This process is not suspended when reading its memory.
time.sleep(0.5)

xx = sys.stdin.read(1)


