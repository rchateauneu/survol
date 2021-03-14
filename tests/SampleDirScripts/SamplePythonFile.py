# This scripts theoretically runs a SQL query.
# It is used for two types of tests:
# - Searching for SQL queries stored in files.
# - Searching for SQL queries in the memory of a process.

import os
import sys
import time

# This filename must appear in the process memory.
filepath_a = os.path.join(os.path.dirname(sys.executable), "this_is_a_file_name_with_slashes.cpp").replace("\\", "/")

# These urls must appear in the process memory.
url_http_str = u"http://www.gnu.org/gnu/gnu.html"
url_http_bytes = b"https://pypi.org/help/"
url_https_bytes = b"https://www.python.org/about/"
url_https_str = u"https://www.perl.org/about.html"

sql_query1 = "select * from 'AnyTable'"
sql_query2 = "select a,b,c from 'AnyTable'"
sql_query3 = "select A.x,B.y from AnyTable A, OtherTable B"

sql_query4 = b"select * from 'AnyTable'"

sys.stdout.write("select something from somewhere\n")
sys.stdout.write("Starting subprocess: %s\n" % __file__)
sys.stdout.flush()

print("Pid=", os.getpid())
print(sql_query1)
print(sql_query2)
print(sql_query3)
print(sql_query4)

# Short delay: This process is not suspended when reading its memory.
time.sleep(0.5)

xx = sys.stdin.read(1)


