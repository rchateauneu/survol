# The goal of this test is to handle an ODBC connection string on a flat file,
# and tests basic features of Survol for ODBC.
# Specifically, the intention is to check processing of CGI values which must
# be not only compressed with base64 but also processed by extracting user/password
# from ODBC connection strings.


import os
import pyodbc

# Present on both machines:
# Dsn="DSN=Excel Files"
# Dsn="DSN=MS Access Database"

def test_text_odbc_driver():
    text_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Test_ODBC_SampleFile.csv')
    print("text_file=" + text_file)
    # connection_string = r'Driver={Microsoft Access Text Driver (*.txt; *.csv)};DBQ=' + text_file + ';Extensions=asc,csv,tab,txt;'
    # connection_string = r'Driver={Microsoft Access Text Driver (*.txt, *.csv)};DBQ=' + text_file
    connection_string = r'Driver={Microsoft Access Text Driver (*.txt, *.csv)};DBQ=' + text_file + ';Extensions=asc,csv,tab,txt;'
    print("connection_string=" + connection_string)
    conn = pyodbc.connect(connection_string)

    c = conn.cursor()

    sql_query = "select * from AssetItems"

    c.execute(sql_query)

    for the_row in c.fetchall():
        print(the_row)
    print("Finished")


def test_access_database():
    # File taken from https://www.599cd.com/access/studentdatabases/

    # cn = pyodbc.connect('DRIVER={ODBC Driver 13 for SQL Server};SERVER=192.168.0.14;PORT=1433;UID=essaisql;PWD=xyz')

    # ('IM002', '[IM002] [Microsoft][ODBC Driver Manager] Data source name not found and no default driver specified (0) (SQLDriverConnect)')
    # connection_string = r'Driver={Microsoft Access Driver (*.mdb, *.accdb)};DBQ=' + curr_dir + 'PCResale_Customer_Database.accdb;'

    # ('IM002', '[IM002] [Microsoft][ODBC Driver Manager] Data source name not found and no default driver specified (0) (SQLDriverConnect)')
    #connection_string = r'Driver={Microsoft Access Driver (*.mdb, *.accdb)};DBQ=' \
    #                    + curr_dir + 'PCResale_Customer_Database.accdb;Provider=MSDASQL;'

    # Maybe this is Python in 64 accessing a 32 bits driver.
    accdb_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Test_ODBC_SampleFile.accdb')
    connection_string = r'Driver={Microsoft Access Driver (*.mdb, *.accdb)};DBQ=' + accdb_file

    # Provider=MSDASQL
    print("connection_string=" + connection_string)
    conn = pyodbc.connect(connection_string)

    c = conn.cursor()

    sql_query = "select * from FirstTable"

    c.execute(sql_query)

    for the_row in c.fetchall():
        print(the_row)
    print("Finished")
    print("")

# Win 7, Python 2.7 and Python 3.6
#   SQL Server
#   SQL Server Native Client 11.0
#   Oracle in XE
#   MySQL ODBC 5.3 ANSI Driver
#   MySQL ODBC 5.3 Unicode Driver

print("Drivers", "\n" + "\n".join(pyodbc.drivers()))
print("")
test_text_odbc_driver()
test_access_database()
