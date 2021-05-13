# The goal of this test is to handle an ODBC connection string on a flat file,
# and tests basic features of Survol for ODBC.
# Specifically, the intention is to check processing of CGI values which must
# be not only compressed with base64 but also processed by extraing user/password
# from ODBC connection strings.

# https://www.connectionstrings.com/textfile/
# Provider=Microsoft.Jet.OLEDB.4.0;Data Source=c:\txtFilesFolder\;Extended Properties="text;HDR=Yes;FMT=Delimited";

# DbConnection connection = new OleDbConnection();
# connection.ConnectionString = "Provider=Microsoft.ACE.OLEDB.12.0;Data Source=C:\\Documents;Extended Properties=\"Text;HDR=Yes\"";
# connection.Open();
# DbCommand cmd;
#
# cmd = connection.CreateCommand();
# cmd.CommandText = "SELECT * FROM [Mappe1#csv]";
# DbDataReader reader = cmd.ExecuteReader();
#
# while (reader.Read())
# {
#     for (int i = 0; i < reader.FieldCount; i++)
#         Console.Write("(" + reader.GetValue(i).ToString() + ")");
#
#     Console.WriteLine();
# }
#
# cmd.Dispose();
# connection.Dispose();
# Console.WriteLine("Done");
# Console.ReadKey();

import pyodbc

curr_dir = "C:\\Users\\rchateau\\Developpement\\ReverseEngineeringApps\\PythonStyle\\Experimental\\"

# https://www.connectionstrings.com/microsoft-text-odbc-driver/

def test_text_odbc_driver():
    connection_string = r'Driver={Microsoft Text Driver (*.txt; *.csv)};Dbq=' + curr_dir + 'odbc_sample.csv;Extensions=asc,csv,tab,txt;'
    print("connection_string=" + connection_string)
    conn = pyodbc.connect(connection_string)

    c = conn.cursor()

    sql_query = "select * from A"

    c.execute(sql_query)

    for the_row in c.fetchall():
        print(the_row)

    print("Finished")

def test_text_file():
    connection_string = r'Provider=Microsoft.Jet.OLEDB.4.0;Data Source=' + curr_dir + ';Extended Properties="text;HDR=Yes;FMT=Delimited";'
    print("connection_string=" + connection_string)
    conn = pyodbc.connect(connection_string)

    c = conn.cursor()

    sql_query = "select * "

    c.execute(sql_query)

    for the_row in c.fetchall():
        print(the_row)

    print("Finished")

# >>> pyodbc.drivers()
# ['SQL Server', 'SQL Server Native Client 11.0', 'Oracle in XE', 'MySQL ODBC 5.3 ANSI Driver',
# 'MySQL ODBC 5.3 Unicode Driver']

# Windows 10
# >>> pyodbc.drivers()
# ['SQL Server', 'ODBC Driver 17 for SQL Server', 'Microsoft Access Driver (*.mdb, *.accdb)',
# 'Microsoft Excel Driver (*.xls, *.xlsx, *.xlsm, *.xlsb)', 'Microsoft Access Text Driver (*.txt, *.csv)']

# Other possibility
def test_access_database():
    # File taken from https://www.599cd.com/access/studentdatabases/

    # cn = pyodbc.connect('DRIVER={ODBC Driver 13 for SQL Server};SERVER=192.168.0.14;PORT=1433;UID=essaisql;PWD=xyz')

    # ('IM002', '[IM002] [Microsoft][ODBC Driver Manager] Data source name not found and no default driver specified (0) (SQLDriverConnect)')
    # connection_string = r'Driver={Microsoft Access Driver (*.mdb, *.accdb)};DBQ=' + curr_dir + 'PCResale_Customer_Database.accdb;'

    # ('IM002', '[IM002] [Microsoft][ODBC Driver Manager] Data source name not found and no default driver specified (0) (SQLDriverConnect)')
    #connection_string = r'Driver={Microsoft Access Driver (*.mdb, *.accdb)};DBQ=' \
    #                    + curr_dir + 'PCResale_Customer_Database.accdb;Provider=MSDASQL;'

    # Maybe this is Python in 64 accessing a 32 bits driver.
    connection_string = r'Driver={Microsoft Access Driver (*.mdb, *.accdb)};DBQ=' \
                        + curr_dir + 'PCResale_Customer_Database.accdb;Uid=;Pwd=;'

    # Provider=MSDASQL
    print("connection_string=" + connection_string)
    conn = pyodbc.connect(connection_string)

    c = conn.cursor()

    sql_query = "select * from CustomerT"

    c.execute(sql_query)

    for the_row in c.fetchall():
        print(the_row)

    print("Finished")

# test_text_odbc_driver()
test_access_database()