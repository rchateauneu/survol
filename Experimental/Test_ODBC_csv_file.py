# The goal of this test is to handle an ODBC connection string on a flat file,
# and tests basic features of Survol for ODBC.
# Specifically, the intention is to check processing of CGI values which must
# be not only compressed with base64 but also processed by extracting user/password
# from ODBC connection strings.


import os
import pyodbc

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

# Data Source=(LocalDb)\v11.0;Initial Catalog=Data1;Integrated Security=true;AttachDBFilename=data1.mdf
#
# Data Source=(LocalDb)\v11.0;Initial Catalog=Data2;Integrated Security=true;AttachDBFilename=data2.mdf
def test_attach_db_filename():
    sql_server_filename = r'C:\Users\rchateau\Developpement\ReverseEngineeringApps\PythonStyle\Experimental\ExpressDB.mdf'
    # connection_string = r'(LocalDb)\v11.0;Initial Catalog=Data2;Integrated Security=true;AttachDBFilename=' + sql_server_filename
    # connection_string = r'Driver={SQL Server};Data Source=(LocalDb)\v11.0;AttachDBFilename=' + sql_server_filename
    # connection_string = r'data source=.\SQLEXPRESS;AttachDBFilename=' + sql_server_filename
    # connection_string = r'Server=192.168.0.1;data source=.\SQLEXPRESS;Integrated Security=SSPI;User Instance=true;Database=' + sql_server_filename
    #connection_string = r'Server=192.168.0.1;Integrated Security=SSPI;User Instance=true;Database=' + sql_server_filename
    #connection_string = r'Driver={SQL Server};Server=192.168.0.1;Integrated Security=SSPI;User Instance=true;Database=toto;AttachDBFilename=' + sql_server_filename
    #connection_string = r'Driver={SQL Server};Integrated Security=SSPI;User Instance=true;Database=toto;AttachDBFilename=' + sql_server_filename
    #connection_string = r'Driver={SQL Server};Server=rchateau-hp;Integrated Security=SSPI;User Instance=true;Database=toto;AttachDBFilename=' + sql_server_filename

    # Invalid value specified for connection string attribute 'Trusted_Connection'
    connection_string = r'Driver={SQL Server Native Client 11.0};Server=rchateau-hp;Integrated Security=SSPI;' + \
                        '; Trusted_Connection=Yes' + \
                        'User Instance=true;Database=toto;AttachDBFilename=' + sql_server_filename

    # Data source name not found and no default driver specified
    connection_string = r'Data Source=(LocalDB)\MSSQLLocalDB;' + \
                        r'AttachDbFilename="|DataDirectory|%s";' % sql_server_filename + \
                        r'Integrated Security=True;Connect Timeout=30'

    # Neither DSN nor SERVER keyword supplied
    connection_string = r'Driver={SQL Server Native Client 11.0};Data Source=(LocalDB)\MSSQLLocalDB;' + \
                        r'AttachDbFilename="|DataDirectory|%s";' % sql_server_filename + \
                        r'Integrated Security=True;Connect Timeout=30'

    # Data source name not found and no default driver specified
    connection_string = r'DRIVER=ODBC Driver 11 for SQL Server;' + \
                    r'SERVER=(local)\SQLEXPRESS;' + \
                    r'Trusted_Connection=yes;' + \
                    r'AttachDbFileName=%s;' % sql_server_filename

    # pyodbc.OperationalError: ('08001', '[08001] [Microsoft][SQL Server Native Client 11.0]Named Pipes Provider: Could not open a connect
    # ion to SQL Server [2].  (2) (SQLDriverConnect); [08001] [Microsoft][SQL Server Native Client 11.0]Login timeout expired (0); [08001]
    #  [Microsoft][SQL Server Native Client 11.0]A network-related or instance-specific error has occurred while establishing a connection
    #  to SQL Server. Server is not found or not accessible. Check if instance name is correct and if SQL Server is configured to allow re
    # mote connections. For more information see SQL Server Books Online. (2)')
    #
    # Et long delai.
    connection_string = r'DRIVER={SQL Server Native Client 11.0};' + \
                    r'SERVER=(local)\SQLEXPRESS;' + \
                    r'Trusted_Connection=yes;' + \
                    r'AttachDbFileName=%s;' % sql_server_filename

    # After havong started server SqlExpress (Because it was stopped):
    # pyodbc.ProgrammingError: ('42000', '[42000] [Microsoft][SQL Server Native Client 11.0][SQL Server]An attempt to attach an auto-named
    #  database for file C:\\Users\\rchateau\\Developpement\\ReverseEngineeringApps\\PythonStyle\\Experimental\\ExpressDB.mdf failed. A da
    # tabase with the same name exists, or specified file cannot be opened, or it is located on UNC share. (15350) (SQLDriverConnect); [42
    # 000] [Microsoft][SQL Server Native Client 11.0][SQL Server]An attempt to attach an auto-named database for file C:\\Users\\rchateau\
    # \Developpement\\ReverseEngineeringApps\\PythonStyle\\Experimental\\ExpressDB.mdf failed. A database with the same name exists, or sp
    # ecified file cannot be opened, or it is located on UNC share. (15350)')


    # pyodbc.ProgrammingError: ('42000', '[42000] [Microsoft][SQL Server Native Client 11.0][SQL Server]Directory lookup for the file "C:\
    # \Users\\rchateau\\Developpement\\ReverseEngineeringApps\\PythonStyle\\Experimental\\ExpressDB.mdf" failed with the operating system
    # error 5(Access is denied.). (5133) (SQLDriverConnect); [42000] [Microsoft][SQL Server Native Client 11.0][SQL Server]Cannot attach t
    # he file \'C:\\Users\\rchateau\\Developpement\\ReverseEngineeringApps\\PythonStyle\\Experimental\\ExpressDB.mdf\' as database \'toto\
    # '. (1832); [42000] [Microsoft][SQL Server Native Client 11.0][SQL Server]Directory lookup for the file "C:\\Users\\rchateau\\Develop
    # pement\\ReverseEngineeringApps\\PythonStyle\\Experimental\\ExpressDB.mdf" failed with the operating system error 5(Access is denied.
    # ). (5133); [42000] [Microsoft][SQL Server Native Client 11.0][SQL Server]Cannot attach the file \'C:\\Users\\rchateau\\Developpement
    # \\ReverseEngineeringApps\\PythonStyle\\Experimental\\ExpressDB.mdf\' as database \'toto\'. (1832)')
    connection_string = r'DRIVER={SQL Server Native Client 11.0};' + \
                    r'SERVER=(local)\SQLEXPRESS;' + \
                    r'Trusted_Connection=yes;Database=toto;' + \
                    r'AttachDbFileName=%s;' % sql_server_filename

    # Login failed for user ''
    connection_string = r'DRIVER={SQL Server Native Client 11.0};' + \
                    r'SERVER=(local)\SQLEXPRESS;' + \
                    r'Database=toto;' + \
                    r'AttachDbFileName=%s;' % sql_server_filename

    # Invalid value specified for connection string attribute 'TrustServerCertificate'
    connection_string = r'DRIVER={SQL Server Native Client 11.0};' + \
                    r'SERVER=(local)\SQLEXPRESS;' + \
                    r'TrustServerCertificate=True;Database=toto;' + \
                    r'AttachDbFileName=%s;' % sql_server_filename

    # Same
    connection_string = r'DRIVER={SQL Server};' + \
                    r'SERVER=(local)\SQLEXPRESS;' + \
                    r'TrustServerCertificate=True;Database=toto;' + \
                    r'AttachDbFileName=%s;' % sql_server_filename

    # Data Source=.\\SQLEXPRESS;
    # AttachDbFilename=C:\\Program Files\\Microsoft SQL Server\\MSSQL11.SQLEXPRESS\\MSSQL\\DATA\\myDatabase.mdf;
    # Initial Catalog=SIGamepresenterNG;Integrated Security=True;Connect Timeout=30;Encrypt=False;
    # TrustServerCertificate=True;ApplicationIntent=ReadWrite;MultiSubnetFailover=False";

    # Data source name not found and no default driver specified
    connection_string = r'Data Source=.\\SQLEXPRESS;' + \
                    r'TrustServerCertificate=True;Database=toto;' + \
                    r'AttachDbFileName=%s;' % sql_server_filename

    # Data source name not found and no default driver specified
    connection_string = r'Data Source=.\\SQLEXPRESS;' + \
                    r'SERVER=(local)\SQLEXPRESS;' + \
                    r'TrustServerCertificate=True;Database=toto;' + \
                    r'AttachDbFileName=%s;' % sql_server_filename

    # pyodbc.ProgrammingError: ('42000', '[42000] [Microsoft][SQL Server Native Client 11.0][SQL Server]Directory lookup for the file "C:\
    # \Users\\rchateau\\Developpement\\ReverseEngineeringApps\\PythonStyle\\Experimental\\ExpressDB.mdf" failed with the operating system
    # error 5(Access is denied.). (5133) (SQLDriverConnect); [42000] [Microsoft][SQL Server Native Client 11.0][SQL Server]Cannot attach t
    # he file \'C:\\Users\\rchateau\\Developpement\\ReverseEngineeringApps\\PythonStyle\\Experimental\\ExpressDB.mdf\' as database \'toto\
    # '. (1832); [42000] [Microsoft][SQL Server Native Client 11.0][SQL Server]Directory lookup for the file "C:\\Users\\rchateau\\Develop
    # pement\\ReverseEngineeringApps\\PythonStyle\\Experimental\\ExpressDB.mdf" failed with the operating system error 5(Access is denied.
    # ). (5133); [42000] [Microsoft][SQL Server Native Client 11.0][SQL Server]Cannot attach the file \'C:\\Users\\rchateau\\Developpement
    # \\ReverseEngineeringApps\\PythonStyle\\Experimental\\ExpressDB.mdf\' as database \'toto\'. (1832)')
    connection_string = r'DRIVER={SQL Server Native Client 11.0};' + \
                    r'SERVER=(local)\SQLEXPRESS;' + \
                    r'Trusted_Connection=yes;Database=toto;' + \
                    r'Integrated Security=True; User Instance=True;' + \
                    r'AttachDbFileName=%s;' % sql_server_filename

    # Login failed for user ''
    connection_string = r'DRIVER={SQL Server Native Client 11.0};' + \
                    r'SERVER=(local)\SQLEXPRESS;' + \
                    r'Database=toto;' + \
                    r'User Instance=True;' + \
                    r'AttachDbFileName=%s;' % sql_server_filename

    # pyodbc.ProgrammingError: ('42000', '[42000] [Microsoft][SQL Server Native Client 11.0][SQL Server]Directory lookup for the file "C:\
    # \Users\\rchateau\\Developpement\\ReverseEngineeringApps\\PythonStyle\\Experimental\\ExpressDB.mdf" failed with the operating system
    # error 5(Access is denied.). (5133) (SQLDriverConnect); [42000] [Microsoft][SQL Server Native Client 11.0][SQL Server]Cannot attach t
    # he file \'C:\\Users\\rchateau\\Developpement\\ReverseEngineeringApps\\PythonStyle\\Experimental\\ExpressDB.mdf\' as database \'toto\
    # '. (1832); [42000] [Microsoft][SQL Server Native Client 11.0][SQL Server]Directory lookup for the file "C:\\Users\\rchateau\\Develop
    # pement\\ReverseEngineeringApps\\PythonStyle\\Experimental\\ExpressDB.mdf" failed with the operating system error 5(Access is denied.
    # ). (5133); [42000] [Microsoft][SQL Server Native Client 11.0][SQL Server]Cannot attach the file \'C:\\Users\\rchateau\\Developpement
    # \\ReverseEngineeringApps\\PythonStyle\\Experimental\\ExpressDB.mdf\' as database \'toto\'. (1832)')
    connection_string = r'DRIVER={SQL Server Native Client 11.0};' + \
                    r'SERVER=(local)\SQLEXPRESS;' + \
                    r'Trusted_Connection=yes;Database=toto;' + \
                    r'Integrated Security=False; User Instance=True;' + \
                    r'AttachDbFileName=%s;' % sql_server_filename

    # Login failed for user ''
    connection_string = r'DRIVER={SQL Server Native Client 11.0};' + \
                    r'SERVER=(local)\SQLEXPRESS;' + \
                    r'Database=toto;' + \
                    r'Integrated Security=False; User Instance=True;' + \
                    r'AttachDbFileName=%s;' % sql_server_filename

    # Login failed for user ''
    connection_string = r'DRIVER={SQL Server Native Client 11.0};' + \
                    r'SERVER=(local)\SQLEXPRESS;' + \
                    r'Database=toto;' + \
                    r'User=toto;' + \
                    r'Integrated Security=False; User Instance=True;' + \
                    r'AttachDbFileName=%s;' % sql_server_filename

    # Login failed for user 'toto'
    connection_string = r'DRIVER={SQL Server Native Client 11.0};' + \
                    r'SERVER=(local)\SQLEXPRESS;' + \
                    r'Database=toto;' + \
                    r'uid=toto;' + \
                    r'Integrated Security=False; User Instance=True;' + \
                    r'AttachDbFileName=%s;' % sql_server_filename

    # Login failed for user 'rchateau'
    connection_string = r'DRIVER={SQL Server Native Client 11.0};' + \
                    r'SERVER=(local)\SQLEXPRESS;' + \
                    r'Database=toto;' + \
                    r'uid=rchateau;' + \
                    r'Integrated Security=False; User Instance=True;' + \
                    r'AttachDbFileName=%s;' % sql_server_filename

    # Login failed for user 'rchateau'
    connection_string = r'DRIVER={SQL Server Native Client 11.0};' + \
                    r'SERVER=(local)\SQLEXPRESS;' + \
                    r'Database=toto;' + \
                    r'uid=rchateau;' + \
                    r'Integrated Security=True; User Instance=True;' + \
                    r'AttachDbFileName=%s;' % sql_server_filename

    print("connection_string=" + connection_string)
    conn = pyodbc.connect(connection_string)
    print("Connect OK")

    c = conn.cursor()
    print("Cursor OK")

    sql_query = "select * from FirstTable"

    c.execute(sql_query)

    for the_row in c.fetchall():
        print(the_row)
    print("Finished")

    return


def test_sql_server():
    connection_string = r'Driver={SQL Server};Server=localhost'
    print("connection_string=" + connection_string)
    conn = pyodbc.connect(connection_string)

    if False:
        print("List of tables")
        with conn.cursor() as curs:
            for x in curs.tables():
                print(x)

    sql_query = "select * from sys.all_views"
    with conn.cursor() as curs:
        curs.execute(sql_query)
        for the_row in curs.fetchall():
            print(the_row)

    print("Finished")


# Win 7, Python 2.7 and Python 3.6
#   SQL Server
#   SQL Server Native Client 11.0
#   Oracle in XE
#   MySQL ODBC 5.3 ANSI Driver
#   MySQL ODBC 5.3 Unicode Driver
# Win 10, Python 3.8
#   SQL Server
#   ODBC Driver 17 for SQL Server
#   Microsoft Access Driver (*.mdb, *.accdb)
#   Microsoft Excel Driver (*.xls, *.xlsx, *.xlsm, *.xlsb)
#   Microsoft Access Text Driver (*.txt, *.csv)

# Present on both machines, with sources = pyodbc.dataSources():
# Dsn="DSN=Excel Files"
# Dsn="DSN=MS Access Database"


print("Drivers", "\n" + "\n".join(pyodbc.drivers()))
print("")
test_sql_server()
#test_attach_db_filename()
#test_text_odbc_driver()
#test_access_database()
