"""
Open Database Connectivity concepts
"""

# ('C:\\Program Files (x86)\\Microsoft Visual Studio 8\\Crystal Reports\\Samples\\en\\Databases\\xtreme', None, 'MSysAccessObjects', 'SYSTEM TABLE', None)
# connectString = 'Driver={Microdsoft ODBC for Oracle};Server=<host>:<port>/<db>.<host>;uid= <username>;pwd=<password>'
# cnxn = pyodbc.connect(connectString)

# "ODBC;DSN=TMA;UID=tmar;PWD=myPASSWORD;DBQ=tma;DBA= W;APA=T;PFC=1;TLO=0;DATABASE="

# ODBC_ConnectString = "DSN=%s" % dsnNam
# Ca fonctionne:
# dsnNam="MyOracleDataSource"

# This works when giving the DATABASE, or not.
# ODBC_ConnectString = 'DSN=%s;UID=system;PWD=troulala;DATABASE="XE"' % dsnNam
# ODBC_ConnectString = 'DSN=%s;UID=system;PWD=troulala' % dsnNam

#	"odbc/dsn"                               : ( "tab",       "#CCFF11", "#CCFF11", 0, False ),
#	"odbc/table"                             : ( "tab",       "#11FF11", "#CCFF11", 0, False ),
#	"odbc/column"                            : ( "tab",       "#11FF11", "#44FF11", 0, False ),
#	"odbc/procedure"                         : ( "tab",       "#11FF11", "#CC4411", 0, False ),


def Graphic_shape():
	return "tab"

def Graphic_colorfill():
	return "#CCFF11"

def Graphic_colorbg():
	return "#CCFF11"

def Graphic_border():
	return 0

def Graphic_is_rounded():
	return True
