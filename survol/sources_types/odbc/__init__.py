"""
Open Database Connectivity concepts
"""

import re
import sys
import cgi
import lib_util

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




# Within a query component, the characters ";", "/", "?", ":", "@", "&", "=", "+", ",", and "$" are reserved.
# reserved    = gen-delims / sub-delims
# gen-delims  = ":" / "/" / "?" / "#" / "[" / "]" / "@"
# sub-delims  = "!" / "$" / "&" / "'" / "(" / ")"
# 		      / "*" / "+" / "," / ";" / "="


# "UID=xxx;PWD=yyy;DRIVER=zzz"
# entity.py?xid=odbc/table.Dsn=@@@@@@@@,Table=MY_TABLE
# entity.py?xid=odbc/table.Dsn:UID-xxx;PWD-yyy;DRIVER-zzz,Table:MY_TABLE
# entity.py?xid=odbc/table.Dsn:UID(xxx)-PWD(yyy)-DRIVER(zzz),Table:MY_TABLE
# entity.py?xid=odbc/table.Dsn:UID-xxx-PWD-yyy-DRIVER-zzz,Table:MY_TABLE
# On encode ou crypte (base64) les valeurs qui ne sont pas en alphanum.
# "True", "False", "true", "yes", "0", "1"
rgxTrueFalse = "[a-zA-Z01]*"

rgxUser = "\w+"

# TODO: Will not work if "=" in the password, even if it is escaped.
# Should reasonably contain more than four or five chars.
rgxPassword = ".+"

# Hexadecimal number
rgxHexa = "[0-9a-fA-F]+"

rgxNumber = "\d+"

rgxAlpha = "[a-zA-Z]+"

# Unfortunately it is not able to filter escaped equal signs.
rgxAnything = "[^=]+"

rgxFileName = rgxAnything

# The individual regular expressions do not contain the pipe character,
# because it is already used between each regular expression.

# https://www.connectionstrings.com/oracle/

mapRgxODBC = {
	"ALLOWBATCH"                  : rgxTrueFalse,              #
	"ALLOWUSERVARIABLES"          : rgxTrueFalse,              #
	"ALLOWZERODATETIME"           : rgxTrueFalse,              #
	"AUTOENLIST"                  : rgxTrueFalse,              #
	"CACHESERVERPROPERTIES"       : rgxTrueFalse,              #
	"CACHETYPE"                   : rgxAlpha,                  # "File"
	"CERTIFICATE STORE LOCATION"  : rgxUser,                   # "CurrentUser"
	"CERTIFICATE THUMBPRINT"      : rgxHexa,                   # "479436009a40f3017a145cf8479e7694d7aadef0"
	"CERTIFICATEFILE"             : rgxFileName,               # "C:\folder\client.pfx"
	"CERTIFICATEPASSWORD"         : rgxPassword,
	"CHARSET"                     : "\w+",                     # "utf8"
	"CHECKPARAMETERS"             : rgxTrueFalse,              #
	"COMMAND LOGGING"             : rgxTrueFalse,              #
	"CONNECTION ?LIFETIME"        : rgxNumber,                 # " " character is optional.
	"CONNECTION TIMEOUT"          : rgxNumber,                 #
	"CONNECTIONRESET"             : rgxTrueFalse,              #
	"CONVERTZERODATETIME"         : rgxTrueFalse,              #
	"DATA SOURCE"                 : "[a-zA-Z_0-9\\/]+",        # "C:\myFolder\myAccessFile.accdb"
															   # "|DataDirectory|\myAccessFile.accdb"
															   # "\\server\share\folder\myAccessFile.accdb"
	"DATABASE"                    : "[ a-zA-Z0-9._]+",
	"DB"                          : "[a-zA-Z0-9._]*",
	"DBA PRIVILEGE"               : rgxAnything,               # "SYSDBA", "SYSOPER"
	"DBQ"                         : rgxAnything,               # "C:\mydatabase.accdb", "111.21.31.99:1521/XE", "myTNSServiceName"
	"DECR POOL SIZE"              : rgxNumber,                 #
	"DEFAULT COMMAND TIMEOUT"     : rgxNumber,                 #
	"DEFAULTTABLECACHEAGE"        : rgxNumber,                 #
	"DRIVER"                      : "\{[^}]*\}",               # "{Microsoft Access Driver (*.mdb, *.accdb)}"
	"DSN"                         : "\w+",                     # "MY_DSN_ORA12"
	"ENCRYPT"                     : rgxTrueFalse,              # "true"
	"EXCLUSIVE"                   : rgxTrueFalse,              # "1"
	"EXTENDEDANSISQL"             : rgxTrueFalse,              # "1"
	"EXTENDED PROPERTIES"         : rgxAnything,               #
	"FILEDSN"                     : rgxFileName,
	"IGNORE PREPARE"              : rgxTrueFalse,              #
	"INCR POOL SIZE"              : rgxNumber,                 #
	"INITIAL CATALOG"             : rgxAnything,               # "myDataBase"
	"INTEGRATEDSECURITY"          : rgxTrueFalse,              #
	"JET OLEDB:DATABASE PASSWORD" : rgxPassword,
	"KEEPALIVE"                   : rgxNumber,                 #
	"LOCALE IDENTIFIER"           : "\d+",                     # "2057" is en-gb locale identifier
	"LOAD BALANCING"              : rgxTrueFalse,              #
	"MAX POOL SIZE"               : rgxNumber,                 #
	"MIN POOL SIZE"               : rgxNumber,                 #
	"MAXIMUMPOOLSIZE"             : rgxNumber,                 #
	"MINIMUMPOOLSIZE"             : rgxNumber,                 #
	"MODE"                        : "[a-zA-Z ]+",              # "Share Exclusive"
	"ODBCKEY[12]"                 : rgxAnything,
	"OLDGUIDS"                    : rgxTrueFalse,              #
	"OLEDBKEY[12]"                : rgxAnything,
	"OPTION"                      : rgxAnything,               #
	"OSAUTHENT"                   : rgxTrueFalse,              # "1"
	"PASSWORD"                    : rgxPassword,
	"PERSIST SECURITY INFO"       : rgxTrueFalse,
	"PIPENAME"                    : "\w+",                     # If "Protocol" = "pipe".
	"POOLING"                     : rgxTrueFalse,              #
	"PORT"                        : "\d+",                     # TODO: Five numbers or less.
	"PROCEDURECACHESIZE"          : rgxNumber,                 #
	"PROTOCOL"                    : "\w+",                     # "socket|memory|pipe"
	"PROVIDER"                    : "[ a-zA-Z0-9._]+",         # "Microsoft.ACE.OLEDB.12.0"
	"PWD"                         : rgxPassword,
	"REMOTE SERVER"               : rgxAnything,               # "http://server.adress.com"
	"SERVER"                      : "[- a-zA-Z0-9\._\\\]+",    # "serverAddress1, serverAddress2, serverAddress3"
															   # This Oracle omission of tnsnames.ora is not taken into account.
															   # "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=MyHost)(PORT=MyPort))(CONNECT_DATA=(SERVICE_NAME=MyOracleSID)))"
	"SHARED MEMORY NAME"          : "\w+",                     # "MYSQL" for example. If "Protocol" = "memory".
	"SOCKET"                      : rgxAnything,               #
	"SQLSERVERMODE"               : rgxTrueFalse,              #
	"SSLCERT"                     : rgxFileName,               # "c:\client-cert.pem"
	"SSLKEY"                      : rgxFileName,               # "c:\client-key.pem"
	"SSLMODE"                     : "\w+",                     # "Preferred|Required"
	"SSLVERIFY"                   : rgxTrueFalse,              # "1"
	"STMT"                        : rgxAnything,               #
	"SYSTEMDB"                    : rgxAnything,               # "C:\mydatabase.mdw"
	"TABLECACHE"                  : rgxTrueFalse,              #
	"TRUSTED_CONNECTION"          : rgxTrueFalse,
	"UID"                         : rgxUser,
	"USEAFFECTEDROWS"             : rgxTrueFalse,              #
	"USECOMPRESSION"              : rgxTrueFalse,              #
	"USER"                        : rgxUser,
	"USER ID"                     : rgxUser,
	"USEPERFORMANCEMONITOR"       : rgxTrueFalse,              #
	"USEPROCEDUREBODIES"          : rgxTrueFalse,              #
	"USEUSAGEADVISOR"             : rgxTrueFalse,              #
}

# Keys which are specifically coded as passwords.
# Should be ["PWD","PASSWORD","JET OLEDB:DATABASE PASSWORD"]
odbcKeysConfidential = [keyWrd for keyWrd in mapRgxODBC if mapRgxODBC[keyWrd] == rgxPassword ]

# Values which do not need to be encoded, making things easier to understand.
odbcKeysUncoded = [keyWrd for keyWrd in mapRgxODBC if mapRgxODBC[keyWrd] in [rgxAlpha,rgxUser,rgxTrueFalse,rgxHexa,rgxNumber] ]


# This behaves like a string plus some properties for serialization.
# So it can be used as a keyword for encoding parameters in the id of an object,
# but also it contains serialization methods.
# Therefore, it can be mixed with plain string keywords, which is the most common case.
class CgiPropertyDsn(str):
	# Python 2
	def __new__(cls):
		return super(CgiPropertyDsn, cls).__new__(cls, "Dsn")

	#def __new__(self):
	#	obj = str.__new__(cls, "Dsn")
	#	return obj

	def SplitPlain(connectStrClear):
		return re.split( " *; *", connectStrClear )

	def ValueEncode(self,connectStrClear):
		# sys.stderr.write("ValueEncode connectStrClear=%s\n"%connectStrClear)
		vecKeywrd = re.split( " *; *", connectStrClear )

		def KeyValuePairEncode(kvPair):
			( aKeyWrd,aVal ) = re.split( " *= *", kvPair )
			# sys.stderr.write("KeyValuePairEncode aKeyWrd=%s\n"%aKeyWrd)
			if aKeyWrd in odbcKeysConfidential:
				# aVal = lib_util.EncodeUri(aVal) # SHOULD BE CRYPTED
				aVal = cgi.escape(aVal) # SHOULD BE CRYPTED
			elif aKeyWrd not in odbcKeysUncoded:
				aVal = cgi.escape(aVal)
			return aKeyWrd.upper() + "~" + aVal

		# return "-".join( KeyValuePairEncode(aKeyW.upper(),vecKeywrd[aKeyW]) for aKeyW in vecKeywrd )
		return "-".join( KeyValuePairEncode(kvPair) for kvPair in vecKeywrd )

	def ValueDecode(self,connectStrCoded):
		# sys.stderr.write("ValueDecode connectStrCoded=%s\n"%connectStrCoded)
		vecTokPairs = re.split( "-", connectStrCoded )

		def TokenDecode(aTok):
			# sys.stderr.write("TokenDecode aTok=%s\n"%aTok)

			# DecodeUri inverse de EncodeUri mais ca n existe pas !!!!
			def TokenLocalDecode(aVal):
				return aVal

			try:
				(aKeyWrd,aVal) = aTok.split("~")
			except ValueError:
				return "Key=Cannot decode"

			if aKeyWrd in odbcKeysConfidential:
				aVal = TokenLocalDecode(aVal) # SHOULD BE CRYPTED
			elif aKeyWrd not in odbcKeysUncoded:
				aVal = TokenLocalDecode(aVal)
			# sys.stderr.write("TokenDecode aVal=%s\n"%aVal)
			return aKeyWrd + "=" + aVal

		return ";".join( TokenDecode(aTok) for aTok in vecTokPairs )

	# Same thing as displaying but the password must be hidden.
	def ValueDisplay(self,connectStrCoded):
		connectStrClear = self.ValueDecode(connectStrCoded)
		connectStrHidden = connectStrClear
		connectStrHidden = re.sub("PWD=[^;]+","PWD=xxxxxxx", connectStrHidden,re.IGNORECASE)
		connectStrHidden = re.sub("PASSWORD=[^;]+","PASSWORD=xxxxxxx", connectStrHidden,re.IGNORECASE)
		return connectStrHidden

	# This must be very fast because used in loops.
	# It abbreviates the DSN especially if this is a connection string.
	def ValueShortDisplay(self,connectStrCoded):
		connectStrClear = self.ValueDecode(connectStrCoded)
		# sys.stderr.write("ValueShortDisplay connectStrCoded=%s connectStrClear=%s\n"%(connectStrCoded,connectStrClear))
		mtchDsn = re.match(".*DSN=([^;]+).*",connectStrClear,re.IGNORECASE)
		if mtchDsn:
			return mtchDsn.group(1)
		mtchDsn = re.match(".*SERVER=([^;]+).*",connectStrClear,re.IGNORECASE)
		if mtchDsn:
			return mtchDsn.group(1)
		return connectStrClear


