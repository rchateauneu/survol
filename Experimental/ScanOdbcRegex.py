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
	"DSN"                         : "\w+"                      # "MY_DSN_ORA12"
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




# Not letter, then the keyword, then "=", then the value regex, then possibly the delimiter.
rgxDSN = "|".join([ "[; ]*" + key + " *= *" + mapRgxODBC[key] + " *" for key in mapRgxODBC ])
sys.stderr.write("rgxDSN=%s\n"%rgxDSN)

# TODO: OPTIONALLY ADD NON-ASCII CHAR AT THE VERY BEGINNING. SLIGHTLY SAFER AND FASTER.
rgxDSN = "[^a-zA-Z]" + regDSN

		
# Last pass after aggregation:
# If several tokens were aggregated and are still separated by a few chars (20, 30 etc...),
# we can assume that they are part of the same connection string,
# especially they contain complementary keywords (UID them PWD etc...)
# So, it does not really matter if some rare keywords are not known.
# We could have a last pass to extract these keywords: Although we are by definition unable
# able to use their content explicitely, a complete connection string can still be used
# to connect to ODBC.
		
# http://www.dofactory.com/reference/connection-strings



================================================================
Property

# Within a query component, the characters ";", "/", "?", ":", "@", "&", "=", "+", ",", and "$" are reserved.
# reserved    = gen-delims / sub-delims
# gen-delims  = ":" / "/" / "?" / "#" / "[" / "]" / "@"
# sub-delims  = "!" / "$" / "&" / "'" / "(" / ")"
# 		      / "*" / "+" / "," / ";" / "="

class CgiPropertyB64(str):
	def __new__(self,propName):
		obj = str.__new__(cls, propName)
		return obj
		
	def ValueEncode(self,valueClear):
		return base64.encode(value)
		
	def ValueDecode(self,valueCoded):
		return base64.decode(value)
		
	def ValueDisplay(self,valueClear):
		return cgi.escape(valueClear)
		
		
class CgiPropertyQuery (CgiPropertyB64):
	def __init__(self):
		super(CgiPropertyQuery, self).__init__("Query")

		
# « UID=xxx;PWD=yyy;DRIVER=zzz »
# entity.py?xid=odbc/table.Dsn=@@@@@@@@,Table=MY_TABLE
# entity.py?xid=odbc/table.Dsn:UID-xxx;PWD-yyy;DRIVER-zzz,Table:MY_TABLE
# entity.py?xid=odbc/table.Dsn:UID(xxx)-PWD(yyy)-DRIVER(zzz),Table:MY_TABLE
# entity.py?xid=odbc/table.Dsn:UID-xxx-PWD-yyy-DRIVER-zzz,Table:MY_TABLE
# On encode ou crypte (base64) les valeurs qui ne sont pas en alphanum.

# Keys which are specifically coded as passwords.
# Should be ["PWD","PASSWORD","JET OLEDB:DATABASE PASSWORD"]
odbcKeysConfidential = [keyWrd in mapRgxODBC where mapRgxODBC[keyWrd] == rgxPassword ]

# Values which do not need to be encoded, making things easier to understand.
odbcKeysUncoded = [keyWrd in mapRgxODBC where mapRgxODBC[keyWrd] == in [rgxAlpha,rgxUser,rgxTrueFalse,rgxHexa,rgxNumber] ]

class CgiPropertyDsn(str):
	def __new__(self):
		obj = str.__new__(cls, "Dsn")
		return obj
		
	def ValueEncode(self,connectStrClear):
		vecKeywrd = re.split( " *; *", connectStrClear )
		
		def KeyValuePairEncode(aKeyWrd,aVal):
			if aKeyWrd in odbcKeysConfidential:
				aVal = CRYPT(aVal)
			elif aKeyWrd not in odbcKeysUncoded:
				aVal = CODEB64(aVal)
			return aKeyWrd + "~" + aVal

		return "-".join( KeyValuePairEncode(aKeyW.upper(),vecKeywrd[aKeyW]) for aKeyW in vecKeywrd )

	def ValueDecode(self,connectStrCoded):
		vecTokPairs = re.split( "-", connectStrCoded )
	
		def TokenDecode(aTok):
			(aKeyWrd,aVal) = aTok.split("~")
			if aKeyWrd in odbcKeysConfidential:
				aVal = DECRYPT(aVal)
			elif aKeyWrd not in odbcKeysUncoded:
				aVal = DECODEB64(aVal)
			return aKeyWrd + "=" + aVal
			
		return ";".join( TokenDecode(aTok) for aTok in vecTokPairs )
		
	def ValueDisplay(self,connectStrClear):
		return cgi.escape(connectStrClear)
		
	
# On veut faire ca avec un minimum de changements.
def survol_sqlserver_query.Ontology():
	return ( [ survol_odbc_dsn.CgiPropertyDsn(), survol_odbc_dsn.CgiPropertyQuery(), ], )
		







