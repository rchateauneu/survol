"""
Open Database Connectivity concepts
"""

import re
import sys
import lib_util
import logging

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

#    "odbc/dsn"                               : ( "tab",       "#CCFF11", "#CCFF11", 0, False ),
#    "odbc/table"                             : ( "tab",       "#11FF11", "#CCFF11", 0, False ),
#    "odbc/column"                            : ( "tab",       "#11FF11", "#44FF11", 0, False ),
#    "odbc/procedure"                         : ( "tab",       "#11FF11", "#CC4411", 0, False ),


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
#               / "*" / "+" / "," / ";" / "="

# "UID=xxx;PWD=yyy;DRIVER=zzz"
# entity.py?xid=odbc/table.Dsn=@@@@@@@@,Table=MY_TABLE
# entity.py?xid=odbc/table.Dsn:UID-xxx;PWD-yyy;DRIVER-zzz,Table:MY_TABLE
# entity.py?xid=odbc/table.Dsn:UID(xxx)-PWD(yyy)-DRIVER(zzz),Table:MY_TABLE
# entity.py?xid=odbc/table.Dsn:UID-xxx-PWD-yyy-DRIVER-zzz,Table:MY_TABLE
# "True", "False", "true", "yes", "0", "1"
_rgx_true_false = "[a-zA-Z01]*"

_rgx_user = r"\w+"

# TODO: Will not work if "=" in the password, even if it is escaped.
# Should reasonably contain more than four or five chars.
_rgx_password = ".+"

# Hexadecimal number
_rgx_hexa = "[0-9a-fA-F]+"

_rgx_number = r"\d+"

_rgx_alpha = "[a-zA-Z]+"

# Unfortunately it is not able to filter escaped equal signs.
_rgx_anything = "[^=]+"

_rgx_file_name = _rgx_anything

# The individual regular expressions do not contain the pipe character,
# because it is already used between each regular expression.

# https://www.connectionstrings.com/oracle/

mapRgxODBC = {
    "ALLOWBATCH"                  : _rgx_true_false,             #
    "ALLOWUSERVARIABLES"          : _rgx_true_false,             #
    "ALLOWZERODATETIME"           : _rgx_true_false,             #
    "AUTOENLIST"                  : _rgx_true_false,             #
    "CACHESERVERPROPERTIES"       : _rgx_true_false,             #
    "CACHETYPE"                   : _rgx_alpha,                  # "File"
    "CERTIFICATE STORE LOCATION"  : _rgx_user,                   # "CurrentUser"
    "CERTIFICATE THUMBPRINT"      : _rgx_hexa,                   # "479436009a40f3017a145cf8479e7694d7aadef0"
    "CERTIFICATEFILE"             : _rgx_file_name,              # "C:\folder\client.pfx"
    "CERTIFICATEPASSWORD"         : _rgx_password,
    "CHARSET"                     : "\w+",                       # "utf8"
    "CHECKPARAMETERS"             : _rgx_true_false,             #
    "COMMAND LOGGING"             : _rgx_true_false,             #
    "CONNECTION ?LIFETIME"        : _rgx_number,                 # " " character is optional.
    "CONNECTION TIMEOUT"          : _rgx_number,                 #
    "CONNECTIONRESET"             : _rgx_true_false,             #
    "CONVERTZERODATETIME"         : _rgx_true_false,             #
    "DATA SOURCE"                 : "[a-zA-Z_0-9\\/]+",          # "C:\myFolder\myAccessFile.accdb"
                                                                 # "|DataDirectory|\myAccessFile.accdb"
                                                                 # "\\server\share\folder\myAccessFile.accdb"
    "DATABASE"                    : "[ a-zA-Z0-9._]+",
    "DB"                          : "[a-zA-Z0-9._]*",
    "DBA PRIVILEGE"               : _rgx_anything,               # "SYSDBA", "SYSOPER"
    "DBQ"                         : _rgx_anything,               # "C:\mydatabase.accdb", "111.21.31.99:1521/XE", "myTNSServiceName"
    "DECR POOL SIZE"              : _rgx_number,                 #
    "DEFAULT COMMAND TIMEOUT"     : _rgx_number,                 #
    "DEFAULTTABLECACHEAGE"        : _rgx_number,                 #
    "DRIVER"                      : "\{[^}]*\}",                 # "{Microsoft Access Driver (*.mdb, *.accdb)}"
    "DSN"                         : "\w+",                       # "MY_DSN_ORA12"
    "ENCRYPT"                     : _rgx_true_false,             # "true"
    "EXCLUSIVE"                   : _rgx_true_false,             # "1"
    "EXTENDEDANSISQL"             : _rgx_true_false,             # "1"
    "EXTENDED PROPERTIES"         : _rgx_anything,               #
    "FILEDSN"                     : _rgx_file_name,
    "IGNORE PREPARE"              : _rgx_true_false,             #
    "INCR POOL SIZE"              : _rgx_number,                 #
    "INITIAL CATALOG"             : _rgx_anything,               # "myDataBase"
    "INTEGRATEDSECURITY"          : _rgx_true_false,             #
    "JET OLEDB:DATABASE PASSWORD" : _rgx_password,
    "KEEPALIVE"                   : _rgx_number,                 #
    "LOCALE IDENTIFIER"           : "\d+",                       # "2057" is en-gb locale identifier
    "LOAD BALANCING"              : _rgx_true_false,             #
    "MAX POOL SIZE"               : _rgx_number,                 #
    "MIN POOL SIZE"               : _rgx_number,                 #
    "MAXIMUMPOOLSIZE"             : _rgx_number,                 #
    "MINIMUMPOOLSIZE"             : _rgx_number,                 #
    "MODE"                        : "[a-zA-Z ]+",                # "Share Exclusive"
    "ODBCKEY[12]"                 : _rgx_anything,
    "OLDGUIDS"                    : _rgx_true_false,             #
    "OLEDBKEY[12]"                : _rgx_anything,
    "OPTION"                      : _rgx_anything,               #
    "OSAUTHENT"                   : _rgx_true_false,             # "1"
    "PASSWORD"                    : _rgx_password,
    "PERSIST SECURITY INFO"       : _rgx_true_false,
    "PIPENAME"                    : "\w+",                       # If "Protocol" = "pipe".
    "POOLING"                     : _rgx_true_false,             #
    "PORT"                        : "\d+",                       # TODO: Five numbers or less.
    "PROCEDURECACHESIZE"          : _rgx_number,                 #
    "PROTOCOL"                    : "\w+",                       # "socket|memory|pipe"
    "PROVIDER"                    : "[ a-zA-Z0-9._]+",           # "Microsoft.ACE.OLEDB.12.0"
    "PWD"                         : _rgx_password,
    "REMOTE SERVER"               : _rgx_anything,               # "http://server.adress.com"
    "SERVER"                      : "[- a-zA-Z0-9\._\\\]+",      # "serverAddress1, serverAddress2, serverAddress3"
                                                                 # This Oracle omission of tnsnames.ora is not taken into account.
                                                                 # "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=MyHost)(PORT=MyPort))(CONNECT_DATA=(SERVICE_NAME=MyOracleSID)))"
    "SHARED MEMORY NAME"          : "\w+",                       # "MYSQL" for example. If "Protocol" = "memory".
    "SOCKET"                      : _rgx_anything,               #
    "SQLSERVERMODE"               : _rgx_true_false,             #
    "SSLCERT"                     : _rgx_file_name,              # "c:\client-cert.pem"
    "SSLKEY"                      : _rgx_file_name,              # "c:\client-key.pem"
    "SSLMODE"                     : "\w+",                       # "Preferred|Required"
    "SSLVERIFY"                   : _rgx_true_false,             # "1"
    "STMT"                        : _rgx_anything,               #
    "SYSTEMDB"                    : _rgx_anything,               # "C:\mydatabase.mdw"
    "TABLECACHE"                  : _rgx_true_false,             #
    "TRUSTED_CONNECTION"          : _rgx_true_false,
    "UID"                         : _rgx_user,
    "USEAFFECTEDROWS"             : _rgx_true_false,             #
    "USECOMPRESSION"              : _rgx_true_false,             #
    "USER"                        : _rgx_user,
    "USER ID"                     : _rgx_user,
    "USEPERFORMANCEMONITOR"       : _rgx_true_false,             #
    "USEPROCEDUREBODIES"          : _rgx_true_false,             #
    "USEUSAGEADVISOR"             : _rgx_true_false,             #
}

# Keys which are specifically coded as passwords.
# Should be ["PWD","PASSWORD","JET OLEDB:DATABASE PASSWORD"]
_odbc_keys_confidential = [key_wrd for key_wrd in mapRgxODBC if mapRgxODBC[key_wrd] == _rgx_password]

# Values which do not need to be encoded, making things easier to understand.
_odbc_keys_uncoded = [
    key_wrd
    for key_wrd in mapRgxODBC
    if mapRgxODBC[key_wrd] in [_rgx_alpha, _rgx_user, _rgx_true_false, _rgx_hexa, _rgx_number]]

# This contains the most often used keys in DSN connection strings.
restrict_rgx_odbc_keys = [
    "DATA SOURCE",
    "DATABASE",
    "DB",
    "DRIVER",
    "DSN",
    "PROTOCOL",
    "PROVIDER",
    "PWD",
    "REMOTE SERVER",
    "SERVER",
    "SHARED MEMORY NAME",
    "SOCKET",
    "SQLSERVERMODE",
    "TRUSTED_CONNECTION",
    "UID",
    "USER",
    "USER ID",
]

# Only the commonest parameters, to make memory scans faster.
mapRgxODBC_Light = {key : mapRgxODBC[key] for key in restrict_rgx_odbc_keys}

# This need a to be not-too-reserved character.
_delimiter_connection_string_odbc = "/" # "-"

# This behaves like a string plus some properties for serialization.
# So it can be used as a keyword for encoding parameters in the id of an object,
# but also it contains serialization methods.
# Therefore, it can be mixed with plain string keywords, which is the most common case.
class CgiPropertyDsn(str):
    # Python 2
    def __new__(cls):
        return super(CgiPropertyDsn, cls).__new__(cls, "Dsn")

    def SplitPlain(connect_str_clear):
        return re.split(" *; *", connect_str_clear)

    def ValueEncode(self, connect_str_clear):
        # sys.stderr.write("ValueEncode connectStrClear=%s\n"%connectStrClear)
        vec_keywrd = re.split(" *; *", connect_str_clear)

        def key_value_pair_encode(kv_pair):
            try:
                a_key_wrd, a_val = re.split(" *= *", kv_pair)
                # sys.stderr.write("key_value_pair_encode a_key_wrd=%s\n"%a_key_wrd)
                if a_key_wrd in _odbc_keys_confidential:
                    a_val = lib_util.html_escape(a_val) # SHOULD BE CRYPTED
                elif a_key_wrd not in _odbc_keys_uncoded:
                    a_val = lib_util.html_escape(a_val)
                return a_key_wrd.upper() + "~" + a_val
            except Exception as exc:
                logging.error("%s: Cannot process: %s", exc, str(kv_pair))
                raise

        # Cannot use the separator "-" as it can be used in server names.
        return _delimiter_connection_string_odbc.join(key_value_pair_encode(kv_pair) for kv_pair in vec_keywrd)

    def ValueDecode(self, connect_str_coded):
        # PROBLEM "SERVER=\MY_MACHINE"
        # SERVER=\\MY_MACHINE;Key=Cannot decode:HP

        vec_tok_pairs = re.split(_delimiter_connection_string_odbc, connect_str_coded)

        def TokenDecode(a_tok):
            # DecodeUri inverse de EncodeUri mais ca n existe pas !!!!
            def TokenLocalDecode(aVal):
                return aVal

            try:
                a_key_wrd, a_val = a_tok.split("~")
            except ValueError:
                return "Key=Cannot decode:"+str(a_tok)

            if a_key_wrd in _odbc_keys_confidential:
                a_val = TokenLocalDecode(a_val) # SHOULD BE CRYPTED
            elif a_key_wrd not in _odbc_keys_uncoded:
                a_val = TokenLocalDecode(a_val)
            # sys.stderr.write("TokenDecode a_val=%s\n"%a_val)
            return a_key_wrd + "=" + a_val

        return ";".join(TokenDecode(a_tok) for a_tok in vec_tok_pairs)

    # Same thing as displaying but the password must be hidden.
    def ValueDisplay(self, connect_str_coded):
        connect_str_clear = self.ValueDecode(connect_str_coded)
        connect_str_hidden = connect_str_clear
        connect_str_hidden = re.sub("PWD=[^;]+", "PWD=xxxxxxx", connect_str_hidden, re.IGNORECASE)
        connect_str_hidden = re.sub("PASSWORD=[^;]+", "PASSWORD=xxxxxxx", connect_str_hidden, re.IGNORECASE)
        return connect_str_hidden

    # This must be very fast because used in loops.
    # It abbreviates the DSN especially if this is a connection string.
    def ValueShortDisplay(self, connect_str_coded):
        connect_str_clear = self.ValueDecode(connect_str_coded)
        # sys.stderr.write("ValueShortDisplay connectStrCoded=%s connect_str_clear=%s\n"%(connectStrCoded,connect_str_clear))
        mtch_dsn = re.match(".*DSN=([^;]+).*", connect_str_clear, re.IGNORECASE)
        if mtch_dsn:
            return mtch_dsn.group(1)
        mtch_dsn = re.match(".*SERVER=([^;]+).*", connect_str_clear, re.IGNORECASE)
        if mtch_dsn:
            return mtch_dsn.group(1)
        return connect_str_clear


