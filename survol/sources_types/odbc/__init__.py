"""
Open Database Connectivity concepts
"""

import re
import sys
import logging

import six

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

# TODO: Check if "=" in the password, possibly escaped.
# The password might be empty.
# This does not work if it contains an escaped double-quote between double-quotes.
_rgx_password = '([^ "=;]*|"[^"]*")'

# Hexadecimal number
_rgx_hexa = "[0-9a-fA-F]+"

_rgx_number = r"\d+"

_rgx_alpha = "[a-zA-Z]+"

# Unfortunately it is not able to filter escaped equal signs.
_rgx_anything = "[^=]+"

_rgx_file_name = r"[^;=]+"

# For example:
# SERVER=(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=MyHost)(PORT=MyPort))(CONNECT_DATA=(SERVICE_NAME=MyOracleSID)));
# Data Source=(DESCRIPTION=(CID=GTU_APP)(ADDRESS_LIST=(ADDRESS=(PROTOCOL=TCP)(HOST=myHost)(PORT=myPort)))(CONNECT_DATA=(SID=MyOracleSID)(SERVER=DEDICATED)));
# Specific difficulty here: Some keywords in Oracle descriptions are also ODBC keywords: "PROTOCOL" and "SERVER".
_rgx_oracle_description = r'\([^;]*\)'

# The individual regular expressions do not contain the pipe character,
# because it is already used between each regular expression.

# https://www.connectionstrings.com/oracle/

_map_rgx_odbc_heavy = {
    "ALLOWBATCH"                  : _rgx_true_false,             #
    "ALLOWUSERVARIABLES"          : _rgx_true_false,             #
    "ALLOWZERODATETIME"           : _rgx_true_false,             #
    "ATTACHDBFILENAME"            : _rgx_file_name,              #
    "AUTOENLIST"                  : _rgx_true_false,             #
    "CACHESERVERPROPERTIES"       : _rgx_true_false,             #
    "CACHETYPE"                   : _rgx_alpha,                  # "File"
    "CERTIFICATE STORE LOCATION"  : _rgx_user,                   # "CurrentUser"
    "CERTIFICATE THUMBPRINT"      : _rgx_hexa,                   # "479436009a40f3017a145cf8479e7694d7aadef0"
    "CERTIFICATEFILE"             : _rgx_file_name,              # "C:\folder\client.pfx"
    "CERTIFICATEPASSWORD"         : _rgx_password,
    "CHARSET"                     : r"\w+",                      # "utf8"
    "CHECKPARAMETERS"             : _rgx_true_false,             #
    "COMMAND LOGGING"             : _rgx_true_false,             #
    "CONNECTION ?LIFETIME"        : _rgx_number,                 # " " character is optional.
    "CONNECTION TIMEOUT"          : _rgx_number,                 #
    "CONNECTIONRESET"             : _rgx_true_false,             #
    "CONNECTIONTYPE"              : r"[a-zA-Z]+",                # "Direct"
    "CONVERTZERODATETIME"         : _rgx_true_false,             #
    # FIXME: It cannot start with a open parenthesis because this would be taken as an Oracle description.
    # It can be a file name such as "
    "DATA SOURCE"                 : r"([^\(]%s|%s)" % (_rgx_file_name, _rgx_oracle_description),
                                                                 # "C:\myFolder\myAccessFile.accdb"
                                                                 # "|DataDirectory|\myAccessFile.accdb"
                                                                 # "\\server\share\folder\myAccessFile.accdb"
    "DATABASE"                    : "[ a-zA-Z0-9._]+",
    "DB"                          : r"[a-zA-Z0-9\._]*",
    "DBA PRIVILEGE"               : "[a-zA-Z0-9_]*",             # "SYSDBA", "SYSOPER"
    "DBQ"                         : _rgx_file_name,              # "C:\mydatabase.accdb", "111.21.31.99:1521/XE", "myTNSServiceName"
    "DECR POOL SIZE"              : _rgx_number,                 #
    "DEFAULT COMMAND TIMEOUT"     : _rgx_number,                 #
    "DEFAULTTABLECACHEAGE"        : _rgx_number,                 #
    "DRIVER"                      : r"(\{[^}]*\}|[a-zA-Z0-9 ]+)",                # "{Microsoft Access Driver (*.mdb, *.accdb)}"
                                                                 # "Driver=MapR Drill ODBC Driver"
    "DSN"                         : r"\w+",                      # "MY_DSN_ORA12"
    "ENCRYPT"                     : _rgx_true_false,             # "true"
    "EXCLUSIVE"                   : _rgx_true_false,             # "1"
    "EXTENDEDANSISQL"             : _rgx_true_false,             # "1"
    "EXTENDED PROPERTIES"         : '"[^"]*"',
    "EXTENSIONS"                  : r"[a-zA-Z0-9,]+",            # "Extensions=asc,csv,tab,txt"
    "FILEDSN"                     : _rgx_file_name,
    "HOST"                        : r"[0-9\.]+",                 # "Host=192.168.222.160"
    "IGNORE PREPARE"              : _rgx_true_false,             #
    "INCR POOL SIZE"              : _rgx_number,                 #
    "INITIAL CATALOG"             : "[a-zA-Z0-9_ ]+",            # "myDataBase"
    "INTEGRATED SECURITY"         : _rgx_true_false,             #
    "JET OLEDB:DATABASE PASSWORD" : _rgx_password,
    "KEEPALIVE"                   : _rgx_number,                 #
    "LOCALE IDENTIFIER"           : r"\d+",                      # "2057" is en-gb locale identifier
    "LOAD BALANCING"              : _rgx_true_false,             #
    "MAX POOL SIZE"               : _rgx_number,                 #
    "MIN POOL SIZE"               : _rgx_number,                 #
    "MAXIMUMPOOLSIZE"             : _rgx_number,                 #
    "MINIMUMPOOLSIZE"             : _rgx_number,                 #
    "MODE"                        : "[a-zA-Z ]+",                # "Share Exclusive"
    "NETWORK LIBRARY"             : "[a-zA-Z ]+",                #
    "ODBCKEY[12]"                 : _rgx_anything,
    "OLDGUIDS"                    : _rgx_true_false,             #
    "OLEDBKEY[12]"                : _rgx_anything,
    "OPTION"                      : _rgx_anything,               #
    "OSAUTHENT"                   : _rgx_true_false,             # "1"
    "PASSWORD"                    : _rgx_password,
    "PERSIST SECURITY INFO"       : _rgx_true_false,
    "PIPENAME"                    : r"\w+",                      # If "Protocol" = "pipe".
    "POOLING"                     : _rgx_true_false,             #
    "PORT"                        : r"\d+",                      # TODO: Five numbers or less.
    "PROCEDURECACHESIZE"          : _rgx_number,                 #
    "PROTOCOL"                    : r"\w+",                      # "socket|memory|pipe"
    "PROVIDER"                    : "[ a-zA-Z0-9._]+",           # "Microsoft.ACE.OLEDB.12.0"
    "PWD"                         : _rgx_password,
    "REMOTE SERVER"               : _rgx_anything,               # "http://server.adress.com"
    "SERVER": r"([- a-zA-Z0-9\._\\#:]+|\(localdb\)\\[0-9a-zA-Z\.\\]*|%s)" % _rgx_oracle_description,
                                                                 # "serverAddress"
                                                                 # "(localdb)\v11.0"
                                                                 # "Server=(localdb)\.\MyInstanceShare"
                                                                 # "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=MyHost)(PORT=MyPort))(CONNECT_DATA=(SERVICE_NAME=MyOracleSID)))"
                                                                 # "Server=np:\\.\pipe\LOCALDB#F365A78E\tsql\query"
    "SHARED MEMORY NAME"          : r"\w+",                      # "MYSQL" for example. If "Protocol" = "memory".
    "SOCKET"                      : _rgx_anything,               #
    "SQLSERVERMODE"               : _rgx_true_false,             #
    "SSLCERT"                     : _rgx_file_name,              # "c:\client-cert.pem"
    "SSLKEY"                      : _rgx_file_name,              # "c:\client-key.pem"
    "SSLMODE"                     : r"\w+",                      # "Preferred|Required"
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
_odbc_keys_confidential = [key_wrd for key_wrd in _map_rgx_odbc_heavy if _map_rgx_odbc_heavy[key_wrd] == _rgx_password]

# Values which do not need to be encoded, making things easier to understand.
_odbc_keys_uncoded = [
    key_wrd
    for key_wrd in _map_rgx_odbc_heavy
    if _map_rgx_odbc_heavy[key_wrd] in [_rgx_alpha, _rgx_user, _rgx_true_false, _rgx_hexa, _rgx_number]]

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
_map_rgx_odbc_light = {key: _map_rgx_odbc_heavy[key] for key in restrict_rgx_odbc_keys}

# This need a to be not-too-reserved character.
_delimiter_connection_string_odbc = "/" # "-"

_rgx_before_keyword = "[; ]*"
_rgx_after_keyword = " *[;\n\r\t\0x00]"

def _concatenate_regex_dict(map_rgx):
    """
    This builds a regular expression for finding ODBC connection strings.
    The input is a dict of ODBC character key. mapped to the regular expression for finding it.
    This might be very slow.
    """
    # Not letter, then the keyword, then "=", then the value regex, then possibly the delimiter.
    rgx_dsn = "|".join([_rgx_before_keyword + key + " *= *" + map_rgx[key] + " *" for key in map_rgx])

    # This works also. Both are very slow.
    #rgx_dsn = "|".join([ ";? *" + key + " *= *" + survol_odbc.mapRgxODBC[key] + " *" for key in survol_odbc.mapRgxODBC ])
    return rgx_dsn


regex_odbc_heavy = _concatenate_regex_dict(_map_rgx_odbc_heavy)

regex_odbc_light = _concatenate_regex_dict(_map_rgx_odbc_light)


def aggregate_dsn_pieces(resu_matches):
    """
    This aggregates contiguous, or nearly contiguous, mactked tokens, in bigger strings.
    This is useful when matching a regular expression made as an OR of possible tokens.
    :param resu_matches: A dict of offsets to matched strings. Each matched string is an individual detected token.
    :return: A similar dict, but contiguous matched strings are concatenated
    """

    sorted_keys = sorted(resu_matches.keys())
    aggreg_dsns = dict()
    curr_offset = -1
    for the_off in sorted_keys:
        curr_mtch = resu_matches[the_off]
        assert isinstance(curr_mtch, six.binary_type)
        if curr_offset == -1:
            curr_offset = the_off
            aggreg_dsns[curr_offset] = curr_mtch
        elif the_off == next_offset:
            # The current string comes just after the last one.
            # Concatenation of the current string.
            # Maybe we can tolerate a small difference for spaces.
            aggreg_dsns[curr_offset] += curr_mtch
        else:
            # This starts a new DSN string because the current match comes far after the previous one.
            curr_offset = the_off
            aggreg_dsns[curr_offset] = curr_mtch
        next_offset = the_off + len(curr_mtch)

    # TODO: Eliminate aggregated strings containing one or two tokens,
    # because they cannot be genuine DSNs.
    # 29812569: SERVER=\MYMACHINE
    # 34515016: Driver={SQL Server};Server=.\SQLEXPRESS;Database=ExpressDB;Trusted_Connection=yes
    # 34801013: SERVER=\MYMACHINE
    # 35634904: Driver={SQL Server};Server=.\SQLEXPRESS;Database=ExpressDB;Trusted_Connection=yes

    return aggreg_dsns


def ShortenDsn(connect_str_clear):
    """
    This must be very fast because used in loops.
    It abbreviates the DSN especially if this is a connection string.
    """
    mtch_dsn = re.match(".*DSN=([^;]+).*", connect_str_clear, re.IGNORECASE)
    if mtch_dsn:
        return mtch_dsn.group(1)
    mtch_dsn = re.match(".*SERVER=([^;]+).*", connect_str_clear, re.IGNORECASE)
    if mtch_dsn:
        return mtch_dsn.group(1)
    return connect_str_clear


