#!/usr/bin/env python

"""
Scan process memory for ODBC connection strings
"""

import os
import sys
import re
import logging

import lib_uris
import lib_util
import lib_common
from lib_properties import pc

from sources_types import CIM_Process
from sources_types.CIM_Process import memory_regex_search
from sources_types import odbc as survol_odbc
from sources_types.odbc import dsn as survol_odbc_dsn

# ODBC connection strings, on Windows only.
Usable = lib_util.UsableWindows

SlowScript = True

# aRegex=[; ]*PIPENAME *= *\w+ *|[; ]*SSLKEY *= *[^=]+ *|[; ]*CONNECTIONRESET *= *[a-zA-Z01]* *|[; ]*DBA PRIVILEGE *= *[^=]+ *|[; ]*EN
# CRYPT *= *[a-zA-Z01]* *|[; ]*OPTION *= *[^=]+ *|[; ]*FILEDSN *= *[^=]+ *|[; ]*IGNORE PREPARE *= *[a-zA-Z01]* *|[; ]*CHARSET *= *\w+
# *|[; ]*DB *= *[a-zA-Z0-9._]* *|[; ]*STMT *= *[^=]+ *|[; ]*CERTIFICATE THUMBPRINT *= *[0-9a-fA-F]+ *|[; ]*INCR POOL SIZE *= *\d+ *|[;
#  ]*USEUSAGEADVISOR *= *[a-zA-Z01]* *|[; ]*SHARED MEMORY NAME *= *\w+ *|[; ]*USER *= *\w+ *|[; ]*OLDGUIDS *= *[a-zA-Z01]* *|[; ]*CERT
# IFICATEPASSWORD *= *.+ *|[; ]*SERVER *= *[- a-zA-Z0-9\._\\]+ *|[; ]*CERTIFICATEFILE *= *[^=]+ *|[; ]*PORT *= *\d+ *|[; ]*LOCALE IDEN
# TIFIER *= *\d+ *|[; ]*PROVIDER *= *[ a-zA-Z0-9._]+ *|[; ]*EXCLUSIVE *= *[a-zA-Z01]* *|[; ]*PROCEDURECACHESIZE *= *\d+ *|[; ]*MINIMUM
# POOLSIZE *= *\d+ *|[; ]*SSLCERT *= *[^=]+ *|[; ]*CERTIFICATE STORE LOCATION *= *\w+ *|[; ]*DEFAULTTABLECACHEAGE *= *\d+ *|[; ]*ALLOW
# ZERODATETIME *= *[a-zA-Z01]* *|[; ]*MAXIMUMPOOLSIZE *= *\d+ *|[; ]*JET OLEDB:DATABASE PASSWORD *= *.+ *|[; ]*MODE *= *[a-zA-Z ]+ *|[
# ; ]*CACHESERVERPROPERTIES *= *[a-zA-Z01]* *|[; ]*CHECKPARAMETERS *= *[a-zA-Z01]* *|[; ]*DECR POOL SIZE *= *\d+ *|[; ]*OLEDBKEY[12] *
# = *[^=]+ *|[; ]*KEEPALIVE *= *\d+ *|[; ]*OSAUTHENT *= *[a-zA-Z01]* *|[; ]*LOAD BALANCING *= *[a-zA-Z01]* *|[; ]*USEPROCEDUREBODIES *
# = *[a-zA-Z01]* *|[; ]*COMMAND LOGGING *= *[a-zA-Z01]* *|[; ]*PROTOCOL *= *\w+ *|[; ]*SYSTEMDB *= *[^=]+ *|[; ]*EXTENDEDANSISQL *= *[
# a-zA-Z01]* *|[; ]*REMOTE SERVER *= *[^=]+ *|[; ]*PERSIST SECURITY INFO *= *[a-zA-Z01]* *|[; ]*DRIVER *= *\{[^}]*\} *|[; ]*EXTENDED P
# ROPERTIES *= *[^=]+ *|[; ]*DSN *= *\w+ *|[; ]*MIN POOL SIZE *= *\d+ *|[; ]*SSLVERIFY *= *[a-zA-Z01]* *|[; ]*ALLOWUSERVARIABLES *= *[
# a-zA-Z01]* *|[; ]*USECOMPRESSION *= *[a-zA-Z01]* *|[; ]*SSLMODE *= *\w+ *|[; ]*AUTOENLIST *= *[a-zA-Z01]* *|[; ]*PASSWORD *= *.+ *|[
# ; ]*UID *= *\w+ *|[; ]*USEPERFORMANCEMONITOR *= *[a-zA-Z01]* *|[; ]*ODBCKEY[12] *= *[^=]+ *|[; ]*DATABASE *= *[ a-zA-Z0-9._]+ *|[; ]
# *DATA SOURCE *= *[a-zA-Z_0-9\/]+ *|[; ]*SOCKET *= *[^=]+ *|[; ]*TRUSTED_CONNECTION *= *[a-zA-Z01]* *|[; ]*CACHETYPE *= *[a-zA-Z]+ *|
# [; ]*USER ID *= *\w+ *|[; ]*DEFAULT COMMAND TIMEOUT *= *\d+ *|[; ]*CONNECTION TIMEOUT *= *\d+ *|[; ]*POOLING *= *[a-zA-Z01]* *|[; ]*
# MAX POOL SIZE *= *\d+ *|[; ]*ALLOWBATCH *= *[a-zA-Z01]* *|[; ]*SQLSERVERMODE *= *[a-zA-Z01]* *|[; ]*PWD *= *.+ *|[; ]*USEAFFECTEDROW
# S *= *[a-zA-Z01]* *|[; ]*INITIAL CATALOG *= *[^=]+ *|[; ]*CONVERTZERODATETIME *= *[a-zA-Z01]* *|[; ]*DBQ *= *[^=]+ *|[; ]*TABLECACHE
#  *= *[a-zA-Z01]* *|[; ]*INTEGRATEDSECURITY *= *[a-zA-Z01]* *|[; ]*CONNECTION ?LIFETIME *= *\d+ *


def _get_aggreg_dsns(pidint, map_rgx):
# "Driver={SQL Server};Server=.\SQLEXPRESS;Database=ExpressDB;Trusted_Connection=yes;"
# 34515015 = "Driver={SQL Server}"
# 34515035 = "Server=.\SQLEXPRESS"
# 34515055 = "Database=ExpressDB"
# 34515074 = "Trusted_Connection=yes"
# 35634903 = "Driver={SQL Server}"
# 35634923 = "Server=.\SQLEXPRESS"
# 35634943 = "Database=ExpressDB"
# 35634962 = "Trusted_Connection=yes"

    try:
        # Not letter, then the keyword, then "=", then the value regex, then possibly the delimiter.
        rgx_dsn = "|".join(["[; ]*" + key + " *= *" + map_rgx[key] + " *" for key in map_rgx])
        # This works also. Both are very slow.
        # rgx_dsn = "|".join([ ";? *" + key + " *= *" + survol_odbc.mapRgxODBC[key] + " *" for key in survol_odbc.mapRgxODBC ])
        logging.debug("rgx_dsn=%s", rgx_dsn)

        # TODO: OPTIONALLY ADD NON-ASCII CHAR AT THE VERY BEGINNING. SLIGHTLY SAFER AND FASTER.
        # rgx_dsn = "[^a-zA-Z]" + regDSN

        # Here we receive the matched keywords and their offset in memory.
        # We try to aggregate them if they are contiguous.
        # This will work less if we used a smaller set of DSN connecton strings keywords.
        # This could be fixed with theese remarks:
        # (1) If the difference of offsets is small.
        # (2) Try to extensively scan the memory (All DSN keywords) in the interval of detected common keywords.
        resu_matches = memory_regex_search.GetRegexMatches(pidint, rgx_dsn, re.IGNORECASE)

        for matched_offset in resu_matches:
            matched_str = resu_matches[matched_offset]
            # This should contain Ascii, convertible to UTF-8, but if the regular expression catch something else,
            # this decode throw: 'utf-8' codec can't decode bytes in position 3768-3769: invalid continuation byte.
            matched_str = matched_str.decode("utf-8", "ignore")
            dsn_token = str(matched_offset) + " = " + matched_str + " = " + str(matched_offset + len(matched_str))
            logging.debug("dsnODBC=%s", dsn_token)

        sorted_keys = sorted(resu_matches.keys())
        aggreg_dsns = dict()
        last_offset = 0
        curr_offset = 0
        for the_off in sorted_keys:
            curr_mtch = resu_matches[the_off]
            next_offset = the_off + len(curr_mtch)
            logging.debug("lastOffset=%d next_offset=%d curr_mtch=%s", last_offset, next_offset, curr_mtch)
            #if lastOffset == 0:
            #    lastOffset = next_offset
            #    aggregDsns[lastOffset] = curr_mtch
            #    continue
            if last_offset == the_off:
                aggreg_dsns[curr_offset] += curr_mtch
            else:
                # This starts a new DSN string.
                curr_offset = the_off
                aggreg_dsns[curr_offset] = curr_mtch
            last_offset = next_offset

        # TODO: Eliminate aggrehated strings containing one or two tokens,
        # because they cannot be genuine DSNs.
        # 29812569: SERVER=\MYMACHINE
        # 34515016: Driver={SQL Server};Server=.\SQLEXPRESS;Database=ExpressDB;Trusted_Connection=yes
        # 34801013: SERVER=\MYMACHINE
        # 35634904: Driver={SQL Server};Server=.\SQLEXPRESS;Database=ExpressDB;Trusted_Connection=yes

        return aggreg_dsns

        # Last pass after aggregation:
        # If several tokens were aggregated and are still separated by a few chars (20, 30 etc...),
        # we can assume that they are part of the same connection string,
        # especially they contain complementary keywords (UID them PWD etc...)
        # So, it does not really matter if some rare keywords are not known.
        # We could have a last pass to extract these keywords: Although we are by definition unable
        # able to use their content explicitely, a complete connection string can still be used
        # to connect to ODBC.

        # http://www.dofactory.com/reference/connection-strings

        # TODO: Instead of just displaying the DSN, connect to it, list tables etc...

    except Exception as exc:
        lib_common.ErrorMessageHtml("Error:%s. Protection ?" % str(exc))


def Main():
    paramkey_extensive_scan = "Extensive scan"

    # Beware that unchecked checkboxes are not posted, i.e. boolean variables set to False.
    # http://stackoverflow.com/questions/1809494/post-the-checkboxes-that-are-unchecked
    cgiEnv = lib_common.ScriptEnvironment(parameters={paramkey_extensive_scan: False})
    pidint = int(cgiEnv.GetId())

    grph = cgiEnv.GetGraph()

    paramExtensiveScan = cgiEnv.get_parameters(paramkey_extensive_scan)

    # By default, uses a small map of possible connection strings keyword.
    # Otherwise it is very slow to scan the whole process memory.
    if paramExtensiveScan:
        map_rgx = survol_odbc.mapRgxODBC
    else:
        map_rgx = survol_odbc.mapRgxODBC_Light

    aggreg_dsns = _get_aggreg_dsns(pidint, map_rgx)

    node_process = lib_uris.gUriGen.PidUri(pidint)

    # TODO: Add a parameter to choose between light and heavy connection string definition.

    # TODO: Eliminate aggregated strings containing one or two tokens,
    # because they cannot be genuine DSNs.
    # 29812569: SERVER=\MYMACHINE
    # 34515016: Driver={SQL Server};Server=.\SQLEXPRESS;Database=ExpressDB;Trusted_Connection=yes
    # 34801013: SERVER=\MYMACHINE
    # 35634904: Driver={SQL Server};Server=.\SQLEXPRESS;Database=ExpressDB;Trusted_Connection=yes

    for aggreg_offset in aggreg_dsns:
        # Do not take the character before the keyword.
        aggreg_dsn_raw = aggreg_dsns[aggreg_offset]

        # Replaces all non-printable characters by spaces.
        # This should be done now by the regular expressions, but better be sure.
        aggreg_dsn = re.sub(b'[\x00-\x1f\x7f-\xff]+', b' ', aggreg_dsn_raw)

        # This should contain Ascii, convertible to UTF-8, but if the regular expression catch something else,
        # this decode throw: 'utf-8' codec can't decode bytes in position 3768-3769: invalid continuation byte.
        aggreg_dsn = aggreg_dsn.decode("utf-8", "ignore")
        dsn_full = str(aggreg_offset) + ": " + aggreg_dsn
        logging.debug("aggreg_offset=%s dsn_full=%s", aggreg_offset, dsn_full)
        grph.add((node_process, pc.property_information, lib_util.NodeLiteral(dsn_full)))

        ### NO! Confusion between DSN and connection string.
        # All the existing code does: ODBC_ConnectString = survol_odbc_dsn.MakeOdbcConnectionString(dsnNam)
        # which basically creates "DSN=dsvNam;PWD=..." but here we already have the connection string.
        # TODO: Should we assimilate both ???
        node_dsn = survol_odbc_dsn.MakeUri(aggreg_dsn)
        grph.add((node_process, pc.property_odbc_dsn, node_dsn))
        # Fix this message.
        grph.add((node_dsn, pc.property_odbc_driver, lib_util.NodeLiteral("ODBC driver")))

    cgiEnv.OutCgiRdf()


def DatabaseEnvParams(processId):
    """
    This is used by query_vs_databases.py, to associate connection strigns with queries found in memory.
    """
    dsn_list = []
    aggreg_dsns = _get_aggreg_dsns(int(processId))

    for aggreg_offset in aggreg_dsns:
        # Do not take the character before the keyword.
        agg_dsn = aggreg_dsns[aggreg_offset]

        # TODO: Passwords are not crypted here, so decrypting will not work.

        dsn_list.append({survol_odbc.CgiPropertyDsn(): agg_dsn})

    # Should be odbc.
    return "sqlserver/query", dsn_list


if __name__ == '__main__':
    Main()

# Searching for OLE connections strings.
#
# https://www.connectionstrings.com/formating-rules-for-connection-strings/
#
# Looking for key-value pairs, sparated by ";". Possibly spaces betfore and after the semicolon.
# Some parameters imply the creation of nodes.
#
# Provider = SQLOLEDB.1; Initial Catalog = scnXYZliv; Persist Security Info = False; Data Source = HOSTNAME\SC4NXYZ;User ID=yyyyy;Password=xxxxx;Trusted_Connection=False;
#
# Provider=Microsoft.Jet.OLEDB.4.0;Data Source=http://www.websitewithhtmltable.com/tablepage.html;Extended Properties="HTML Import;HDR=YES;IMEX=1";
#
# DRIVER={Empress ODBC Interface [Default]};Server=serverName;Port=6322;UID=userName;PWD=password;Database=dbName;
#
# Driver={CData ODBC Driver for Exchange 2015};Server='https://outlook.office365.com/EWS/Exchange.asmx';Platform='Exchange_Online';User='myUser@mydomain.onmicrosoft.com';Password='myPassword';
#
# DRIVER={InterSystems ODBC};SERVER=myServerAddress;PORT=12345;DATABASE=myDataBase;
# PROTOCOL=TCP;STATIC CURSORS=1;UID=myUsername;PWD=myPassword;
#
# DRIVER={InterSystems ODBC};SERVER=myServerAddress;PORT=12345;DATABASE=myDataBase;
# UID=myUsername;PWD=myPassword;
#
# Provider=MSDASQL;DRIVER=Ingres;SRVR=xxxxx;DB=xxxxx;Persist Security Info=False;
# Uid=myUsername;Pwd=myPassword;SELECTLOOPS=N;Extended Properties="SERVER=xxxxx;
# DATABASE=xxxxx;SERVERTYPE=INGRES";

# https://www.sqlservercentral.com/Forums/Topic1101451-392-1.aspx
# A DSN (Data Source Name) is an identifier which defines a data source for an ODBC driver.
# It consists of information such as: Database name, Directory, Database driver, User ID, Password
#
# A connection string specifies information about a data source and the means of connecting to it.
# It is passed in code to an underlying driver or provider in order to initiate the connection
#
# DSN use in a connection string
#
# Example
# Data Source=myServerAddress;Initial Catalog=myDataBase;User Id=myUsername;Password=myPassword;
#
# myServerAddress is a DSN and whole string is called Connection String