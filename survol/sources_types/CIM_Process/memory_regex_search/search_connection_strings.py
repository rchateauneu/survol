#!/usr/bin/env python

"""
Scan process memory for ODBC connection strings
"""

import os
import sys
import re
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


def GetAggregDsns(pidint,mapRgx):
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
		rgxDSN = "|".join([ "[; ]*" + key + " *= *" + mapRgx[key] + " *" for key in mapRgx ])
		# This works also. Both are very slow.
		# rgxDSN = "|".join([ ";? *" + key + " *= *" + survol_odbc.mapRgxODBC[key] + " *" for key in survol_odbc.mapRgxODBC ])
		DEBUG("rgxDSN=%s",rgxDSN)


		# TODO: OPTIONALLY ADD NON-ASCII CHAR AT THE VERY BEGINNING. SLIGHTLY SAFER AND FASTER.
		# rgxDSN = "[^a-zA-Z]" + regDSN

		# Here we receive the matched keywords and their offset in memory.
		# We try to aggregate them if they are contiguous.
		# This will work less if we used a smaller set of DSN connecton strings keywords.
		# This could be fixed with theese remarks:
		# (1) If the difference of offsets is small.
		# (2) Try to extensively scan the memory (All DSN keywords) in the interval of detected common keywords.
		resuMatches = memory_regex_search.GetRegexMatches(pidint,rgxDSN, re.IGNORECASE)

		for matchedOffset in resuMatches:
			matchedStr = resuMatches[matchedOffset]
			dsnToken = str(matchedOffset) + " = " + matchedStr + " = " + str(matchedOffset + len(matchedStr))
			DEBUG("dsnODBC=%s",dsnToken)

		sortedKeys = sorted(resuMatches.keys())
		aggregDsns = dict()
		lastOffset = 0
		currOffset = 0
		for theOff in sortedKeys:
			currMtch = resuMatches[theOff]
			nextOffset = theOff + len(currMtch)
			DEBUG("lastOffset=%d nextOffset=%d currMtch=%s",lastOffset,nextOffset,currMtch)
			#if lastOffset == 0:
			#	lastOffset = nextOffset
			#	aggregDsns[lastOffset] = currMtch
			#	continue
			if lastOffset == theOff:
				aggregDsns[currOffset] += currMtch
			else:
				# This starts a new DSN string.
				currOffset = theOff
				aggregDsns[currOffset] = currMtch
			lastOffset = nextOffset

		# TODO: Eliminate aggrehated strings containing one or two tokens,
		# because they cannot be genuine DSNs.
		# 29812569: SERVER=\RCHATEAU-HP
		# 34515016: Driver={SQL Server};Server=.\SQLEXPRESS;Database=ExpressDB;Trusted_Connection=yes
		# 34801013: SERVER=\RCHATEAU-HP
		# 35634904: Driver={SQL Server};Server=.\SQLEXPRESS;Database=ExpressDB;Trusted_Connection=yes

		return aggregDsns

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

	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Error:%s. Protection ?"%str(exc))




def Main():
	paramkeyExtensiveScan = "Extensive scan"

	# Beware that unchecked checkboxes are not posted, i.e. boolean variables set to False.
	# http://stackoverflow.com/questions/1809494/post-the-checkboxes-that-are-unchecked
	cgiEnv = lib_common.CgiEnv( parameters = { paramkeyExtensiveScan : False })
	pidint = int( cgiEnv.GetId() )

	grph = cgiEnv.GetGraph()

	paramExtensiveScan = cgiEnv.GetParameters( paramkeyExtensiveScan )

	# By default, uses a small map of possible connection strings keyword.
	# Otherwise it is very slow to scan the whole process memory.
	if paramExtensiveScan:
		mapRgx = survol_odbc.mapRgxODBC
	else:
		mapRgx = survol_odbc.mapRgxODBC_Light

	aggregDsns = GetAggregDsns(pidint,mapRgx)

	node_process = lib_common.gUriGen.PidUri(pidint)

	# TODO: Add a parameter to choose between light and heavy connection string definition.

	# TODO: Eliminate aggregated strings containing one or two tokens,
	# because they cannot be genuine DSNs.
	# 29812569: SERVER=\RCHATEAU-HP
	# 34515016: Driver={SQL Server};Server=.\SQLEXPRESS;Database=ExpressDB;Trusted_Connection=yes
	# 34801013: SERVER=\RCHATEAU-HP
	# 35634904: Driver={SQL Server};Server=.\SQLEXPRESS;Database=ExpressDB;Trusted_Connection=yes

	for aggregOffset in aggregDsns:
		# Do not take the character before the keyword.
		aggregDSN = aggregDsns[aggregOffset]
		dsnFull = str(aggregOffset) + ": " + aggregDSN
		DEBUG("aggregOffset=%s dsnFull=%s",aggregOffset,dsnFull)
		grph.add( ( node_process, pc.property_information, lib_common.NodeLiteral(dsnFull) ) )

		### NO! Confusion between DSN and connection string.
		# All the existing code does: ODBC_ConnectString = survol_odbc_dsn.MakeOdbcConnectionString(dsnNam)
		# which basically creates "DSN=dsvNam;PWD=..." but here we already have the connection string.
		# TODO: Should we assimilate both ???
		nodeDsn = survol_odbc_dsn.MakeUri( aggregDSN )
		grph.add( (node_process, pc.property_odbc_dsn, nodeDsn ) )
		# Fix this message.
		grph.add( (nodeDsn, pc.property_odbc_driver, lib_common.NodeLiteral("ODBC driver") ) )



	cgiEnv.OutCgiRdf()

# This is used by query_vs_databases.py, to associate connection strigns with queries found in memory.
def DatabaseEnvParams(processId):

	dsnList = []
	aggregDsns = GetAggregDsns(int(processId))

	for aggregOffset in aggregDsns:
		# Do not take the character before the keyword.
		aggDSN = aggregDsns[aggregOffset]

		# TODO: Passwords are not crypted here, so decrypting will not work.

		dsnList.append( { survol_odbc.CgiPropertyDsn(): aggDSN } )

	# Should be odbc.
	return ( "sqlserver/query", dsnList )



if __name__ == '__main__':
	Main()



# RECHERCHE DE CHAINES DE CONNEXION OLE DB
#
# https://www.connectionstrings.com/formating-rules-for-connection-strings/
#
# Donc on cherche des paires clef-valeur, separees par ";". Il peut y avoir des espaces de part et d autre du ";".
# Certains parametres vont entrainer la creation de noeuds (C est meme le but de l operation).
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