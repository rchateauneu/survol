#!/usr/bin/python

"""
Scan process memory for ODBC Data Source Names (DSN)
"""

import os
import sys
import re
import lib_util
import lib_common
from lib_properties import pc

from sources_types import CIM_Process
from sources_types.CIM_Process import memory_regex_search
from sources_types.odbc import dsn as survol_odbc_dsn

# ODBC conneciton strings, on Windows only.
Usable = lib_util.UsableWindows

def Main():
	cgiEnv = lib_common.CgiEnv()
	pidint = int( cgiEnv.GetId() )

	grph = cgiEnv.GetGraph()

	node_process = lib_common.gUriGen.PidUri(pidint)






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
		mapRgxODBC = {
			"PROVIDER"           : "[ a-zA-Z0-9._]+",
			"DRIVER"             : "\{[^}]*\}",
			"DATABASE"           : "[ a-zA-Z0-9._]+",
			"SERVER"             : "[- a-zA-Z0-9\._\\\]+",
			"PROTOCOL"           : "[a-zA-Z]+",
			"PORT"               : "[0-9]+",
			"DB"                 : "[a-zA-Z0-9._]*",
			"DATA SOURCE"        : "[a-zA-Z_0-9\\/]+",
			"TRUSTED_CONNECTION" : "[a-zA-Z]*"
		}

		# Not letter, then the keyword, then "=", then the value regex, then possibly the delimiter.
		rgxDSN = "|".join([ "[; ]*" + key + " *= *" + mapRgxODBC[key] + " *" for key in mapRgxODBC ])
		# rgxDSN = "|".join([ "[^a-zA-Z_ ]" + key + " *= *" + mapRgxODBC[key] + " *" for key in mapRgxODBC ])
		# rgxDSN = "|".join([ "[^a-zA-Z_ ]" + key + " *= *" + mapRgxODBC[key] + " *" for key in mapRgxODBC ])
		# rgxDSN = "|".join([ key + " *= *" + mapRgxODBC[key] + " *;?" for key in mapRgxODBC ])
		sys.stderr.write("rgxDSN=%s\n"%rgxDSN)

		resuMatches = memory_regex_search.GetRegexMatches(pidint,rgxDSN, re.IGNORECASE)

		for matchedOffset in resuMatches:
			matchedStr = resuMatches[matchedOffset]
			dsnToken = str(matchedOffset) + " = " + matchedStr + " = " + str(matchedOffset + len(matchedStr))
			sys.stderr.write("dsnODBC=%s\n"%dsnToken)

		sortedKeys = sorted(resuMatches.keys())
		aggregDsns = dict()
		lastOffset = 0
		currOffset = 0
		for theOff in sortedKeys:
			currMtch = resuMatches[theOff]
			nextOffset = theOff + len(currMtch)
			sys.stderr.write("lastOffset=%d nextOffset=%d currMtch=%s\n"%(lastOffset,nextOffset,currMtch))
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

		for aggregOffset in aggregDsns:
			# Do not take the character before the keyword.
			aggregDSN = aggregDsns[aggregOffset]
			sys.stderr.write("aggregOffset=%s\n"%aggregOffset)
			# dsnToken = str(matchedOffset) + " = " + matchedStr[1:]
			dsnFull = str(aggregOffset) + ": " + aggregDSN
			sys.stderr.write("dsnFull=%s\n"%dsnFull)
			grph.add( ( node_process, pc.property_information, lib_common.NodeLiteral(dsnFull) ) )

			nodeDsn = survol_odbc_dsn.MakeUri( aggregDSN )
			grph.add( (node_process, pc.property_odbc_dsn, nodeDsn ) )
			grph.add( (nodeDsn, pc.property_odbc_driver, lib_common.NodeLiteral("Le driver") ) )


		# TODO: Instead of just displaying the DSN, connect to it, list tables etc...

	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Error:%s. Protection ?"%str(exc))

	cgiEnv.OutCgiRdf()

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
