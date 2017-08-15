#!/usr/bin/python

"""
Scan process memory for ODBC dsns
"""

import os
import sys
import re
import lib_util
import lib_common
from lib_properties import pc

from sources_types import CIM_Process
from sources_types.CIM_Process import memory_regex_search

# ODBC conneciton strings, on Windows only.
Usable = lib_util.UsableWindows

def Main():
	cgiEnv = lib_common.CgiEnv()
	pidint = int( cgiEnv.GetId() )

	grph = cgiEnv.GetGraph()

	node_process = lib_common.gUriGen.PidUri(pidint)

	try:
		rgxDSN = "PROVIDER *= *[a-zA-Z0-9._]|Driver *= \{[^}]*\}*"

		resu = memory_regex_search.GetRegexMatches(pidint,rgxDSN, re.IGNORECASE)

		for dsnODBC in resu:
			sys.stderr.write("dsnODBC=%s\n"%dsnODBC)
			grph.add( ( node_process, pc.property_rdf_data_nolist1, lib_common.NodeLiteral(dsnODBC) ) )

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
