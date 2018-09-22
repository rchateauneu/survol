#!/usr/bin/python

"""
Nmap MS-SQL discovery

Discovers Microsoft SQL servers in the same broadcast domain.
"""

import re
import sys
import socket
import xml.dom.minidom
import lib_util
import lib_common
import lib_credentials
from lib_properties import pc

# If pyodbc is available, it adds a link to the databases.
try:
	import pyodbc
	from sources_types.odbc import dsn as survol_odbc_dsn
except ImportError:
	pyodbc = None


# https://nmap.org/nsedoc/scripts/broadcast-ms-sql-discover.html
#
# Starting Nmap 7.12 ( https://nmap.org ) at 2017-11-30 07:45 GMT
# Pre-scan script results:
# | broadcast-ms-sql-discover:
# |   192.168.0.14 (RCHATEAU-HP)
# |     [192.168.0.14\SQLEXPRESS]
# |       Name: SQLEXPRESS
# |       Product: Microsoft SQL Server 2012
# |       TCP port: 1433
# |_      Named pipe: \\192.168.0.14\pipe\MSSQL$SQLEXPRESS\sql\query
# WARNING: No targets were specified, so 0 hosts scanned.
# Nmap done: 0 IP addresses (0 hosts up) scanned in 5.76 seconds
#
def AddOdbcNode(grph,machNam,srvName,tcpPort):
	# cn = pyodbc.connect('DRIVER={ODBC Driver 13 for SQL Server};SERVER=192.168.0.14;PORT=1433;UID=essaisql;PWD=xyz')
	if lib_util.isPlatformLinux:
		driverName = "ODBC Driver 13 for SQL Server"
	else:
		driverName = "ODBC Driver 13 for SQL Server"

	# credKey = "RCHATEAU-HP\\SQLEXPRESS"
	credKey = "%s\\%s" % ( machNam, srvName )
	DEBUG("credKey=%s",credKey)
	aCred = lib_credentials.GetCredentials("SqlExpress", credKey )

	if aCred:

		strDsn = 'DRIVER={%s};SERVER=%s;PORT=%s;UID=%s;PWD=%s' % (driverName, machNam, tcpPort, aCred[0], aCred[1] )
		DEBUG("strDsn=%s",strDsn)

		### cn = pyodbc.connect(strDsn)
		# nodeDsn = survol_odbc_dsn.MakeUri( "DSN=" + strDsn )
		nodeDsn = survol_odbc_dsn.MakeUri( strDsn )
		grph.add( (lib_common.nodeMachine, pc.property_odbc_dsn, nodeDsn ) )




def Main():
	cgiEnv = lib_common.CgiEnv()

	args = ["nmap", '-oX', '-', '--script', "broadcast-ms-sql-discover", ]

	# The returned IP address is wrong when launched from a Windows machine where the DB is running.
	p = lib_common.SubProcPOpen(args)

	grph = cgiEnv.GetGraph()

	(nmap_last_output, nmap_err) = p.communicate()

	dom = xml.dom.minidom.parseString(nmap_last_output)

	# <script id="broadcast-ms-sql-discover" output="&#xa; 192.168.0.14 (RCHATEAU-HP)&#xa; [192.168.0.14\SQLEXPRESS]&#xa; Name: SQLEXPRESS&#xa; Product: Microsoft SQL Server 2012&#xa; TCP port: 1433&#xa; Named pipe: \\192.168.0.14\pipe\MSSQL$SQLEXPRESS\sql\query&#xa;"/>
	for aScript in dom.getElementsByTagName('script'):
		anOutput = aScript.getAttributeNode('output').value.strip()
		DEBUG("anOutput=%s",str(anOutput))
		arrSplit = [ aWrd.strip() for aWrd in anOutput.split("\n") ]

		sys.stderr.write("arrSplit=%s\n"%str(arrSplit))

		# "192.168.0.14 (RCHATEAU-HP)"
		theMachFull = arrSplit[0].strip()
		reMach = re.match("([^ ]*) *\(([^)]*)\)", theMachFull)
		if reMach:
			machIp = reMach.group(1)
			machNam = reMach.group(2)

			nodeHost = lib_common.gUriGen.HostnameUri( machNam )
			grph.add( ( nodeHost, lib_common.MakeProp("IP address"), lib_common.NodeLiteral( machIp ) ) )
		else:
			nodeHost = lib_common.gUriGen.HostnameUri( theMachFull )
			machIp = None
			machNam = theMachFull

		theNameDB = arrSplit[1].strip()
		grph.add( ( nodeHost, lib_common.MakeProp("Sql server instance"), lib_common.NodeLiteral( theNameDB ) ) )

		tcpPort = None
		srvName = None

		# RCHATEAU-HP	IP_address	192.168.0.14
		# Name	SQLEXPRESS
		# Named_pipe	\\192.168.0.14\pipe\MSSQL$SQLEXPRESS\sql\query
		# Product	Microsoft SQL Server 2012
		# Sql_server_instance	[192.168.0.14\SQLEXPRESS]
		# TCP_port	1433
		for oneWrd in arrSplit[2:]:
			DEBUG("oneWrd=%s",oneWrd)
			oneSplit = [ aSplit.strip() for aSplit in oneWrd.split(":") ]
			oneKey = oneSplit[0]

			if len(oneSplit) > 1:
				oneVal = ":".join(oneSplit[1:])
				# In case there would be more than one ":"
				grph.add( ( nodeHost, lib_common.MakeProp(oneKey), lib_common.NodeLiteral( oneVal ) ) )
				if oneKey == "TCP port":
					tcpPort = oneVal
				elif oneKey == "Name":
					srvName = oneVal
				else:
					pass
			else:
				grph.add( ( nodeHost, pc.property_information, lib_common.NodeLiteral(oneKey) ) )



		if tcpPort and srvName and pyodbc:
			AddOdbcNode(grph,machNam,srvName,tcpPort)
			AddOdbcNode(grph,machIp,srvName,tcpPort)


	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()

# pyodbc installation on Linux:
# [root@fedora22 rchateau]# yum install unixODBC-devel
#
# [rchateau@fedora22 survol]$ python
# Python 2.7.10 (default, Jun 20 2016, 14:45:40)
# [GCC 5.3.1 20160406 (Red Hat 5.3.1-6)] on linux2
# Type "help", "copyright", "credits" or "license" for more information.
# >>> import pyodbc
# >>> pyodbc.drivers()
# ['PostgreSQL', 'MySQL']
# >>> conn = pyodbc.connect('DRIVER={PostgreSQL};SERVER=192.168.0.14;PORT=1433;DATABASE=SQLEXPRESS;UID=rchateau;PWD=xxxxxxx;TDS_VERSION=7.2')
# Traceback (most recent call last):
# File "<stdin>", line 1, in <module>
# pyodbc.Error: ('01000', u"[01000] [unixODBC][Driver Manager]Can't open lib '/usr/lib64/psqlodbcw.so' : file not found (0) (SQLDriverConnect)")
# >>> conn = pyodbc.connect('DRIVER={MySQL};SERVER=192.168.0.14;PORT=1433;DATABASE=SQLEXPRESS;UID=rchateau;PWD=kennwert;TDS_VERSION=7.2')
# Traceback (most recent call last):
# File "<stdin>", line 1, in <module>
# pyodbc.Error: ('01000', u"[01000] [unixODBC][Driver Manager]Can't open lib '/usr/lib64/libmyodbc5.so' : file not found (0) (SQLDriverConnect)")
#
# C:\Users\rchateau>python
# Python 2.7.10 (default, May 23 2015, 09:44:00) [MSC v.1500 64 bit (AMD64)] on win32
# Type "help", "copyright", "credits" or "license" for more information.
# >>> import pyodbc
# >>> pyodbc.drivers()
# ['SQL Server', 'SQL Server Native Client 11.0', 'Oracle in XE']
#
# https://docs.microsoft.com/en-us/sql/connect/odbc/linux-mac/installing-the-microsoft-odbc-driver-for-sql-server
#
# >>> pyodbc.drivers()
# ['PostgreSQL', 'MySQL', 'ODBC Driver 13 for SQL Server']
#
# cn = pyodbc.connect('DRIVER={ODBC Driver 13 for SQL Server};SERVER=192.168.0.14;PORT=1433;UID=essaisql;PWD=xyz')
# cursor = cn.cursor()
# cursor.execute("select name from sys.databases")
# rows = cursor.fetchall()
# [(u'master', ), (u'tempdb', ), (u'model', ), (u'msdb', ), (u'ExpressDB', ), (u'Insight_v50_0_81912336', )]

# nodeDsn = survol_odbc_dsn.MakeUri( "DSN=" + dsn )
# grph.add( (lib_common.nodeMachine, pc.property_odbc_dsn, nodeDsn ) )

