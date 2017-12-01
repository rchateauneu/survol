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
from lib_properties import pc

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
		sys.stderr.write("anOutput=%s\n"%str(anOutput))
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

		theNameDB = arrSplit[1].strip()
		grph.add( ( nodeHost, lib_common.MakeProp("Sql server instance"), lib_common.NodeLiteral( theNameDB ) ) )

		for oneWrd in arrSplit[2:]:
			sys.stderr.write("oneWrd=%s\n"%oneWrd)
			oneSplit = [ aSplit.strip() for aSplit in oneWrd.split(":") ]

			if len(oneSplit) > 1:
				# In case there would be more than one ":"
				grph.add( ( nodeHost, lib_common.MakeProp(oneSplit[0] ), lib_common.NodeLiteral( ":".join(oneSplit[1:]) ) ) )
			else:
				grph.add( ( nodeHost, pc.property_information, lib_common.NodeLiteral( oneSplit[0]) ) )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
