#!/usr/bin/env python

"""
ODBC Data sources (ODBC module)
"""

import sys
import lib_util
import lib_common
from lib_properties import pc

import odbc

from sources_types.odbc import dsn as survol_odbc_dsn

Usable = lib_util.UsableWindows

# TODO: Maybe this script should be renamed enumerate_odbc_something ?

# https://github.com/mkleehammer/pyodbc/wiki/Connecting-to-SQL-Server-from-Windows
#    {SQL Server} - released with SQL Server 2000
#    {SQL Native Client} - released with SQL Server 2005 (also known as version 9.0)
#    {SQL Server Native Client 10.0} - released with SQL Server 2008
#    {SQL Server Native Client 11.0} - released with SQL Server 2012
# The connection strings for all these drivers are essentially the same, for example:
# DRIVER={SQL Server Native Client 11.0};SERVER=test;DATABASE=test;UID=user;PWD=password
# conn = pyodbc.connect(r'DSN=mynewdsn;UID=user;PWD=password')

# The code would be odbc.SQL_FETCH_FIRST to get all DSNs.
def DisplayDsns(grph,fetch_code,dsn_type):
	odbc_iter_code = fetch_code

	propDsnType = lib_common.MakeProp("Source type")
	littDsnType = lib_common.NodeLiteral(dsn_type)

	while True:
		source = odbc.SQLDataSources(odbc_iter_code)
		if source == None:
			break
		# TODO: Prints the description and other data.
		dsn, driver = source
		DEBUG("dsn=%s driver=%s type=%s", dsn, driver, dsn_type)
		odbc_iter_code = odbc.SQL_FETCH_NEXT

		# This creates a connection string.
		nodeDsn = survol_odbc_dsn.MakeUri( "DSN=" + dsn )
		grph.add( (lib_common.nodeMachine, pc.property_odbc_dsn, nodeDsn ) )
		grph.add( (nodeDsn, pc.property_odbc_driver, lib_common.NodeLiteral(driver) ) )
		grph.add( (nodeDsn, propDsnType, littDsnType ) )


def show_odbc_sources(grph):
	DEBUG("odbc=%s", str(dir(odbc)) )

	DisplayDsns(grph,odbc.SQL_FETCH_FIRST_USER,"User")
	DisplayDsns(grph,odbc.SQL_FETCH_FIRST_SYSTEM,"System")

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()
	show_odbc_sources(grph)

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
