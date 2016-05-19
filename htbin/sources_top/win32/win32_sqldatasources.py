#!/usr/bin/python

import sys
import rdflib
import lib_util
import lib_common
from lib_properties import pc

import win32com.client
import win32net

import odbc

def show_odbc_sources(grph):
	odbc_iter_code = odbc.SQL_FETCH_FIRST
	while True:
		# System DSN only. For users DSN, I do not know.
		source = odbc.SQLDataSources(odbc_iter_code)
		if source == None:
			break
		# TODO: Prints the description and other data.
		dsn, driver = source
		sys.stderr.write("dsn=%s driver=%s\n" % ( dsn, driver) )
		odbc_iter_code = odbc.SQL_FETCH_NEXT

		nodeDsn = lib_common.gUriGen.OdbcDsnUri( dsn )
		grph.add( (lib_common.nodeMachine, pc.property_odbc_dsn, nodeDsn ) )
		grph.add( (nodeDsn, pc.property_odbc_driver, rdflib.Literal(driver) ) )

def Main():
	if not lib_util.isPlatformWindows:
		lib_common.ErrorMessageHtml("ODBC Data sources only on Windows platforms")

	cgiEnv = lib_common.CgiEnv("ODBC Data sources")

	grph = rdflib.Graph()
	show_odbc_sources(grph)

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
