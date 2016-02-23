#!/usr/bin/python

import sys
import rdflib
import lib_util
import lib_common
from lib_properties import pc

cgiEnv = lib_common.CgiEnv("ODBC Data sources")

if not lib_util.isPlatformWindows:
	lib_common.ErrorMessageHtml("ODBC Data sources only on Windows platforms")

try:
	import win32com.client
	import win32net
except ImportError:
	lib_common.ErrorMessageHtml("win32 Python library not installed")

try:
	import odbc
except ImportError:
	lib_common.ErrorMessageHtml("Cannot load module odbc")

grph = rdflib.Graph()


def show_odbc_sources():
	odbc_iter_code = odbc.SQL_FETCH_FIRST
	while True:
		source = odbc.SQLDataSources(odbc_iter_code)
		if source == None:
			break
		dsn, driver = source
		sys.stderr.write("dsn=%s driver=%s\n" % ( dsn, driver) )
		odbc_iter_code = odbc.SQL_FETCH_NEXT

		nodeDsn = lib_common.gUriGen.OdbcDsnUri( dsn )
		grph.add( (lib_common.nodeMachine, pc.property_odbc_dsn, nodeDsn ) )
		grph.add( (nodeDsn, pc.property_odbc_driver, rdflib.Literal(driver) ) )

show_odbc_sources()

cgiEnv.OutCgiRdf(grph)

