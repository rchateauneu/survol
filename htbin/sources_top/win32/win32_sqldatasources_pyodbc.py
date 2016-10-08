#!/usr/bin/python

"""
ODBC Data sources (pyODBC module)
"""

import sys
import rdflib
import lib_util
import lib_common
from lib_properties import pc

import pyodbc
from sources_types.odbc import dsn as survol_odbc_dsn

# http://code.activestate.com/recipes/578815-printing-list-of-odbc-data-sources-with-pyodbc-mod/

def display_data_sources(grph):
	sources = pyodbc.dataSources()

	for dsn in sources:
		driver = sources[dsn]

		sys.stderr.write("dsn=%s driver=%s\n" % ( dsn, driver) )

		nodeDsn = survol_odbc_dsn.MakeUri( dsn )
		grph.add( (lib_common.nodeMachine, pc.property_odbc_dsn, nodeDsn ) )
		grph.add( (nodeDsn, pc.property_odbc_driver, rdflib.Literal(driver) ) )

def Main():
	if not lib_util.isPlatformWindows:
		lib_common.ErrorMessageHtml("ODBC Data sources only on Windows platforms")

	cgiEnv = lib_common.CgiEnv()

	grph = rdflib.Graph()
	display_data_sources(grph)

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
