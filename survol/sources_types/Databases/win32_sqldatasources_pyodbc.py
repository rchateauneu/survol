#!/usr/bin/env python

"""
ODBC Data sources (pyODBC module)
"""

import sys
import lib_util
import lib_common
from lib_properties import pc

import pyodbc
from sources_types.odbc import dsn as survol_odbc_dsn

Usable = lib_util.UsableWindows

# TODO: Maybe it should be called enumerate_odbc_something ?

# http://code.activestate.com/recipes/578815-printing-list-of-odbc-data-sources-with-pyodbc-mod/

def display_data_sources(grph):
	sources = pyodbc.dataSources()

	for dsn in sources:
		driver = sources[dsn]

		DEBUG("dsn=%s driver=%s", dsn, driver )

		# This creates a connection string.
		nodeDsn = survol_odbc_dsn.MakeUri( "DSN=" + dsn )
		grph.add( (lib_common.nodeMachine, pc.property_odbc_dsn, nodeDsn ) )
		grph.add( (nodeDsn, pc.property_odbc_driver, lib_common.NodeLiteral(driver) ) )

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()
	display_data_sources(grph)

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
