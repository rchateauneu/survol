#!/usr/bin/env python

"""
ODBC Data sources (pyODBC module)
"""

import sys
import logging
import lib_util
import lib_common
from lib_properties import pc

import pyodbc
from sources_types.odbc import dsn as survol_odbc_dsn

Usable = lib_util.UsableWindows


# http://code.activestate.com/recipes/578815-printing-list-of-odbc-data-sources-with-pyodbc-mod/


def display_data_sources(grph):
	# https://stackoverflow.com/questions/41591287/driver-not-found-even-though-its-listed-in-pyodbc-datasources
	# The list produced by pyodbc.dataSources() is misleading because it shows the results
	# from both the 32-bit and 64-bit "Platform".
	# A more reliable way to get the list of available drivers is to use pyodbc.drivers()
	sources = pyodbc.dataSources()

	for dsn in sources:
		driver = sources[dsn]

		logging.debug("dsn=%s driver=%s", dsn, driver)

		# This creates a connection string.
		node_dsn = survol_odbc_dsn.MakeUri("DSN=" + dsn)
		grph.add((lib_common.nodeMachine, pc.property_odbc_dsn, node_dsn))
		grph.add((node_dsn, pc.property_odbc_driver, lib_util.NodeLiteral(driver)))


def Main():
	cgiEnv = lib_common.ScriptEnvironment()

	grph = cgiEnv.GetGraph()
	display_data_sources(grph)

	cgiEnv.OutCgiRdf()


if __name__ == '__main__':
	Main()
