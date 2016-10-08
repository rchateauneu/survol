#!/usr/bin/python

"""
Information about an ODBC connection.
"""

import sys
import rdflib
import lib_util
import lib_common
from lib_properties import pc
from sources_types import odbc as survol_odbc
from sources_types.odbc import dsn as survol_odbc_dsn

try:
	import pyodbc
except ImportError:
	lib_common.ErrorMessageHtml("pyodbc Python library not installed")

def Main():

	cgiEnv = lib_common.CgiEnv()

	grph = rdflib.Graph()

	dsnNam = cgiEnv.m_entity_id_dict["Dsn"]

	sys.stderr.write("dsn=(%s)\n" % dsnNam )

	nodeDsn = survol_odbc_dsn.MakeUri( dsnNam )

	ODBC_ConnectString = survol_odbc_dsn.MakeOdbcConnectionString(dsnNam)

	try:
		cnxn = pyodbc.connect(ODBC_ConnectString)
		sys.stderr.write("Connected: %s\n" % dsnNam)

		# for prmstr in sqlgetinfo_params:
		for prmstr in dir(pyodbc):
			if not prmstr.startswith("SQL_"):
				continue
			sys.stderr.write("prmstr: %s\n" % prmstr)

			# Some keywords are not interesting. This is a bit arbitrary.
			if prmstr in ["SQL_KEYWORDS"]:
				continue

			nicestr = prmstr[4:].replace("_"," ").capitalize()

			prop = lib_common.MakeProp(nicestr)

			try:
				# prm = getattr(pyodbc,"SQL_"+prmstr)
				prm = getattr(pyodbc,prmstr)
			# except AttributeError:
			except:
				grph.add( (nodeDsn, prop, rdflib.Literal("Unavailable") ) )
				continue

			try:
				prm_value = cnxn.getinfo(prm)
			except:
				#txt = str( sys.exc_info()[1] )
				#grph.add( (nodeDsn, prop, rdflib.Literal(txt) ) )
				continue

			try:
				grph.add( (nodeDsn, prop, rdflib.Literal(prm_value) ) )
			except:
				txt = str( sys.exc_info()[1] )
				grph.add( (nodeDsn, prop, rdflib.Literal(txt) ) )
				continue

	except Exception:
		exc = sys.exc_info()[0]
		lib_common.ErrorMessageHtml("nodeDsn=%s Unexpected error:%s" % ( dsnNam, str( sys.exc_info() ) ) )

	# cgiEnv.OutCgiRdf(grph)
	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()

