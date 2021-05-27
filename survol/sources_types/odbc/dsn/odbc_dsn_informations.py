#!/usr/bin/env python

"""
Information about an ODBC connection.
"""

import sys
import logging

import pyodbc

import lib_util
import lib_common
from lib_properties import pc
from sources_types.odbc import dsn as survol_odbc_dsn


def Main():

    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    dsn_nam = survol_odbc_dsn.GetDsnNameFromCgi(cgiEnv)

    logging.debug("dsn=(%s)", dsn_nam)

    node_dsn = survol_odbc_dsn.MakeUri(dsn_nam)

    odbc_connect_string = survol_odbc_dsn.MakeOdbcConnectionString(dsn_nam)

    try:
        cnxn = pyodbc.connect(odbc_connect_string)
        logging.debug("Connected: %s", dsn_nam)

        for prmstr in dir(pyodbc):
            if not prmstr.startswith("SQL_"):
                continue

            # Some keywords are not interesting. This is a bit arbitrary.
            if prmstr in ["SQL_KEYWORDS"]:
                continue

            nicestr = prmstr[4:].replace("_", " ").capitalize()

            prop = lib_common.MakeProp(nicestr)

            try:
                prm = getattr(pyodbc, prmstr)
            except:
                grph.add((node_dsn, prop, lib_util.NodeLiteral("Unavailable")))
                continue

            try:
                prm_value = cnxn.getinfo(prm)
            except:
                continue

            try:
                grph.add((node_dsn, prop, lib_util.NodeLiteral(prm_value)))
            except Exception as exc:
                txt = str(exc)
                grph.add((node_dsn, prop, lib_util.NodeLiteral(txt)))
                continue

    except Exception as exc:
        lib_common.ErrorMessageHtml("node_dsn=%s Unexpected error:%s" % (dsn_nam, str(exc)))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()

