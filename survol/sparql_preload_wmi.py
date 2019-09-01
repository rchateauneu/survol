#!/usr/bin/env python

# This uses exclusively data from WMI.
# This is used only for tests.

"""
This RDF server translates SPARQL queries into WMI data model.
"""
import cgitb
cgitb.enable(format="txt")

import lib_kbase
import lib_sparql
import lib_wmi
import lib_util
import logging

# This is a SPARQL server which executes the query with WMI data.
# It loads data from WMI unconditionally.
# This returns RDF data, which is different of what a Sparql endpoint returns
def Main():
    lib_util.SetLoggingConfig(logging.ERROR)
    envSparql = lib_sparql.SparqlEnvironment()

    grph = lib_kbase.MakeGraph()

    sparql_query = envSparql.Query()

    lib_sparql.QueryToGraph(grph, sparql_query, lib_wmi.WmiSparqlCallbackApi() )

    envSparql.WriteTripleStoreAsString(grph)

if __name__ == '__main__':
    Main()


