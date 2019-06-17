#!/usr/bin/python

# This uses exclusively data from WMI.

"""
This SPARQL server translates SPARQL queries into WMI data model.
"""

import lib_kbase
import lib_sparql
import lib_wmi

# This is a SPARQL server which executes the query with WMI data.
# It loads data from WMI inconditionnaly.
def Main():
    envSparql = lib_sparql.SparqlEnvironment()

    grph = lib_kbase.MakeGraph()

    sparql_query = envSparql.Query()

    lib_sparql.QueryToGraph(grph,sparql_query, lib_wmi.WmiCallbackSelect, lib_wmi.WmiCallbackAssociator)

    envSparql.WriteTripleStoreAsString(grph)

if __name__ == '__main__':
    Main()


