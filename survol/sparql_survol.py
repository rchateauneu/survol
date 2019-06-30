#!/usr/bin/python

"""
This SPARQL server translates SPARQL queries into Survol data model.
"""

# See Experimental/Test_package_sparqlwrapper.py

import os
import sys
import lib_util
import lib_kbase
import lib_sparql
import lib_sparql_callback_survol

# HTTP_HOST and SERVER_NAME and SERVER_PORT

def Main():
    envSparql = lib_sparql.SparqlEnvironment()

    sparql_query = envSparql.Query()

    grph = lib_kbase.MakeGraph()

    lib_sparql.QueryToGraph(
        grph,
        sparql_query,
        lib_sparql_callback_survol.SurvolCallbackSelect,
        lib_sparql_callback_survol.SurvolCallbackAssociator)

    envSparql.WriteTripleStoreAsString(grph)



if __name__ == '__main__':
    Main()

