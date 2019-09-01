#!/usr/bin/env python

"""
It extracts data from Survol only.
This is used only for tests and returns RDF data.
"""

import os
import sys
import logging
import lib_util
import lib_common
import lib_kbase
import lib_sparql
import lib_sparql_callback_survol
import lib_export_ontology

# See Experimental/Test_package_sparqlwrapper.py

# http://timgolden.me.uk/python/downloads/wmi-0.6b.py

lib_util.SetLoggingConfig(logging.DEBUG)

# This is a SPARQL server which executes the query with WMI data.
def Main():
    lib_util.SetLoggingConfig(logging.ERROR)
    envSparql = lib_sparql.SparqlEnvironment()

    grph = lib_kbase.MakeGraph()

    sparql_query = envSparql.Query()

    lib_sparql.QueryToGraph(grph, sparql_query, lib_sparql_callback_survol.SurvolCallbackAp())

    # See lib_common.py : This added to any RDF document.
    ###########lib_export_ontology.Grph2Rdf(grph)

    # At this stage, we must run the Sparql query on the generated RDF triplestore.

    envSparql.WriteTripleStoreAsString(grph)



if __name__ == '__main__':
    Main()

