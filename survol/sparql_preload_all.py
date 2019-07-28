#!/usr/bin/python

"""
Mandatory SPARQL end-point

It extracts data from Survol, WMI or WBEM, then runs a Sparql query on the current RDF triplestore.
This triplestore can also be updated by events.
"""

import os
import sys
import logging
import lib_util
import lib_common
import lib_kbase
import lib_sparql
import lib_wmi
import lib_sparql_callback_survol
import lib_export_ontology

# For the moment, it just displays the content of the input to standard error,
# so the SparQL protocol can be analysed.

# See Experimental/Test_package_sparqlwrapper.py

# http://timgolden.me.uk/python/downloads/wmi-0.6b.py

lib_util.SetLoggingConfig(logging.DEBUG)

prefix_to_callbacks = {
    "WMI": lib_wmi.WmiSparqlCallbackApi(),
    "survol": lib_sparql_callback_survol.SurvolSparqlCallbackApi(),
}

objectCallback = lib_sparql.SwitchCallbackApi(prefix_to_callbacks)


# This is a SPARQL server which executes the query with WMI data.
def Main():
    lib_util.SetLoggingConfig(logging.ERROR)
    envSparql = lib_sparql.SparqlEnvironment()

    grph = lib_kbase.MakeGraph()

    sparql_query = envSparql.Query()

    lib_sparql.QueryToGraph(grph, sparql_query, objectCallback)

    # See lib_common.py : This added to any RDF document.
    ###########lib_export_ontology.Grph2Rdf(grph)

    # At this stage, we must run the Sparql query on the generated RDF triplestore.

    envSparql.WriteTripleStoreAsString(grph)

if __name__ == '__main__':
    Main()


