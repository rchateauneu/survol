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


__prefix_to_callbacks = {
    "WMI": (lib_wmi.WmiCallbackSelect, lib_wmi.WmiCallbackAssociator),
    "survol": (lib_sparql_callback_survol.SurvolCallbackSelect, lib_sparql_callback_survol.SurvolCallbackAssociator),
}

# This meta-callback dispatches the query to the right data source.
def CallbackSelect(grph, class_name, see_also, where_key_values):
    predicate_prefix, colon, see_also_script = see_also.partition(":")
    DEBUG("UnitTestSeeCallbackSelect predicate_prefix=%s where_key_values=%s", predicate_prefix, where_key_values)

    callback_select = __prefix_to_callbacks[predicate_prefix][0]
    return callback_select(grph, class_name, see_also, where_key_values)

# This meta-callback dispatches the query to the right data source.
def CallbackAssociator(grph, result_class_name, see_also, associator_key_name, subject_path):
    predicate_prefix, colon, see_also_script = see_also.partition(":")
    DEBUG("UnitTestSeeCallbackAssociator predicate_prefix=%s",predicate_prefix)

    callback_select = __prefix_to_callbacks[predicate_prefix][1]
    return callback_select(grph, result_class_name, see_also, associator_key_name, subject_path)


# This is a SPARQL server which executes the query with WMI data.
def Main():
    lib_util.SetLoggingConfig(logging.ERROR)
    envSparql = lib_sparql.SparqlEnvironment()

    grph = lib_kbase.MakeGraph()

    sparql_query = envSparql.Query()

    lib_sparql.QueryToGraph(grph, sparql_query, CallbackSelect, CallbackAssociator)

    # See lib_common.py : This added to any RDF document.
    ###########lib_export_ontology.Grph2Rdf(grph)

    # At this stage, we must run the Sparql query on the generated RDF triplestore.

    envSparql.WriteTripleStoreAsString(grph)

if __name__ == '__main__':
    Main()


