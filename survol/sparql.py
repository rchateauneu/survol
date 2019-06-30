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
import lib_export_ontology

# Ca n est pas la meme chose que les trois scripts specifiques qui prechargent le triplestore
# et renvoient sont contenu.
# Ici, on precharge le triplestore, mais on renvoie le  result de la requete Sparql.

# Ca doit remplacer aussi la recherche: Strings etc..., recherche sur des paths
# Il faudrait renvoyer des resultats au fur et a mesure,
# ou passer des parametres de recherche dans la query sparql.


#On vire tout ce qui cvontient type subclass domain etc...
#On ajoute l ontologie.


# For the moment, it just displays the content of the input to standard error,
# so the SparQL protocol can be analysed.

# See Experimental/Test_package_sparqlwrapper.py

# http://timgolden.me.uk/python/downloads/wmi-0.6b.py

lib_util.SetLoggingConfig(logging.DEBUG)


def GenericExecuteQueryCallback(class_name, predicate_prefix, filtered_where_key_values):
    INFO("GenericExecuteQueryCallback class_name=%s where_key_values=%s", class_name, filtered_where_key_values)

    funcCallback = {
        "wmi" : lib_wmi.WmiCallbackSelect,
        "survol" : lib_sparql.SurvolCallbackSelect }[predicate_prefix]

    return funcCallback(class_name, predicate_prefix, filtered_where_key_values)



# This is a SPARQL server which executes the query with WMI data.
def Main():
    envSparql = lib_sparql.SparqlEnvironment()

    grph = lib_kbase.MakeGraph()

    sparql_query = envSparql.Query()

    lib_sparql.QueryToGraph(grph, sparql_query, GenericExecuteQueryCallback)

    # See lib_common.py : This added to any RDF document.
    lib_export_ontology.Grph2Rdf(grph)

    #envSparql.WriteTripleStoreAsString(grph)
    #def lib_export_ontology.AddOntology(old_grph):



if __name__ == '__main__':
    Main()


