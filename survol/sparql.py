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

# HTTP_HOST and SERVER_NAME and SERVER_PORT

def Main():
    envSparql = lib_sparql.SparqlEnvironment()

    grph = lib_kbase.MakeGraph()

    sparql_query = envSparql.Query()

    itr_tuple_objects = lib_sparql.QueryEntities(sparql_query, lib_sparql.SurvolExecuteQueryCallback)

    grph = lib_kbase.MakeGraph()

    list_tuple_objects = list(itr_tuple_objects)
    for one_objects_tuple in list_tuple_objects:
        lib_sparql.ObjectsToGrph(grph,one_objects_tuple)

    envSparql.WriteTripleStoreAsString(grph)



if __name__ == '__main__':
    Main()

