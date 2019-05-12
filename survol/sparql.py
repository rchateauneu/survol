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

    qry = envSparql.Query()

    lstTriples = list( lib_sparql.GenerateTriplesList(qry) )
    lstEntities = lib_sparql.ExtractEntities(lstTriples)


    #
    for one_entity in lstEntities:
        pass


    envSparql.WriteTripleStoreAsString(grph)



if __name__ == '__main__':
    Main()

