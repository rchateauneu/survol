# This uses exclusively data from WMI.

#!/usr/bin/python

"""
This SPARQL server translates SPARQL queries into Survol data model.
"""

# For the moment, it just displays the content of the input to standard error,
# so the SparQL protocol can be analysed.

# See Experimental/Test_package_sparqlwrapper.py

import os
import sys
import lib_util
import lib_common
import lib_kbase
import lib_sparql
import lib_wmi

# http://timgolden.me.uk/python/downloads/wmi-0.6b.py



# This is a SPARSL server which executes the query with WMI data.
def Main():
    envSparql = lib_sparql.SparqlEnvironment()

    grph = lib_kbase.MakeGraph()

    sparql_query = envSparql.Query()

    dictEntitiesByVariable = lib_sparql.ParseQueryToEntities(sparql_query)
    sys.stderr.write("dictEntitiesByVariable=%s\n"%dictEntitiesByVariable)

    iter_entities_dicts = lib_sparql.QueryEntities(dictEntitiesByVariable, lib_wmi.WmiExecuteQueryCallback, "wmi")

    sys.stderr.write("iter_entities_dicts=%s\n"%dir(iter_entities_dicts))

    for one_dict_entity in iter_entities_dicts:
        pass

    # apres execution du sparql dans le nouveau grph
    envSparql.WriteTripleStoreAsString(grph)

if __name__ == '__main__':
    Main()


