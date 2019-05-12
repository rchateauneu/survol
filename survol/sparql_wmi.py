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

    qry = envSparql.Query()

    lstTriples = list( lib_sparql.GenerateTriplesList(qry) )
    dictEntities = lib_sparql.ExtractEntitiesWithConstantAttributes(lstTriples)

    # This returns an array of WMI queries which must be executed independently,
    # and their results mixed in one triple-store.
    # TODO: Joins might be possible.

    wmiHost = None
    nameSpace = "root\\CIMV2" # Default namespace.

    connWmi = lib_wmi.WmiConnect(wmiHost,nameSpace)

    for variable_name in dictEntities:
        class_name, key_values = lib_sparql.ExtractClass( dictEntities[variable_name] )
        aQry = lib_util.SplitMonikToWQL(key_values,class_name)

        objList = connWmi.query(aQry)

        mapPropUnits = lib_wmi.WmiDictPropertiesUnit(connWmi, class_name)

        # In the general case, there will be several objects.
        # The instance node must be created following Survol's ontology ?
        displayNoneValues = False
        for objWmi in objList:

            wmiInstanceUrl = lib_util.EntityUrlFromMoniker( cgiMoniker )

            # Possible problem because this associates a single URL with possibly several objects ??
            wmiInstanceNode = lib_common.NodeUrl(wmiInstanceUrl)

            DEBUG("entity_wmi.py objWmi=[%s]", str(objWmi) )

            # See DispWmiProperties in entity_wmi.py
            lstKeyValues = lib_wmi.WmiKeyValues(connWmi, objWmi, displayNoneValues, class_name)
            for prpProp, prpValue in lstKeyValues:
                grph.add( ( wmiInstanceNode, prpProp, prpValue ) )

            # TODO: For the associators and the references, see entity_wmi.py

    envSparql.WriteTripleStoreAsString(grph)

if __name__ == '__main__':
    Main()


