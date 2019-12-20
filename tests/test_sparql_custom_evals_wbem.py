#!/usr/bin/env python

# Many SPARQL examples.
# http://api.talis.com/stores/space/items/tutorial/spared.html?query=SELECT+%3Fp+%3Fo%0D%0A{+%0D%0A++%3Chttp%3A%2F%2Fnasa.dataincubator.org%2Fspacecraft%2F1968-089A%3E+%3Fp+%3Fo%0D%0A}
#
# This is equivalent to:
# Special characters encoded in hexadecimal.
#
# The goal is to extract triples, for two different purposes:
# (1) Transform a Sparql query into WQL: This might work in very simple cases;, for WMI and WBEM.
# (2) Or identify which scripts should be run to feed a local triplestore and get useful data.
# Both purposes need the triples and the classes.

from __future__ import print_function

import os
import sys
import json
import unittest
import pkgutil
import rdflib

from init import *

update_test_path()

# This is what we want to test.
import lib_sparql
import lib_util
import lib_properties
import lib_kbase
import lib_wbem

import lib_sparql_custom_evals

survol_namespace = rdflib.Namespace(lib_sparql_custom_evals.survol_url)
################################################################################

class CUSTOM_EVALS_WBEM_Base_Test(unittest.TestCase):

    def setUp(self):
        # add function directly, normally we would use setuptools and entry_points
        rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_function_wbem'] = lib_sparql_custom_evals.custom_eval_function_wbem

    def tearDown(self):
        if 'custom_eval_function_wbem' in rdflib.plugins.sparql.CUSTOM_EVALS:
            del rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_function_wbem']

################################################################################
class SparqlCallWbemTest(CUSTOM_EVALS_WBEM_Base_Test):
    @unittest.skipIf(not is_linux_wbem(), "WBEM not on this machine. Test skipped.")
    def test_wbem_all_processes(self):
        sparql_query ="""
            SELECT ?the_pid
            WHERE
            { ?url_proc survol:Handle ?the_pid .
              ?url_proc rdf:type survol:CIM_Process .
            }
            """
        rdflib_graph = rdflib.Graph()
        query_result = rdflib_graph.query(sparql_query)
        print(query_result)

    @unittest.skipIf(not is_linux_wbem(), "WBEM not on this machine. Test skipped.")
    def test_wbem_all_computers(self):
        sparql_query ="""
            SELECT ?computer_name
            WHERE
            { ?url_computer survol:Name ?computer_name .
              ?url_computer rdf:type survol:CIM_ComputerSystem .
            }
            """
        rdflib_graph = rdflib.Graph()
        query_result = rdflib_graph.query(sparql_query)
        print(query_result)

    @unittest.skipIf(not is_linux_wbem(), "WBEM not on this machine. Test skipped.")
    def test_server_remote_wbem(self):
        # This selects all processes on the remote machine, as seen by WBEM.
        sparql_query = """
            PREFIX survol: <%s>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT ?name ?caption
            WHERE
            { ?url_proc survol:Name ?name .
              ?url_proc survol:Caption ?caption .
              ?url_proc rdf:type survol:CIM_Process .
            }
            """ % (survol_namespace)
        rdflib_graph = rdflib.Graph()
        query_result = rdflib_graph.query(sparql_query)
        print(query_result)


if __name__ == '__main__':
    unittest.main()

