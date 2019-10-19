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

from init import *

update_test_path()

# This is what we want to test.
import lib_sparql
import lib_util
import lib_properties
import lib_kbase
import lib_wbem
import lib_sparql_callback_survol



################################################################################

try:
    objectWbemSparqlCallbackApi = lib_wbem.WbemSparqlCallbackApi()
except:
    objectWbemSparqlCallbackApi = None

class SparqlCallWbemTest(unittest.TestCase):
    @staticmethod
    def __run_wbem_query(sparql_query):
        list_dict_objects = QueryKeyValuePairs(sparql_query, objectWbemSparqlCallbackApi )
        assert isinstance(list_dict_objects, list)
        INFO("list_dict_objects len=%d", len(list_dict_objects))
        return list_dict_objects

    @unittest.skipIf(not is_linux_wbem(), "WBEM not on this machine. Test skipped.")
    def test_wbem_all_processes(self):

        sparql_query ="""
            SELECT ?the_pid
            WHERE
            { ?url_proc survol:Handle ?the_pid .
              ?url_proc rdf:type survol:CIM_Process .
            }
            """

        INFO("query=%s", sparql_query)

        # This returns a list of dict(input_key => tuple_result)
        list_dict_objects = SparqlCallWbemTest.__run_wbem_query(sparql_query)
        for dict_object in list_dict_objects:
            # dict_object={'url_proc': {'ParentProcessID': '1', 'OSName': 'Fedora', 'CreationClassName': 'PG_UnixProcess'}}

            DEBUG("dict_object=%s", str(dict_object))
            self.assertTrue('url_proc' in dict_object)
            proc_object = dict_object['url_proc']
            self.assertTrue(proc_object['CreationClassName'] == 'PG_UnixProcess')
            self.assertTrue(proc_object['__class__'] == 'CIM_Process')


    @unittest.skipIf(not is_linux_wbem(), "WBEM not on this machine. Test skipped.")
    @unittest.skipIf(not is_linux_wbem(), "pywbem cannot be imported. test_ontology_wbem not executed.")
    def test_wbem_all_computers(self):

        sparql_query ="""
            SELECT ?computer_name
            WHERE
            { ?url_computer survol:Name ?computer_name .
              ?url_computer rdf:type survol:CIM_ComputerSystem .
            }
            """

        INFO("query=%s", sparql_query)

        # This returns a list of dict(input_key => tuple_result)
        list_dict_objects = SparqlCallWbemTest.__run_wbem_query(sparql_query)
        self.assertTrue(len(list_dict_objects) == 1)
        for dict_object in list_dict_objects:

            DEBUG("dict_object=%s", str(dict_object))
            self.assertTrue('url_computer' in dict_object)
            computer_object = dict_object['url_computer']
            self.assertTrue(computer_object['__class__'] == 'CIM_ComputerSystem')




if __name__ == '__main__':
    unittest.main()

