#!/usr/bin/env python

from __future__ import print_function

import os
import sys
import json
import unittest
import pkgutil

from init import *

update_test_path()

# This is what we want to test.
import lib_wbem
import lib_kbase

################################################################################

class LibWbemTest(unittest.TestCase):
    @unittest.skipIf(not is_linux_wbem(), "No WBEM.")
    def test_local_ontology(self):
        # This test can run only if the local machine has a WBEM server.
        map_classes, map_attributes = lib_wbem.ExtractWbemOntology()
        self.assertTrue("CIM_Process" in map_classes)
        self.assertTrue("CIM_DataFile" in map_classes)
        self.assertTrue("CIM_Directory" in map_classes)

        self.assertTrue("Handle" in map_attributes)
        self.assertTrue("Name" in map_attributes)
        self.assertTrue("Caption" in map_attributes)

    @unittest.skipIf(not pkgutil.find_loader('pywbem'), "pywbem cannot be imported. test_remote_ontology not executed.")
    def test_remote_ontology(self):
        """Very slow test: It displays the entire list of classes and their properties."""
        # In contrast to another test which remotely connect to a Survol agent,
        # which then makes a local TCP/IP connection to its local WBEM Cimom,
        # this test directly connects to the remote Cimom.
        wbem_connection = lib_wbem.WbemConnection(SurvolWbemCimom)

        map_classes, map_attributes = lib_wbem.ExtractRemoteWbemOntology(wbem_connection)
        self.assertTrue( "CIM_Process" in map_classes)
        self.assertTrue("Handle" in map_attributes)

    @unittest.skipIf(not pkgutil.find_loader('pywbem'), "pywbem cannot be imported. test_remote_ontology not executed.")
    def test_remote_namespaces(self):
        """At least the defaultnamespace must be there."""
        wbem_connection = lib_wbem.WbemConnection(SurvolWbemCimom)
        namespaces_dict = lib_wbem.EnumNamespacesCapabilities(wbem_connection)
        self.assertTrue("root/cimv2" in namespaces_dict)

    @unittest.skipIf(not is_linux_wbem(), "pywbem cannot be imported.")
    def test_sparql_callback_select(self):
        callback_object = lib_wbem.WbemSparqlCallbackApi()
        filtered_where_key_values = {
            "Handle": CurrentPid
        }
        grph = lib_kbase.MakeGraph()

        iterator_objects = callback_object.CallbackSelect(grph, "CIM_Process", "WBEM", filtered_where_key_values)
        for object_path, dict_key_values in iterator_objects:
            pass

    @unittest.skipIf(not is_linux_wbem(), "pywbem cannot be imported.")
    def test_sparql_callback_associator(self):
        callback_object = lib_wbem.WbemSparqlCallbackApi()
        grph = lib_kbase.MakeGraph()
        iterator_objects = callback_object.CallbackAssociator(
                grph,
                "result_class_name",
                "WBEM",
                "associator_key_name",
                r'//%s/root/cimv2:Win32_Process.Handle="%s"' % (CurrentMachine, CurrentPid))
        for object_path, dict_key_values in iterator_objects:
            pass

    @unittest.skipIf(not is_linux_wbem(), "pywbem cannot be imported.")
    def test_sparql_callback_types(self):
        callback_object = lib_wbem.WbemSparqlCallbackApi()
        grph = lib_kbase.MakeGraph()
        iterator_types = callback_object.CallbackTypes(grph, "see_also")
        for object_path, dict_key_values in iterator_types:
            pass


if __name__ == '__main__':
    unittest.main()

