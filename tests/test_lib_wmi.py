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
import lib_wmi
import lib_kbase

################################################################################

class LibWmiTest(unittest.TestCase):
    @unittest.skipIf(not pkgutil.find_loader('wmi'), "wmi cannot be imported.")
    def test_local_ontology(self):
        # This test is very slow because it does not use the cache.
        map_classes, map_attributes = lib_wmi.ExtractWmiOntologyLocal()
        print("map_classes=", map_classes)
        # print("map_attributes=", map_attributes)
        self.assertTrue("CIM_Process" in map_classes)
        self.assertTrue("CIM_DataFile" in map_classes)
        self.assertTrue("CIM_Directory" in map_classes)
        print(sorted(map_attributes.keys()))
        self.assertTrue("Handle" in map_attributes)
        self.assertTrue("Name" in map_attributes)
        self.assertTrue("Caption" in map_attributes)


    @unittest.skipIf(not pkgutil.find_loader('wmi'), "wmi cannot be imported.")
    def test_sparql_callback_select(self):
        # TODO: Beware, this can be incredibly very slow depending on the properties.
        callback_object = lib_wmi.WmiSparqlCallbackApi()
        filtered_where_key_values = {
            "Handle": CurrentPid
        }
        grph = lib_kbase.MakeGraph()

        iterator_objects = callback_object.CallbackSelect(grph, "CIM_Process", "WMI", filtered_where_key_values)
        for object_path, dict_key_values in iterator_objects:
            pass

    @unittest.skipIf(not pkgutil.find_loader('wmi'), "wmi cannot be imported.")
    def test_sparql_callback_associator(self):
        callback_object = lib_wmi.WmiSparqlCallbackApi()
        grph = lib_kbase.MakeGraph()
        iterator_objects = callback_object.CallbackAssociator(
                grph,
                "result_class_name",
                "WBEM",
                "associator_key_name",
                r'\\%s\root\cimv2:Win32_Process.Handle="%s"' % (CurrentMachine, CurrentPid) )
        for object_path, dict_key_values in iterator_objects:
            pass

    @unittest.skipIf(not pkgutil.find_loader('wmi'), "wmi cannot be imported.")
    def test_sparql_callback_types(self):
        callback_object = lib_wmi.WmiSparqlCallbackApi()
        grph = lib_kbase.MakeGraph()
        iterator_types = callback_object.CallbackTypes(grph, "see_also")
        for object_path, dict_key_values in iterator_types:
            pass


if __name__ == '__main__':
    unittest.main()

