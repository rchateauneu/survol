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
import lib_common

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

        iterator_objects = callback_object.CallbackSelect(grph, "CIM_Process", "WBEM", filtered_where_key_values)
        list_objects = list(iterator_objects)

        for object_path, dict_key_values in list_objects:
            DEBUG(object_path)
            DEBUG(dict_key_values)
            print(object_path)
            print(dict_key_values)
        self.assertTrue(len(list_objects) == 1)
        # '\\RCHATEAU-HP\root\cimv2:Win32_Process.Handle="164944"'
        # '{rdflib.term.URIRef(u'http://primhillcomputers.com/survol#OtherTransferCount'): rdflib.term.Literal(u'733244'),
        # rdflib.term.URIRef(u'http://www.w3.org/1999/02/22-rdf-syntax-ns#type'): rdflib.term.URIRef(u'http://primhillcomputers.com/survol#CIM_Process'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#QuotaNonPagedPoolUsage'): rdflib.term.Literal(u'18'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#UserModeTime'): rdflib.term.Literal(u'3120020 milliseconds'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#PageFileUsage'): rdflib.term.Literal(u'25604'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#HandleCount'): rdflib.term.Literal(u'218'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#Handle'): rdflib.term.Literal(u'164944'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#PrivatePageCount'): rdflib.term.Literal(u'26218496'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#ProcessId'): rdflib.term.Literal(u'164944'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#CSCreationClassName'): rdflib.term.Literal(u'Win32_ComputerSystem'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#ThreadCount'): rdflib.term.Literal(u'6'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#QuotaPagedPoolUsage'): rdflib.term.Literal(u'249'),
        # rdflib.term.URIRef(u'http://www.w3.org/2000/01/rdf-schema#seeAlso'): rdflib.term.Literal(u'WMI'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#ReadTransferCount'): rdflib.term.Literal(u'4451474'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#CreationClassName'): rdflib.term.Literal(u'Win32_Process'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#QuotaPeakPagedPoolUsage'): rdflib.term.Literal(u'250'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#VirtualSize'): rdflib.term.Literal(u'138530816'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#CSName'): rdflib.term.Literal(u'RCHATEAU-HP'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#MinimumWorkingSetSize'): rdflib.term.Literal(u'200'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#WorkingSetSize'): rdflib.term.Literal(u'32747520 B'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#PageFaults'): rdflib.term.Literal(u'9753'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#ParentProcessId'): rdflib.term.Literal(u'5360'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#WriteOperationCount'): rdflib.term.Literal(u'21'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#KernelModeTime'): rdflib.term.Literal(u'2028013 milliseconds'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#Priority'): rdflib.term.Literal(u'8'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#OtherOperationCount'): rdflib.term.Literal(u'22068'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#CommandLine'): rdflib.term.Literal(u'C:\\\\Python27\\\\python.exe "C:\\\\Program Files\\\\JetBrains\\\\PyCharm Community Edition 2019.1.3\\\\helpers\\\\pycharm\\\\_jb_unittest_runner.py" --target test_lib_wmi.LibWmiTest.test_sparql_callback_select'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#WriteTransferCount'): rdflib.term.Literal(u'4213'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#PeakWorkingSetSize'): rdflib.term.Literal(u'31980'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#CreationDate'): rdflib.term.Literal(u'2019-10-14 22:29:33'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#PeakVirtualSize'): rdflib.term.Literal(u'138530816'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#Description'): rdflib.term.Literal(u'python.exe'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#WindowsVersion'): rdflib.term.Literal(u'6.1.7601'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#OSCreationClassName'): rdflib.term.Literal(u'Win32_OperatingSystem'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#MaximumWorkingSetSize'): rdflib.term.Literal(u'1380'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#PeakPageFileUsage'): rdflib.term.Literal(u'25604'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#ExecutablePath'): rdflib.term.Literal(u'C:\\\\Python27\\\\python.exe'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#ReadOperationCount'): rdflib.term.Literal(u'1580'),
        # rdflib.term.URIRef(u'http://www.w3.org/2000/01/rdf-schema#isDefinedBy'): rdflib.term.Literal(u'WMI'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#Caption'): rdflib.term.Literal(u'python.exe'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#QuotaPeakNonPagedPoolUsage'): rdflib.term.Literal(u'19'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#SessionId'): rdflib.term.Literal(u'1'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#Name'): rdflib.term.Literal(u'python.exe')}"
        one_path, one_dict = list_objects[0]

        def GetElementAsString(property_name):
            property_node = lib_common.MakeProp(property_name)
            value_node = one_dict[property_node]
            value_literal = str(value_node)
            return value_literal
            # qname_key = lib_properties.PropToQName(key_node)

        self.assertTrue(GetElementAsString('Handle') == str(CurrentPid))
        self.assertTrue(GetElementAsString('ProcessId') == str(CurrentPid))
        # Spelled "ParentProcessID" in WBEM.
        self.assertTrue(GetElementAsString('ParentProcessId') == str(CurrentParentPid))
        self.assertTrue(GetElementAsString('OSCreationClassName') == 'Win32_OperatingSystem')
        self.assertTrue(GetElementAsString('Caption') == 'python.exe')

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

