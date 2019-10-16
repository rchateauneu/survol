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
import lib_properties

################################################################################

# Similar function in test_lib_wbem.py
def GetElementAsString(one_dict, property_name):
    property_node = lib_properties.MakeProp(property_name)
    value_node = one_dict[property_node]
    value_literal = str(value_node)
    return value_literal
    # qname_key = lib_properties.PropToQName(key_node)


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
        # Example: Only some properties are displayed.
        # '\\RCHATEAU-HP\root\cimv2:Win32_Process.Handle="164944"'
        # '{rdflib.term.URIRef(u'http://primhillcomputers.com/survol#OtherTransferCount'): rdflib.term.Literal(u'733244'),
        # rdflib.term.URIRef(u'http://www.w3.org/1999/02/22-rdf-syntax-ns#type'): rdflib.term.URIRef(u'http://primhillcomputers.com/survol#CIM_Process'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#QuotaNonPagedPoolUsage'): rdflib.term.Literal(u'18'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#ProcessId'): rdflib.term.Literal(u'164944'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#CSCreationClassName'): rdflib.term.Literal(u'Win32_ComputerSystem'),
        # rdflib.term.URIRef(u'http://www.w3.org/2000/01/rdf-schema#seeAlso'): rdflib.term.Literal(u'WMI'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#CreationClassName'): rdflib.term.Literal(u'Win32_Process'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#CSName'): rdflib.term.Literal(u'RCHATEAU-HP'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#OtherOperationCount'): rdflib.term.Literal(u'22068'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#CommandLine'): rdflib.term.Literal(u'C:\\\\Python27\\\\python.exe "C:\\\\Program Files\\\\JetBrains\\\\PyCharm Community Edition 2019.1.3\\\\helpers\\\\pycharm\\\\_jb_unittest_runner.py" --target test_lib_wmi.LibWmiTest.test_sparql_callback_select'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#Description'): rdflib.term.Literal(u'python.exe'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#OSCreationClassName'): rdflib.term.Literal(u'Win32_OperatingSystem'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#ExecutablePath'): rdflib.term.Literal(u'C:\\\\Python27\\\\python.exe'),
        # rdflib.term.URIRef(u'http://www.w3.org/2000/01/rdf-schema#isDefinedBy'): rdflib.term.Literal(u'WMI'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#Caption'): rdflib.term.Literal(u'python.exe'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#Name'): rdflib.term.Literal(u'python.exe')}"
        one_path, one_dict = list_objects[0]

        self.assertTrue(GetElementAsString(one_dict, 'Handle') == str(CurrentPid))
        self.assertTrue(GetElementAsString(one_dict, 'ProcessId') == str(CurrentPid))
        # Spelled "ParentProcessID" in WBEM.
        self.assertTrue(GetElementAsString(one_dict, 'ParentProcessId') == str(CurrentParentPid))
        self.assertTrue(GetElementAsString(one_dict, 'OSCreationClassName') == 'Win32_OperatingSystem')
        self.assertTrue(GetElementAsString(one_dict, 'Caption') == 'python.exe')

    # ASSOCIATORS OF {CIM_Process.Handle=32360} WHERE AssocClass=CIM_ProcessExecutable ResultClass=CIM_DataFile
    @unittest.skipIf(not pkgutil.find_loader('wmi'), "wmi cannot be imported.")
    def test_sparql_callback_associator_process(self):
        callback_object = lib_wmi.WmiSparqlCallbackApi()
        grph = lib_kbase.MakeGraph()
        iterator_objects = callback_object.CallbackAssociator(
                grph,
                result_class_name = "CIM_DataFile",
                predicate_prefix = "WBEM",
                associator_key_name = "CIM_ProcessExecutable",
                wmi_path_full = r'\\%s\root\cimv2:CIM_Process.Handle=%s' % (CurrentMachine, CurrentPid))

        # Example: Only some properties are displayed.
        # {
        # rdflib.term.URIRef(u'http://www.w3.org/1999/02/22-rdf-syntax-ns#type'): 'CIM_DataFile',
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#System'): rdflib.term.Literal(u'False'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#EightDotThreeFileName'): rdflib.term.Literal(u'c:\\\\windows\\\\system32\\\\ntdll.dll'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#Readable'): rdflib.term.Literal(u'True'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#Manufacturer'): rdflib.term.Literal(u'Microsoft Corporation'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#Hidden'): rdflib.term.Literal(u'False'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#CSCreationClassName'): rdflib.term.Literal(u'Win32_ComputerSystem'),
        # rdflib.term.URIRef(u'http://www.w3.org/2000/01/rdf-schema#seeAlso'): rdflib.term.Literal(u'WMI'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#FSCreationClassName'): rdflib.term.Literal(u'Win32_FileSystem'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#FileName'): rdflib.term.Literal(u'ntdll'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#CSName'): rdflib.term.Literal(u'RCHATEAU-HP'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#FSName'): rdflib.term.Literal(u'NTFS'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#Drive'): rdflib.term.Literal(u'c:'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#CreationClassName'): rdflib.term.Literal(u'CIM_LogicalFile'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#Description'): rdflib.term.Literal(u'c:\\\\windows\\\\system32\\\\ntdll.dll'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#FileType'): rdflib.term.Literal(u'Application Extension'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#Path'): rdflib.term.Literal(u'\\\\windows\\\\system32\\\\'),
        # rdflib.term.URIRef(u'http://www.w3.org/2000/01/rdf-schema#isDefinedBy'): rdflib.term.Literal(u'WMI'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#Caption'): rdflib.term.Literal(u'c:\\\\windows\\\\system32\\\\ntdll.dll'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#Name'): rdflib.term.Literal(u'c:\\\\windows\\\\system32\\\\ntdll.dll'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#Extension'): rdflib.term.Literal(u'dll')
        # }
        found_kernel32_dll = False
        for object_path, dict_key_values in iterator_objects:
            self.assertTrue(GetElementAsString(dict_key_values, 'FSCreationClassName') == "Win32_FileSystem")
            self.assertTrue(GetElementAsString(dict_key_values, 'CreationClassName') == "CIM_LogicalFile")
            if not found_kernel32_dll:
                found_kernel32_dll = GetElementAsString(dict_key_values, 'Name').endswith("kernel32.dll")
        self.assertTrue(found_kernel32_dll)


    # ASSOCIATORS OF {Win32_LogicalDisk.DeviceID="C:"} WHERE AssocClass = Win32_SystemDevices
    @unittest.skipIf(not pkgutil.find_loader('wmi'), "wmi cannot be imported.")
    def test_sparql_callback_associator_logical_disk(self):
        callback_object = lib_wmi.WmiSparqlCallbackApi()
        grph = lib_kbase.MakeGraph()
        iterator_objects = callback_object.CallbackAssociator(
                grph,
                result_class_name = "Win32_ComputerSystem",
                predicate_prefix = "WBEM",
                associator_key_name = "Win32_SystemDevices",
                wmi_path_full = r'\\%s\root\cimv2:Win32_LogicalDisk.DeviceID="C:"' % CurrentMachine)

        list_objects = list(iterator_objects)
        self.assertTrue(len(list_objects) == 1)

        # Example: Not all values are displayed.
        # {rdflib.term.URIRef(u'http://primhillcomputers.com/survol#TotalPhysicalMemory'): rdflib.term.Literal(u'17099120640 B'),
        # rdflib.term.URIRef(u'http://www.w3.org/1999/02/22-rdf-syntax-ns#type'): 'Win32_ComputerSystem',
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#Manufacturer'): rdflib.term.Literal(u'Hewlett-Packard'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#UserName'): rdflib.term.Literal(u'rchateau-HP\\\\rchateau'),
        # rdflib.term.URIRef(u'http://www.w3.org/2000/01/rdf-schema#seeAlso'): rdflib.term.Literal(u'WMI'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#CreationClassName'): rdflib.term.Literal(u'Win32_ComputerSystem'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#DNSHostName'): rdflib.term.Literal(u'rchateau-HP'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#Workgroup'): rdflib.term.Literal(u'WORKGROUP'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#Domain'): rdflib.term.Literal(u'WORKGROUP'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#Description'): rdflib.term.Literal(u'AT/AT COMPATIBLE'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#PrimaryOwnerName'): rdflib.term.Literal(u'rchateau'),
        # rdflib.term.URIRef(u'http://www.w3.org/2000/01/rdf-schema#isDefinedBy'): rdflib.term.Literal(u'WMI'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#Caption'): rdflib.term.Literal(u'RCHATEAU-HP'),
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#Name'): rdflib.term.Literal(u'RCHATEAU-HP'),
        for object_path, dict_key_values in list_objects:
            print(object_path)
            print(dict_key_values)
            self.assertTrue(GetElementAsString(dict_key_values, 'CreationClassName') == "Win32_ComputerSystem")
            self.assertTrue(GetElementAsString(dict_key_values, 'Name').upper() == CurrentMachine.upper())

    @unittest.skipIf(not pkgutil.find_loader('wmi'), "wmi cannot be imported.")
    def test_sparql_callback_types(self):
        callback_object = lib_wmi.WmiSparqlCallbackApi()
        grph = lib_kbase.MakeGraph()
        iterator_types = callback_object.CallbackTypes(grph, "see_also")
        for object_path, dict_key_values in iterator_types:
            print(object_path)
            print(dict_key_values)


if __name__ == '__main__':
    unittest.main()

