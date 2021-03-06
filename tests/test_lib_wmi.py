#!/usr/bin/env python

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
import lib_wmi
import lib_client
import lib_properties


def GetElementAsString(one_dict, property_name):
    """
    There is a similar function in test_lib_wbem.py
    """
    property_node = lib_properties.MakeProp(property_name)
    value_node = one_dict[property_node]
    value_literal = str(value_node)
    return value_literal


@unittest.skipIf(not pkgutil.find_loader('wmi'), "LibWmiTest needs wmi package.")
class LibWmiTest(unittest.TestCase):

    def test_wmi_classes_and_attributes(self):
        """
        This test creates the two dictionaries of classes and their attributes from WMI.
        It is slow because it does not use the three caches for each ontology models (WMI, WBEM, Survol).
        """
        map_classes, map_attributes = lib_wmi.extract_specific_ontology_wmi()
        self.assertTrue("CIM_Process" in map_classes)
        self.assertTrue("CIM_DataFile" in map_classes)
        self.assertTrue("CIM_Directory" in map_classes)

        self.assertTrue("Win32_Process" in map_classes)
        win32_process_attributes = map_classes["Win32_Process"]

        self.assertTrue("Handle" in map_attributes)
        self.assertTrue("Name" in map_attributes)
        # 'Caption' is not a key.
        #self.assertTrue("Caption" not in map_attributes)

        # This checks the presence of a select list of attributes and their classes.
        self.assertTrue("Win32_LogonSession" in map_attributes["LogonId"]["predicate_domain"])
        self.assertTrue("Win32_PingStatus" in map_attributes["Address"]["predicate_domain"])
        self.assertTrue("CIM_SoftwareFeature" in map_attributes["ProductName"]["predicate_domain"])
        self.assertTrue("Win32_Binary" in map_attributes["ProductCode"]["predicate_domain"])
        self.assertTrue("Win32_StartupCommand" in map_attributes["Command"]["predicate_domain"])
        self.assertTrue("Win32_StartupCommand" in map_attributes["Location"]["predicate_domain"])
        self.assertTrue("Win32_Group" in map_attributes["Domain"]["predicate_domain"])
        self.assertTrue("Win32_Account" in map_attributes["Domain"]["predicate_domain"])
        self.assertTrue("Win32_UserAccount" in map_attributes["Domain"]["predicate_domain"])
        self.assertTrue("Win32_SystemAccount" in map_attributes["Domain"]["predicate_domain"])

        # Associators
        self.assertEqual(map_attributes["Win32_MountPoint.Directory"],
            {"predicate_type": "ref:Win32_Directory", "predicate_domain": ["Win32_Volume"]})
        self.assertEqual(map_attributes["Win32_MountPoint.Volume"],
            {"predicate_type": "ref:Win32_Volume", "predicate_domain": ["Win32_Directory"]})

        self.assertEqual(map_attributes["CIM_ProcessExecutable.Antecedent"],
            {"predicate_type": "ref:CIM_DataFile", "predicate_domain": ["CIM_Process"]})
        self.assertEqual(map_attributes["CIM_ProcessExecutable.Dependent"],
            {"predicate_type": "ref:CIM_Process", "predicate_domain": ["CIM_DataFile"]})

        self.assertEqual(map_attributes["CIM_DirectoryContainsFile.GroupComponent"],
            {"predicate_type": "ref:CIM_Directory", "predicate_domain": ["CIM_DataFile"]})
        self.assertEqual(map_attributes["CIM_DirectoryContainsFile.PartComponent"],
            {"predicate_type": "ref:CIM_DataFile", "predicate_domain": ["CIM_Directory"]})

        # This is specific to WMI only.
        handle_attribute_dict = map_attributes["Handle"]
        self.assertEqual(handle_attribute_dict["predicate_type"], "survol_string")
        self.assertTrue("Win32_Process" in handle_attribute_dict["predicate_domain"])

    # TODO: DEPRECATED
    def test_sparql_callback_select(self):
        # TODO: Beware, this can be incredibly very slow depending on the properties.
        callback_object = lib_wmi.WmiSparqlCallbackApi()
        filtered_where_key_values = {
            "Handle": CurrentPid
        }
        grph = rdflib.Graph()

        iterator_objects = callback_object.CallbackSelect(grph, "CIM_Process", "WBEM", filtered_where_key_values)
        list_objects = list(iterator_objects)

        for object_path, dict_key_values in list_objects:
            logging.debug(object_path)
            logging.debug(dict_key_values)
            print(object_path)
            print(dict_key_values)
        self.assertTrue(len(list_objects) == 1)
        # Example: Only some properties are displayed.
        # '\\MY_MACHINE\root\cimv2:Win32_Process.Handle="164944"'
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

    # TODO: DEPRECATED
    # ASSOCIATORS OF {CIM_Process.Handle=32360} WHERE AssocClass=CIM_ProcessExecutable ResultClass=CIM_DataFile
    def test_sparql_callback_associator_process(self):
        logging.critical("THIS IS DEPRECATED")
        callback_object = lib_wmi.WmiSparqlCallbackApi()
        grph = rdflib.Graph()
        iterator_objects = callback_object.CallbackAssociator(
                grph,
                result_class_name = "CIM_DataFile",
                predicate_prefix = "WBEM",
                associator_key_name = "CIM_ProcessExecutable",
                subject_path = r'\\%s\root\cimv2:CIM_Process.Handle=%s' % (CurrentMachine, CurrentPid))

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
            self.assertEqual(GetElementAsString(dict_key_values, 'FSCreationClassName'), "Win32_FileSystem")
            self.assertEqual(GetElementAsString(dict_key_values, 'CreationClassName'), "CIM_LogicalFile")
            if not found_kernel32_dll:
                # Conversion to lower case because on Windows10 it is "KERNEL32.DLL".
                found_kernel32_dll = GetElementAsString(dict_key_values, 'Name').lower().endswith("kernel32.dll")
        self.assertTrue(found_kernel32_dll)

    # TODO: DEPRECATED
    # ASSOCIATORS OF {Win32_LogicalDisk.DeviceID="C:"} WHERE AssocClass = Win32_SystemDevices
    def test_sparql_callback_associator_logical_disk(self):
        logging.critical("THIS IS DEPRECATED")
        callback_object = lib_wmi.WmiSparqlCallbackApi()
        grph = rdflib.Graph()
        iterator_objects = callback_object.CallbackAssociator(
                grph,
                result_class_name = "Win32_ComputerSystem",
                predicate_prefix = "WBEM",
                associator_key_name = "Win32_SystemDevices",
                subject_path = r'\\%s\root\cimv2:Win32_LogicalDisk.DeviceID="C:"' % CurrentMachine)

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
            # Problem on Travis: Name='PACKER-5D93E860', DNSHostName='packer-5d93e860-43ba-c2e7-85d2-3ea0696b8fc8'
            self.assertTrue(GetElementAsString(dict_key_values, 'Name').lower() == CurrentDomainWin32)

    # TODO: DEPRECATED
    def test_sparql_callback_types(self):
        callback_object = lib_wmi.WmiSparqlCallbackApi()
        grph = rdflib.Graph()
        iterator_types = callback_object.CallbackTypes(grph, "see_also", {})
        for object_path, dict_key_values in iterator_types:
            print(object_path)
            print(dict_key_values)


    def text_build_wmi_path_from_survol_path(self):
        test_data = [
            ('CIM_Directory.Name=abc.def', 'CIM_Directory.Name="abc.def"')
        ]

        for input_path, expected_wmi_path in test_data:
            actual_wmi_path = lib_wmi.reformat_path_for_wmi(input_path)
            self.assertEqual(actual_wmi_path, expected_wmi_path)


@unittest.skipIf(not pkgutil.find_loader('wmi'), "WmiSparqlExecutorTest needs wmi package.")
class WmiSparqlExecutorTest(unittest.TestCase):
    @staticmethod
    def _object_path_to_path(object_path):
        # object_path= '\\RCHATEAU-HP\root\cimv2:Win32_Directory.Name="c:\\windows"'
        return object_path.partition(":")[2].replace("\\", "/").replace("//", "/")

    # The output order is always the same for all platforms, in alphabetical order.
    def test_associator_keys(self):
        wmi_executor = lib_wmi.WmiSparqlExecutor()
        lst_CIM_ProcessExecutable = wmi_executor.associator_keys("CIM_ProcessExecutable")
        print("lst_CIM_ProcessExecutable=", lst_CIM_ProcessExecutable)
        self.assertTrue(lst_CIM_ProcessExecutable == [('CIM_DataFile', 'Antecedent'), ('CIM_Process', 'Dependent')])

        lst_CIM_DirectoryContainsFile = wmi_executor.associator_keys("CIM_DirectoryContainsFile")
        print("lst_CIM_DirectoryContainsFile=", lst_CIM_DirectoryContainsFile)
        self.assertTrue(lst_CIM_DirectoryContainsFile == [('CIM_Directory', 'GroupComponent'), ('CIM_DataFile', 'PartComponent')])

        lst_Win32_SubDirectory = wmi_executor.associator_keys("Win32_SubDirectory")
        print("lst_Win32_SubDirectory=", lst_Win32_SubDirectory)
        self.assertTrue(lst_Win32_SubDirectory == [('Win32_Directory', 'GroupComponent'), ('Win32_Directory', 'PartComponent')])

    def test_BidirectionalAssociatorsFromObject_file_to_dir(self):
        wmi_executor = lib_wmi.WmiSparqlExecutor()

        file_name = always_present_file.replace("\\", "/").lower()
        wmi_path_file = 'CIM_DataFile.Name="%s"' % file_name

        directory_name = always_present_dir.replace("\\", "/").lower()

        iter_results = wmi_executor.SelectBidirectionalAssociatorsFromObject(
            "CIM_Directory", "CIM_DirectoryContainsFile", wmi_path_file, 0)
        list_results = list(iter_results)
        directory_path = 'Win32_Directory.Name="%s"' % directory_name
        for object_path, dict_key_values in list_results:
            print("object_path=", object_path)
            actual_filename_clean = self._object_path_to_path(object_path)
            print("actual_filename_clean=", actual_filename_clean)
            print("directory_path=", directory_path)
            self.assertTrue(actual_filename_clean==directory_path)

    def test_BidirectionalAssociatorsFromObject_dir_to_file(self):
        wmi_executor = lib_wmi.WmiSparqlExecutor()

        file_name = always_present_file.replace("\\", "/").lower()
        directory_name = always_present_dir.replace("\\", "/").lower()

        print("file_name=", file_name)
        print("os.getcwd()=", os.getcwd())

        # WMI needs parameters enclosed in double-quotes.
        wmi_path_directory = 'CIM_Directory.Name="%s"' % directory_name

        # CIM_DirectoryContainsFile.GroupComponent or CIM_DirectoryContainsFile.PartComponent
        iter_results = wmi_executor.SelectBidirectionalAssociatorsFromObject(
            "CIM_DataFile", "CIM_DirectoryContainsFile", wmi_path_directory, 1)
        list_results = list(iter_results)
        paths_list = []
        for object_path, dict_key_values in list_results:
            actual_filename_clean = self._object_path_to_path(object_path).lower()
            paths_list.append(actual_filename_clean)
        print("paths_list=", paths_list)
        print("file_name=", file_name)
        expected_file_path = 'CIM_DataFile.Name="%s"' % file_name
        print("expected_file_path=", expected_file_path)
        self.assertTrue(expected_file_path.lower() in paths_list)

    def test_BidirectionalAssociatorsFromObject_dir_to_subdir(self):
        wmi_executor = lib_wmi.WmiSparqlExecutor()

        sub_dir_name = always_present_sub_dir.replace("\\", "/").lower()
        directory_name = always_present_dir.replace("\\", "/").lower()

        # WMI needs parameters enclosed in double-quotes.
        wmi_path_directory = 'CIM_Directory.Name="%s"' % directory_name

        iter_results = wmi_executor.SelectBidirectionalAssociatorsFromObject(
            "Win32_Directory", "Win32_SubDirectory", wmi_path_directory, 1)
        list_results = list(iter_results)
        paths_list = []
        for object_path, dict_key_values in list_results:
            # Filenames are converted to lowercase because of different behaviour wrt Windows version.
            actual_sub_dir_clean = self._object_path_to_path(object_path).lower()
            paths_list.append(actual_sub_dir_clean)
        print("paths_list=", paths_list)
        print("sub_dir_name=", sub_dir_name)
        expected_subdir_path = 'Win32_Directory.Name="%s"' % sub_dir_name
        print("expected_subdir_path=", expected_subdir_path)
        self.assertTrue(expected_subdir_path.lower() in paths_list)

    def test_BidirectionalAssociatorsFromObject_subdir_to_dir(self):
        wmi_executor = lib_wmi.WmiSparqlExecutor()

        sub_dir_name = always_present_sub_dir.replace("\\", "/").lower()
        directory_name = always_present_dir.replace("\\", "/").lower()

        wmi_path_sub_dir = 'CIM_Directory.Name="%s"' % sub_dir_name

        iter_results = wmi_executor.SelectBidirectionalAssociatorsFromObject(
            "Win32_Directory", "Win32_SubDirectory", wmi_path_sub_dir, 0)
        list_results = list(iter_results)
        paths_list = []
        for object_path, dict_key_values in list_results:
            actual_dir_clean = self._object_path_to_path(object_path)
            paths_list.append(actual_dir_clean)
        print("paths_list=", paths_list)
        print("sub_dir_name=", sub_dir_name)
        expected_dir_path = 'Win32_Directory.Name="%s"' % directory_name
        print("expected_dir_path=", expected_dir_path)
        self.assertTrue(expected_dir_path in paths_list)

    def test_enumerate_associated_instances_CIM_ProcessExecutable_Antecedent(self):
        wmi_executor = lib_wmi.WmiSparqlExecutor()
        wmi_path = lib_client.create_instance_path("CIM_DataFile", Name=sys.executable)
        dict_key_values = wmi_executor.enumerate_associated_instances(
            wmi_path,
            "CIM_ProcessExecutable", "CIM_DataFile", "Antecedent")
        print("dict_key_values=", dict_key_values)

    def test_enumerate_associated_instances_CIM_ProcessExecutable_Dependent(self):
        wmi_executor = lib_wmi.WmiSparqlExecutor()
        wmi_path = lib_client.create_instance_path("CIM_Process", Handle=CurrentPid)
        dict_key_values = wmi_executor.enumerate_associated_instances(
            wmi_path,
            "CIM_ProcessExecutable", "CIM_Process", "Dependent")
        print("dict_key_values=", dict_key_values)

    def test_enumerate_associated_instances_CIM_DirectoryContainsFile_GroupComponent(self):
        wmi_executor = lib_wmi.WmiSparqlExecutor()
        wmi_path = lib_client.create_instance_path("CIM_Directory", Name=always_present_dir)
        dict_key_values = wmi_executor.enumerate_associated_instances(
            wmi_path,
            "CIM_DirectoryContainsFile", "CIM_Directory", "GroupComponent")
        print("dict_key_values=", dict_key_values)

    def test_enumerate_associated_instances_CIM_DirectoryContainsFile_PartComponent(self):
        wmi_executor = lib_wmi.WmiSparqlExecutor()
        wmi_path = lib_client.create_instance_path("CIM_DataFile", Name=always_present_file)
        dict_key_values = wmi_executor.enumerate_associated_instances(
            wmi_path,
            "CIM_DirectoryContainsFile", "CIM_DataFile", "PartComponent")

    def test_enumerate_associated_instances_Win32_SubDirectory_GroupComponent(self):
        wmi_executor = lib_wmi.WmiSparqlExecutor()
        wmi_path = lib_client.create_instance_path("Win32_Directory", Name=always_present_sub_dir)
        dict_key_values = wmi_executor.enumerate_associated_instances(
            wmi_path,
            "Win32_SubDirectory", "Win32_Directory", "GroupComponent")
        print("dict_key_values=", dict_key_values)

    def test_enumerate_associated_instances_Win32_SubDirectory_PartComponent(self):
        wmi_executor = lib_wmi.WmiSparqlExecutor()
        wmi_path = lib_client.create_instance_path("Win32_Directory", Name=always_present_dir)
        dict_key_values = wmi_executor.enumerate_associated_instances(
            wmi_path,
            "Win32_SubDirectory", "Win32_Directory", "PartComponent")
        print("dict_key_values=", dict_key_values)


if __name__ == '__main__':
    unittest.main()

