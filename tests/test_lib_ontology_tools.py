#!/usr/bin/env python

"""Test the generation of ontologies."""

from __future__ import print_function

import unittest

from init import *

import lib_wmi
import lib_ontology_tools


@unittest.skipIf(is_platform_linux, "WMI test only")
class OntologyToolsFunctionsWMITest(unittest.TestCase):

    def test_get_associated_attribute_wmi(self):
        input_data = [
            ("CIM_ProcessExecutable", [('CIM_DataFile', 'Antecedent'), ('CIM_Process', 'Dependent')]),
            ("CIM_DirectoryContainsFile", [('CIM_Directory', 'GroupComponent'), ('CIM_DataFile', 'PartComponent')]),
            ("Win32_SubDirectory", [('Win32_Directory', 'GroupComponent'), ('Win32_Directory', 'PartComponent')])
        ]

        test_data = [
            ("CIM_ProcessExecutable.Antecedent", 'CIM_Process', 'Dependent'),
            ("CIM_ProcessExecutable.Dependent", 'CIM_DataFile', 'Antecedent'),
            ("CIM_DirectoryContainsFile.GroupComponent", 'CIM_DataFile', 'PartComponent'),
            ("CIM_DirectoryContainsFile.PartComponent", 'CIM_Directory', 'GroupComponent'),
            ("Win32_SubDirectory.GroupComponent", 'Win32_Directory', 'PartComponent'),
            ("Win32_SubDirectory.PartComponent", 'Win32_Directory', 'GroupComponent'),
        ]

        for attribute_name, result_class, result_role in test_data:
            calculated_result_class, calculated_result_role = lib_ontology_tools.get_associated_attribute(
                "wmi", lib_wmi.extract_specific_ontology_wmi, attribute_name)
            self.assertEqual(result_class, calculated_result_class)
            self.assertEqual(result_role, calculated_result_role)

    def test_class_associators_wmi(self):
        """This checks that associators and roles are properly returned."""
        test_data = [
            ("CIM_Process", ["CIM_ProcessExecutable.Antecedent"]),
            ("CIM_DataFile", ["CIM_ProcessExecutable.Dependent", "CIM_DirectoryContainsFile.GroupComponent"]),
            ("CIM_Directory", ["CIM_DirectoryContainsFile.PartComponent"]),
            ("Win32_Directory", ["Win32_SubDirectory.GroupComponent", "Win32_SubDirectory.PartComponent"]),
        ]

        for entity_type, expected_attribute_names in test_data:
            print("entity_type=", entity_type)
            print("expected_attribute_names=", expected_attribute_names)
            attributes_names_list = list(lib_ontology_tools.class_associators(
                "wmi", lib_wmi.extract_specific_ontology_wmi, entity_type))
            print("attributes_names_list=", attributes_names_list)

            self.assertTrue(
                set(expected_attribute_names).issubset(set(attributes_names_list))
            )
