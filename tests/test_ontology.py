#!/usr/bin/env python

"""Test the generation of ontologies."""

from __future__ import print_function

import os
import sys
import socket
import unittest
import rdflib

from init import *

import lib_client
import lib_kbase


class RdfOntologyConformanceSurvolLocaTest(unittest.TestCase):
    """
    These tests do not need a Survol agent because they import directly the module.
    They use all sorts of URL to have a reasonably general coverage.
    """

    def _check_rdf_url_ontology(self, the_content_rdf):
        print("test_create_source_local_rdf: RDF content=%s ..." % str(the_content_rdf)[:30])

        rdf_graph = lib_kbase.triplestore_from_rdf_xml(the_content_rdf)
        errors_list = lib_kbase.check_rdf_ontology_conformance(rdf_graph)
        print("Errors:")
        for one_error in errors_list:
            print("    ", one_error)
        return errors_list

    def test_conformance_file_stat(self):
        my_source_local = lib_client.SourceLocal(
            "sources_types/CIM_DataFile/file_stat.py",
            "CIM_DataFile",
            Name=always_present_file)
        print("test_conformance_file_stat: query=%s" % my_source_local.create_url_query())
        the_content_rdf = my_source_local.content_rdf()
        errors_list = self._check_rdf_url_ontology(the_content_rdf)
        self.assertEqual(errors_list, [])

    def test_conformance_enumerate_CIM_LogicalDisk(self):
        """Test of enumerate_CIM_LogicalDisk.py"""
        my_source_local = lib_client.SourceLocal(
            "sources_types/enumerate_CIM_LogicalDisk.py")
        print("test_conformance_enumerate_CIM_LogicalDisk: query=%s" % my_source_local.create_url_query())
        the_content_rdf = my_source_local.content_rdf()
        errors_list = self._check_rdf_url_ontology(the_content_rdf)
        self.assertEqual(errors_list, [])

    @unittest.skipIf(not is_platform_windows, "Windows only")
    def test_conformance_enumerate_Win32_UserAccount(self):
        """Test of enumerate_Win32_UserAccount.py"""
        my_source_local = lib_client.SourceLocal(
            "sources_types/win32/enumerate_Win32_UserAccount.py")
        print("test_conformance_enumerate_Win32_UserAccount: query=%s" % my_source_local.create_url_query())
        the_content_rdf = my_source_local.content_rdf()
        errors_list = self._check_rdf_url_ontology(the_content_rdf)
        self.assertEqual(errors_list, [])

    @unittest.skipIf(not is_platform_windows, "Windows only")
    def test_conformance_win32_NetLocalGroupGetMembers(self):
        """Test of win32_NetLocalGroupGetMembers.py"""

        # The group "Users" is always here.
        my_source_local = lib_client.SourceLocal(
            "sources_types/Win32_Group/win32_NetLocalGroupGetMembers.py",
            "Win32_Group",
            Name="Users",
            Domain=CurrentMachine)
        print("test_conformance_win32_NetLocalGroupGetMembers: query=%s" % my_source_local.create_url_query())
        the_content_rdf = my_source_local.content_rdf()
        errors_list = self._check_rdf_url_ontology(the_content_rdf)
        self.assertEqual(errors_list, [])

