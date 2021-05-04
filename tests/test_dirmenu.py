#!/usr/bin/env python

"""The intention is to test the capability to search for specific strigns in the memory of a running process."""

from __future__ import print_function

import unittest
import subprocess
import sys
import os
import time

from init import *

# This loads the module from the source, so no need to install it, and no need of virtualenv.
update_test_path()

import lib_client


class EntityDirMenuTest(unittest.TestCase):
    """
    This tests the correctness of the menu of scripts for several types of instances.
    """

    def test_dirmenu_cim_process(self):
        my_source = lib_client.SourceLocal(
            "entity_dirmenu_only.py",
            "CIM_Process",
            Handle=CurrentPid)

        triple_sql_queries = my_source.get_triplestore()
        print(len(triple_sql_queries))

        # On Windows, it must contains an associator to the executable file.

    def test_dirmenu_cim_datafile(self):
        my_source = lib_client.SourceLocal(
            "entity_dirmenu_only.py",
            "CIM_DataFile",
            Name=always_present_file)

        triple_sql_queries = my_source.get_triplestore()
        print(len(triple_sql_queries))

        # On Windows, it must contains an associator to the directory.

    def test_dirmenu_cim_directory(self):
        my_source = lib_client.SourceLocal(
            "entity_dirmenu_only.py",
            "CIM_Directory",
            Name=always_present_dir)

        triple_sql_queries = my_source.get_triplestore()
        print(len(triple_sql_queries))

        # On Windows, it must contains an associator to the files contained in this directory.


class AssociatorScriptTest(unittest.TestCase):
    """
    This tests the correctness of the menu of scripts for several types of instances.
    """

    # CIM_ProcessExecutable.Antecedent":
    #     predicate_type:	"ref:CIM_DataFile"
    #     predicate_domain: ["CIM_Process"]
    # CIM_ProcessExecutable.Dependent:
    #     predicate_type:	"ref:CIM_Process"
    #     predicate_domain: ["CIM_DataFile"]

    def test_associations_cim_process_executable_cim_process(self):
        my_source = lib_client.SourceLocal(
            "entity.py",
            "CIM_Process",
            Handle=CurrentPid,
            __associator_attribute__="CIM_ProcessExecutable.Antecedent",
            )

        # It must return sys.executable
        triple_sql_queries = my_source.get_triplestore()

    def test_associations_cim_process_executable_cim_datafile(self):
        my_source = lib_client.SourceLocal(
            "entity.py",
            "CIM_DataFile",
            Name=sys.executable,
            __associator_attribute__="CIM_ProcessExecutable.Dependent",
            )

        # It must return at least the current pid.
        triple_sql_queries = my_source.get_triplestore()


    def test_associations_cim_directory_contains_file_group_component(self):
        my_source = lib_client.SourceLocal(
            "entity.py",
            "CIM_Directory",
            Name=always_present_sub_dir,
            __associator_attribute__="CIM_DirectoryContainsFile.GroupComponent",
            )

        # It must return at least the current pid.
        triple_sql_queries = my_source.get_triplestore()


    def test_associations_cim_directory_contains_file_part_component_dir(self):
        my_source = lib_client.SourceLocal(
            "entity.py",
            "CIM_Directory",
            Name=always_present_sub_dir,
            __associator_attribute__="CIM_DirectoryContainsFile.PartComponent",
            )

        # It must return at least the current pid.
        triple_sql_queries = my_source.get_triplestore()

    def test_associations_cim_directory_contains_file_part_component_file(self):
        my_source = lib_client.SourceLocal(
            "entity.py",
            "CIM_DataFile",
            Name=always_present_sub_file,
            __associator_attribute__="CIM_DirectoryContainsFile.GroupComponent",
            )

        # It must return at least the current pid.
        triple_sql_queries = my_source.get_triplestore()
