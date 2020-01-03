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

import lib_sparql
import lib_util
import lib_common
import lib_properties
import lib_kbase
import lib_wmi
import lib_sparql_custom_evals

# This can run only on Windows.
def setUpModule():
    try:
        import wmi
    except ImportError as err:
        raise unittest.SkipTest(str(err))

################################################################################

survol_namespace = rdflib.Namespace(lib_sparql_custom_evals.survol_url)

################################################################################

class CUSTOM_EVALS_WMI_Base_Test(unittest.TestCase):

    def setUp(self):
        # add function directly, normally we would use setuptools and entry_points
        rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_function_wmi'] = lib_sparql_custom_evals.custom_eval_function_wmi

    def tearDown(self):
        if 'custom_eval_function_wmi' in rdflib.plugins.sparql.CUSTOM_EVALS:
            del rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_function_wmi']

################################################################################


class SparqlWmiFromPropertiesTest(CUSTOM_EVALS_WMI_Base_Test):

    def test_wmi_query_process(self):
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_proc
            WHERE
            { ?url_proc survol:Handle '%d'  .
              ?url_proc rdf:type survol:CIM_Process .
            }""" % (survol_namespace, CurrentPid)
        rdflib_graph = rdflib.Graph()
        query_result = rdflib_graph.query(sparql_query)
        print("query_result=", query_result, len(query_result))
        for s_p_o in query_result:
            print("    ", s_p_o)
        self.assertTrue( len(query_result) == 1)

        process_node = lib_common.gUriGen.UriMakeFromDict("CIM_Process", {"Handle": CurrentPid})
        print("Expected process_node=", process_node)
        self.assertTrue(process_node == list(query_result)[0][0])

    def test_wmi_query_directory(self):
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_dir
            WHERE
            { ?url_dir survol:Name "c:"  .
              ?url_dir rdf:type survol:CIM_Directory .
            }""" % survol_namespace
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("query_result=", query_result, len(query_result))
        print("query_result=", query_result[0][0])
        directory_node = lib_common.gUriGen.UriMakeFromDict("CIM_Directory", {"Name": "c:"})
        self.assertTrue(directory_node == query_result[0][0])

    def test_Win32_LogicalDisk_C(self):
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_disk
            WHERE
            { ?url_disk rdf:type survol:Win32_LogicalDisk .
              ?url_disk survol:DeviceID "C:" .
            }""" % survol_namespace
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)
        print("query_result=", query_result[0][0])
        directory_node = lib_common.gUriGen.UriMakeFromDict("Win32_LogicalDisk", {"DeviceID": "C:"})
        self.assertTrue(directory_node == query_result[0][0])

    def test_Win32_LogicalDisk_all(self):
        # Load all disks.
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_disk
            WHERE
            { ?url_disk rdf:type survol:Win32_LogicalDisk .
            }""" % survol_namespace
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)
        print("query_result=", query_result[0][0])
        directory_node = lib_common.gUriGen.UriMakeFromDict("Win32_LogicalDisk", {"DeviceID": "C:"})
        self.assertTrue(directory_node in [one_query[0] for one_query in query_result])

    def test_wmi_query_user_account_url(self):
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_account
            WHERE
            { ?url_account rdf:type survol:Win32_UserAccount .
            }""" % survol_namespace
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)
        # At least two users: "Administrator" and curret user.
        self.assertTrue(len(query_result) >= 2)

    def test_wmi_query_user_account(self):
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?account_name ?account_domain
            WHERE
            { ?url_account rdf:type survol:Win32_UserAccount .
              ?url_account survol:Name ?account_name .
              ?url_account survol:Domain ?account_domain .
            }""" % survol_namespace
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        # Result= [
        # (rdflib.term.Literal(u'Administrator'), rdflib.term.Literal(u'rchateau-HP')),
        # (rdflib.term.Literal(u'HomeGroupUser$'), rdflib.term.Literal(u'rchateau-HP')),
        # (rdflib.term.Literal(u'Guest'), rdflib.term.Literal(u'rchateau-HP')),
        # (rdflib.term.Literal(u'rchateau'), rdflib.term.Literal(u'rchateau-HP'))]
        print("Result=", query_result)
        only_names = [str(one_result[0]) for one_result in query_result]
        print("only_names=", only_names)
        self.assertTrue("Administrator" in only_names)
        self.assertTrue("Guest" in only_names)
        self.assertTrue(CurrentUsername in only_names)

        for one_result in query_result:
            self.assertTrue(str(one_result[1]).lower() ==  CurrentMachine.lower())

    def test_CIM_Process_Name(self):
        sparql_query="""
            PREFIX survol: <%s>
            SELECT ?url_proc
            WHERE
            { ?url_proc rdf:type survol:CIM_Process .
              ?url_proc survol:Name "python.exe" .
            }""" % survol_namespace
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)
        # At least one process running Python, i.e. the current process.
        self.assertTrue(len(query_result) > 0)

    def test_CIM_Process_Name_to_Pid(self):
        sparql_query="""
            PREFIX survol: <%s>
            SELECT ?pid_proc
            WHERE
            { ?url_proc rdf:type survol:CIM_Process .
              ?url_proc survol:Name "python.exe" .
              ?url_proc survol:Handle ?pid_proc .
            }""" % survol_namespace
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)
        # At least one process running Python, i.e. the current process.
        self.assertTrue(len(query_result) > 0)
        only_pids = [str(one_result[0]) for one_result in query_result]
        print("only_pids=", only_pids)
        self.assertTrue(str(CurrentPid) in only_pids)

    def test_Win32_Process_Description_to_Pid(self):
        sparql_query = """
            PREFIX survol: <%s>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT ?pid
            WHERE
            {
                ?url_proc rdf:type survol:Win32_Process .
                ?url_proc survol:Description 'python.exe' .
                ?url_proc survol:Handle ?pid .
            }""" % (survol_namespace)
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)
        self.assertTrue(len(query_result) > 0)
        only_pids = [str(one_result[0]) for one_result in query_result]
        print("only_pids=", only_pids)
        self.assertTrue(str(CurrentPid) in only_pids)

    def test_Win32_Process_all(self):
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?pid WHERE {
                ?url_process a survol:Win32_Process .
                ?url_process survol:Handle ?pid .
            }
        """ % (survol_namespace)
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)
        only_pids = [str(one_result[0]) for one_result in query_result]
        print("only_pids=", only_pids)
        self.assertTrue(str(CurrentPid) in only_pids)

    def test_wmi_query_disk_drive(self):
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_disk
            WHERE
            { ?url_disk rdf:type survol:CIM_DiskDrive .
            }
        """ % survol_namespace
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)

    def test_CIM_DataFile_Name(self):
        # FIXME: Very ugly harcode for transforming slashes to back-slashes and return. Same for lowercase.
        # FileAlwaysThere=
        # file_name = "c:/program files/mozilla firefox/firefox.exe"
        file_name = FileAlwaysThere.replace("\\", "/").lower()
        sparql_query="""
            PREFIX survol: <%s>
            SELECT ?url_file
            WHERE
            {
              ?url_file survol:Name "%s" .
              ?url_file rdf:type survol:CIM_DataFile .
            }""" % (survol_namespace, file_name)
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)
        self.assertTrue(len(query_result) == 1)
        datafile_node = lib_common.gUriGen.UriMakeFromDict("CIM_DataFile", {"Name": file_name})
        self.assertTrue(query_result[0][0] == datafile_node)

    def test_CIM_Directory_Name(self):
        # FIXME: Very ugly harcode for transforming slashes to back-slashes and return. Same for lowercase.
        # directory_name = "c:/program files/mozilla firefox"
        directory_name = DirAlwaysThere.replace("\\", "/").lower()
        sparql_query="""
            PREFIX survol: <%s>
            SELECT ?url_file
            WHERE
            {
              ?url_file survol:Name "%s" .
              ?url_file rdf:type survol:CIM_Directory .
            }""" % (survol_namespace, directory_name)
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)
        self.assertTrue(len(query_result) == 1)
        directory_node = lib_common.gUriGen.UriMakeFromDict("CIM_Directory", {"Name": directory_name})
        self.assertTrue(query_result[0][0] == directory_node)

    def test_server_wmi_more_user_account_caption(self):
        sparql_query = """
            PREFIX survol: <%s>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT ?caption
            WHERE
            {
                ?url_user rdf:type survol:Win32_UserAccount .
                ?url_user survol:Name '%s' .
                ?url_user survol:Caption ?caption .
            }""" % (survol_namespace, CurrentUsername)
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)
        self.assertTrue(len(query_result)== 1)
        account_caption = str(query_result[0][0])
        self.assertTrue(account_caption.lower() == CurrentMachine.lower() + "\\\\" + CurrentUsername)

    def test_server_wmi_more_user_account_domain(self):
        sparql_query = """
            PREFIX survol: <%s>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT ?domain ?caption
            WHERE
            {
                ?url_user rdf:type survol:Win32_UserAccount .
                ?url_user survol:Name '%s' .
                ?url_user survol:Caption ?caption .
                ?url_user survol:Domain ?domain .
            }""" % (survol_namespace, CurrentUsername)
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        # [(rdflib.term.Literal(u'rchateau-HP'), rdflib.term.Literal(u'rchateau-HP\\\\rchateau'))]
        print("Result=", query_result)
        self.assertTrue(len(query_result)== 1)
        account_domain = str(query_result[0][0])
        account_caption = str(query_result[0][1])
        self.assertTrue(account_domain.lower() == CurrentMachine.lower())
        self.assertTrue(account_caption.lower() == CurrentMachine.lower() + "\\\\" + CurrentUsername)


class SparqlCallWmiAssociatorsTest(CUSTOM_EVALS_WMI_Base_Test):

    @unittest.skip("Too slow !!!")
    def test_associator_process_datafile(self):
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_proc ?url_file
            WHERE
            { ?url_proc survol:Handle %d  .
              ?url_proc survol:CIM_ProcessExecutable ?url_file  .
              ?url_proc rdf:type survol:CIM_Process .
              ?url_file rdf:type survol:CIM_DataFile .
            }""" % (survol_namespace, CurrentPid)
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)

    def test_associator_file_directories(self):
        """Combinations of directories and files"""
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_fileA ?url_fileB
            WHERE
            { ?url_fileA rdf:type survol:CIM_Directory .
              ?url_fileA survol:Name "C:/Windows"  .
              ?url_fileA survol:CIM_DirectoryContainsFile ?url_fileB  .
              ?url_fileB survol:Name "C:/Windows/regedit.exe"  .
              ?url_fileB rdf:type survol:CIM_DataFile .
            }""" % survol_namespace
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)

    @unittest.skip("NOT WORKING YET")
    def test_associator_directory_subdirectory_cmd(self):
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_fileA ?url_fileB ?url_fileC
            WHERE
            { ?url_fileA rdf:type survol:CIM_Directory .
              ?url_fileB survol:Win32_SubDirectory ?url_fileA  .
              ?url_fileB rdf:type survol:CIM_Directory .
              ?url_fileC survol:CIM_DirectoryContainsFile ?url_fileB  .
              ?url_fileC survol:Name "C:/Windows/System32/cmd.exe"  .
              ?url_fileC rdf:type survol:CIM_DataFile .
            }""" % survol_namespace
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)

    @unittest.skip("Too slow !!!")
    def test_associator_file_cmd(self):
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_fileA ?url_fileB
            WHERE
            { ?url_fileA rdf:type survol:CIM_Directory .
              ?url_fileB survol:CIM_DirectoryContainsFile ?url_fileA  .
              ?url_fileB survol:Name "C:/Windows/System32/cmd.exe"  .
              ?url_fileB rdf:type survol:CIM_DataFile .
            }""" % survol_namespace
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)

    @unittest.skip("Too slow !!!")
    def test_associator_directory_system32(self):
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_fileA ?url_fileB
            WHERE
            { ?url_fileA rdf:type survol:CIM_Directory .
              ?url_fileB survol:Win32_SubDirectory ?url_fileA  .
              ?url_fileB survol:Name "C:/Windows/System32"  .
              ?url_fileB rdf:type survol:CIM_Directory .
            }""" % survol_namespace
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)

    def test_associator_windows_directory(self):
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_fileA ?url_fileB
            WHERE
            { ?url_dirA survol:Name "C:/Windows"  .
              ?url_dirA rdf:type survol:CIM_Directory .
              ?url_dirA survol:Win32_SubDirectory ?url_dirB  .
              ?url_dirB rdf:type survol:CIM_Directory .
            }""" % survol_namespace
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)

    @unittest.skip("Too slow !!!")
    def test_associator_windows_datafile(self):
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_fileA ?url_fileB
            WHERE
            { ?url_fileA survol:Name "C:/Windows"  .
              ?url_fileA rdf:type survol:CIM_Directory .
              ?url_fileA survol:CIM_DirectoryContainsFile ?url_fileB  .
              ?url_fileB rdf:type survol:CIM_DataFile .
            }""" % survol_namespace
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)

    def test_wmi_associators_pid_to_files(self):
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_proc ?url_file
            WHERE
            {
              ?url_proc survol:Handle %d .
              ?url_proc rdf:type survol:CIM_Process .
              ?url_proc survol:CIM_ProcessExecutable ?url_file .
              ?url_file rdf:type survol:CIM_DataFile .
            }""" % (survol_namespace, CurrentPid)
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)

    def test_wmi_associators_executable_to_files(self):
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_proc ?url_file
            WHERE
            {
              ?url_proc survol:Caption "firefox.exe"  .
              ?url_proc rdf:type survol:CIM_Process .
              ?url_proc survol:CIM_ProcessExecutable ?url_file .
              ?url_file rdf:type survol:CIM_DataFile .
            }""" % survol_namespace
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)

    def test_wmi_associators_pid_to_exe(self):
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_proc ?url_file
            WHERE
            {
              ?url_proc survol:Handle %d  .
              ?url_proc rdf:type survol:CIM_Process .
              ?url_proc survol:CIM_ProcessExecutable ?url_file .
              ?url_file survol:Name 'c:/program files/mozilla firefox/firefox.exe' .
              ?url_file rdf:type survol:CIM_DataFile .
            }
            """ % (survol_namespace, CurrentPid)
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)

    def test_wmi_associators_all_procs_to_firefox(self):
        # TODO: How to have backslashes in SparQL queries ???
        # "C:&#92;Users" 0x5C "C:%5CUsers"
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_proc ?url_file
            WHERE
            {
              ?url_proc survol:Handle ?proc_id  .
              ?url_proc rdf:type survol:CIM_Process .
              ?url_file survol:CIM_ProcessExecutable ?url_proc .
              ?url_file survol:Name '%s' .
              ?url_file rdf:type survol:CIM_DataFile .
            }
            """ % (survol_namespace, r"c:\\program files\\mozilla firefox\\firefox.exe")
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)

class SparqlSeeAlsoTest(CUSTOM_EVALS_WMI_Base_Test):
    def test_see_also_data_file(self):
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_proc
            WHERE
            { ?url_proc survol:Name "%s" .
              ?url_proc rdf:type survol:CIM_DataFile .
              ?url_proc rdfs:seeAlso "survol:CIM_DataFile/python_properties" .
            }
            """ % (survol_namespace, sys.executable)
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)

    def test_see_also_mapping_processes(self):
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_proc
            WHERE
            { ?url_proc survol:Name "/usr/lib/systemd/systemd-journald" .
              ?url_proc rdf:type survol:CIM_DataFile .
              ?url_proc rdfs:seeAlso "survol:CIM_DataFile/mapping_processes" .
            }""" % (survol_namespace)
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)

    def test_see_also_process_handle(self):
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_proc
            WHERE
            { ?url_proc survol:Handle %d  .
              ?url_proc rdf:type survol:CIM_Process .
              ?url_proc rdfs:seeAlso <http://vps516494.ovh.net/Survol/survol/entity.py?xid=CIM_Process.Handle=29&mode=rdf> .
            }""" % (survol_namespace)
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)

    def test_see_also_three_urls(self):
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_proc
            WHERE
            { ?url_proc survol:Handle %d  .
              ?url_proc rdf:type survol:CIM_Process .
              ?url_proc rdfs:seeAlso "survol:CIM_Process/process_open_files" .
              ?url_proc rdfs:seeAlso "survol:CIM_Process/single_pidstree" .
              ?url_proc rdfs:seeAlso "survol:CIM_Process/languages/python/current_script" .
            }""" % (survol_namespace)
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)

    def test_see_also_python_properties(self):
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_proc ?url_file
            WHERE
            { ?url_proc survol:Handle %d  .
              ?url_proc rdf:type survol:CIM_Process .
              ?url_proc survol:CIM_ProcessExecutable ?url_file  .
              ?url_file rdf:type survol:CIM_DataFile .
              ?url_file rdfs:seeAlso "survol:CIM_DataFile/python_properties" .
            }
            """ % (survol_namespace, CurrentPid)
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)

    def test_see_also_file_stat(self):
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_proc ?url_file
            WHERE
            { ?url_proc survol:Handle %d  .
              ?url_proc survol:CIM_ProcessExecutable ?url_file  .
              ?url_proc rdf:type survol:CIM_Process .
              ?url_file rdf:type survol:CIM_DataFile .
              ?url_file rdfs:seeAlso "survol:CIM_DataFile/file_stat" .
            }
            """ % (survol_namespace, CurrentPid)
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)


class SparqlMetaTest(CUSTOM_EVALS_WMI_Base_Test):

    def test_all_classes(self):
        """All WMI classes."""
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_class
            WHERE
            { ?url_class rdf:type rdfs:Class .
            }""" % (survol_namespace)
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)

    def test_labelled_class(self):
        """One WMI class with a given name."""
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_class
            WHERE
            { ?url_class rdf:type rdfs:Class .
              ?url_class rdfs:label "CIM_Process" .
            }""" % (survol_namespace)
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)

    def test_all_sub_classes(self):
        # This returns all pairs of WMI classes and subclasses.
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_class ?url_subclass
            WHERE
            { ?url_subclass rdfs:subClassOf ?url_class .
              ?url_class rdf:type rdfs:Class .
              ?url_subclass rdf:type rdfs:Class .
            }""" % (survol_namespace)
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)

    def test_base_class(self):
        # This prints the base class of CIM_Process
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_cim_process ?url_base_class
            WHERE
            { ?url_cim_process rdfs:subClassOf ?url_base_class .
              ?url_base_class rdf:type rdfs:Class .
              ?url_cim_process rdf:type rdfs:Class .
              ?url_cim_process rdfs:label "CIM_Process" .
            }""" % (survol_namespace)
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)

    def test_subclasses(self):
        # This prints the derived classes of a given base class.
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_class ?url_subclass
            WHERE
            { ?url_subclass rdfs:subClassOf ?url_base_class .
              ?url_base_class rdf:type rdfs:Class .
              ?url_subclass rdf:type rdfs:Class .
              ?url_base_class rdfs:label "CIM_LogicalElement" .
            }""" % (survol_namespace)
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)

    def test_all_properties(self):
        # This returns all WMI properties of classes.
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_attribute
            WHERE
            { ?url_attribute rdf:type rdf:Property .
            }""" % (survol_namespace)
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)

    def test_all_process_properties(self):
        # This returns all properties of the class CIM_Process.
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_property
            WHERE
            { ?url_property rdf:type rdf:Property .
              ?url_property rdfs:domain survol:CIM_Process .
            }""" % (survol_namespace)
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)

    def test_all_process_named_property(self):
        # This returns the property named "Handle" of the class CIM_Process.
        sparql_query = """
            SELECT ?url_property
            WHERE
            { ?url_property rdf:type rdf:Property .
              ?url_property rdfs:domain survol:CIM_Process .
              ?url_property rdfs:label "Handle" .
            }""" % (survol_namespace)
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)

    def test_all_process_dynamic_property(self):
        # This returns all objects with a dynamic property.
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_property
            WHERE
            { ?url_property rdf:type rdf:Property .
              ?url_property rdfs:domain survol:CIM_Process .
            }""" % (survol_namespace)
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)

    def test_server_survol_wmi_meta(self):
        sparql_query = """
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT ?url_class
            WHERE
            { ?url_class rdf:type rdfs:Class .
            }
            """
        rdflib_graph = rdflib.Graph()
        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)

    # Some query examples taken from https://codyburleson.com/sparql-examples-list-classes/
    # TODO: Test rdfs:range

################################################################################

# This works: gwmi -Query 'xxxxx'
# ASSOCIATORS OF {Win32_Process.Handle=1520}
# ASSOCIATORS OF {CIM_Process.Handle=1520}
# ASSOCIATORS OF {CIM_Process.Handle=1520} where classdefsonly
# ASSOCIATORS OF {CIM_Process.Handle=1520} where resultclass=CIM_DataFile

# For the associators, the exact keys are needed, i.e. ite object path.

if __name__ == '__main__':
    unittest.main()

# TODO: Test calls to <Any class>.AddInfo()
# TODO: When double-clicking any Python script, it should do something visible.

