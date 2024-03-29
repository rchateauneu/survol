#!/usr/bin/env python

from __future__ import print_function

import os
import sys
import subprocess
import tempfile
import rdflib
import unittest
import psutil

from init import *

update_test_path()

import lib_util
import lib_kbase
import lib_sparql_custom_evals

survol_namespace = lib_kbase.LDT

try:
    from rdflib.plugins.memory import IOMemory
except ImportError:
    from rdflib.plugins.stores.memory import Memory as IOMemory

class SurvolStore(IOMemory):
    """The derived class of a plain rdflib store helps debugging."""
    def __init__(self, configuration=None, identifier=None):
        super(SurvolStore, self).__init__(configuration)

    def triples(self, t_triple, context=None):
        t_subject, t_predicate, t_object = t_triple
        # print("triples vals=",t_subject, t_predicate, t_object)
        # print("triples typs=",type(t_subject), type(t_predicate), type(t_object))

        """
        triples vals= None http://www.w3.org/1999/02/22-rdf-syntax-ns#type http://primhillcomputer.com/ontologies/CIM_Directory
        triples typs= <type 'NoneType'> <class 'rdflib.term.URIRef'> <class 'rdflib.term.URIRef'>
        """

        return super(SurvolStore, self).triples((t_subject, t_predicate, t_object), context)


def _create_graph():
    """The return value behaves exactly like a rdflib Graph plus ease of debuggign if needed"""
    survol_store = SurvolStore()
    rdflib_graph = rdflib.Graph(survol_store)

    return rdflib_graph


# This displays the correct case for a filename. This is necessary because
# the variable sys.executable is not correctly cased with pytest on Windows.
# "c:\python27\python.exe" into "C:/Python27/python.exe"
sys_executable_case = lib_util.standardized_file_path(sys.executable)


################################################################################
# TODO: If the class is not statically defined, use WMI or WBEM,
# without using SeeAlso.
# If a property or an associator is not defined is a custom property,
# use WMI or WBEM.
#
# Use rdfs:seeAlso for scripts: It just loads the content.
# Comme seeAlso est un attribute, on passe les parametres.
#               ?url_file rdf:type survol:CIM_DataFile .
#               ?url_file rdfs:seeAlso "survol:CIM_DataFile/python_properties" .
#               ?url_file survol:CIM_ProcessExecutable ?url_proc  .
#
# Other query examples.

# {'url_proc': {'CSName': 'RCHATEAU-HP', 'Name': 'python.exe', 'ProcessId': str(CurrentPid),
#               'Handle': str(CurrentPid),
#               'OSCreationClassName': 'Win32_OperatingSystem',
#               '__class__': 'CIM_Process',
#               'rdf-schema#isDefinedBy': 'WMI',
#               'ParentProcessId': str(CurrentParentPid),
#               'Caption': 'python.exe',
#               'CSCreationClassName': 'Win32_ComputerSystem', 'Description': 'python.exe',
#               'ExecutablePath': 'C:\\\\Python27\\\\python.exe',
#               'CreationClassName': 'Win32_Process', },
#  'url_file': {'CSName': 'RCHATEAU-HP',
#               'FSCreationClassName': 'Win32_FileSystem',
#               'Description': 'c:\\\\python27\\\\python.exe', '__class__': 'CIM_DataFile',
#               'rdf-schema#isDefinedBy': 'WMI',
#               'Name': 'c:\\\\python27\\\\python.exe',
#               'FileType': 'Application', 'Drive': 'c:', 'Extension': 'exe',
#               'Caption': 'c:\\\\python27\\\\python.exe',
#               'CSCreationClassName': 'Win32_ComputerSystem', 'FileName': 'python',
#               'CreationClassName': 'CIM_LogicalFile'}},
# ],

################################################################################
# Utilities functions.

# Sparql does easily accept strings with backslahes. Therefore, it is simpler
# to enforce a plain slash as file path separator for Windows.
_temp_dir_path = lib_util.standardized_file_path(tempfile.gettempdir())


def _create_temp_file():
    tmp_filename = "survol_temp_file_%d.tmp" % os.getpid()
    tmp_pathname = os.path.join(_temp_dir_path, tmp_filename)
    tmpfil = open(tmp_pathname, "w")
    tmpfil.close()
    return tmp_pathname


# This generates an unique directory name.
_unique_string = "%d_%f" % (os.getpid(), time.time())


def _print_subprocesses(proc_id, depth = 0):
    for one_proc in psutil.Process(proc_id).children(recursive=False):
        print("    " * depth, one_proc.pid)
        _print_subprocesses(one_proc.pid, depth+1)


class CUSTOM_EVALS_Survol_Base_Test(unittest.TestCase):
    """
    This sets the CUSTOM_EVALS callback for all derived tests.
    It is mandatory to define which sets of classes are used to create CIM objects.
    There might be several representations, with an overlap of plain CIM classes:
    - WMI: Classes and instances are listed with WMI calls exclusively. This is for Windows.
    - WBEM: Classes and instances are listed with WBEM and pywbem calls exclusively. This is for Linux.
    - Survol: Which derived from WMI or WBEM and adds it owns classes which are not represented yet in CIM, WMI or WBEM.
    """

    def setUp(self):
        # add function directly, normally we would use setuptools and entry_points
        rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_function'] = lib_sparql_custom_evals.custom_eval_function

    def tearDown(self):
        if 'custom_eval_function' in rdflib.plugins.sparql.CUSTOM_EVALS:
            del rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_function']


class CUSTOM_EVALS_Low_Level_Test(CUSTOM_EVALS_Survol_Base_Test):
    """
    This tests low-level and internal features.
    """

    def _one_return_tst(self, num_results_expected, return_variables):
        # https://docs.python.org/3/library/itertools.html#itertools.combinations
        # itertools.product

        def make_var(input_var):
            """
            This receives input data for testing the enujmeration of all combinations of variables and values.
            It just transforms the variable names into rdflib variable nodes, and values into rdflib literals.
            This is needed to test the library function whch calculates the combinations.

            :param input_var: This is a dictionary whose keys are tuples of strings representing Sparql variables.
            :return:
            """
            return_dict = {}
            for variables_tuple, values_list in input_var.items():
                var_node = tuple(rdflib.term.Variable(variable_name) for variable_name in variables_tuple)
                values_nodes = [
                    tuple(rdflib.term.Literal(one_value)
                    for one_value in one_value_tuple)
                    for one_value_tuple in values_list]
                return_dict[var_node] = values_nodes
            return return_dict

        input_as_variables = make_var(return_variables)
        results_iter = lib_sparql_custom_evals.product_variables_lists(input_as_variables)
        print("return_variables=", return_variables)
        results_list = list(results_iter)
        for one_resu in results_list:
            print("one_resu=", one_resu)

        num_results_actual = len(results_list)
        self.assertEqual(num_results_actual, num_results_expected)

    def test_prod_variables(self):
        """
        This tests the enumeration of all possible combination of values or a set of input variables,
        that is, the cartesians product of Sparql variables and their values.
        This loops on all possible combinations.
        """
        self._one_return_tst(1, {('a',): [('a1',)], ('b',): [('b1',)], ('c',): [('c1',)], })
        self._one_return_tst(2, {('a',): [('a1',)], ('b',): [('b1',), ('b2',)], ('c',): [('c1',)], })
        self._one_return_tst(6, {('a',): [('a1',)], ('b',): [('b1',), ('b2',)], ('c',): [('c1',), ('c2',), ('c3',)], })
        self._one_return_tst(2, {('a', 'aa'): [('a1', 'aa1')], ('b',): [('b1',), ('b2',)], ('c',): [('c1',)], })
        self._one_return_tst(4, {('a', 'aa'): [('a1', 'aa1'), ('a2', 'aa2')], ('b',): [('b1',), ('b2',)], ('c',): [('c1',)], })


class CUSTOM_EVALS_Basic_Sparql_Queries_Test(CUSTOM_EVALS_Survol_Base_Test):

    def test_sparql_parent(self):
        rdflib_graph = _create_graph()

        # C:/Windows/temp\\survol_temp_file_12532.tmp'
        tmp_pathname = _create_temp_file()

        # Sparql does not accept backslashes.
        tmp_pathname = lib_util.standardized_file_path(tmp_pathname)

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?directory_name WHERE {
                ?url_directory a survol:CIM_Directory .
                ?url_datafile a survol:CIM_DataFile .
                ?url_directory survol:CIM_DirectoryContainsFile ?url_datafile .
                ?url_directory survol:Name ?directory_name .
                ?url_datafile survol:Name "%s" .
            }
        """ % (survol_namespace, tmp_pathname)

        query_result = list(rdflib_graph.query(sparql_query))
        self.assertEqual(str(query_result[0][0]), _temp_dir_path)
        print("Result=", query_result)

    def test_sparql_children_files(self):
        rdflib_graph = _create_graph()

        # C:/Windows/temp\\survol_temp_file_12532.tmp'
        tmp_pathname = lib_util.standardized_file_path(_create_temp_file())

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?datafile_name WHERE {
                ?url_directory a survol:CIM_Directory .
                ?url_datafile a survol:CIM_DataFile .
                ?url_directory survol:CIM_DirectoryContainsFile ?url_datafile .
                ?url_datafile survol:Name ?datafile_name .
                ?url_directory survol:Name "%s" .
            }
        """ % (survol_namespace, _temp_dir_path)

        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)
        self.assertTrue(tmp_pathname in [str(node[0]) for node in query_result])

    def test_sparql_grandparent(self):
        rdflib_graph = _create_graph()

        # C:/Windows/temp\\survol_temp_file_12532.tmp'
        tmp_pathname = _create_temp_file()

        # Sparql does not accept backslashes.
        tmp_pathname = lib_util.standardized_file_path(tmp_pathname)

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?grandparent_name WHERE {
                ?url_grandparent a survol:CIM_Directory .
                ?url_directory a survol:CIM_Directory .
                ?url_datafile a survol:CIM_DataFile .
                ?url_grandparent survol:CIM_DirectoryContainsFile ?url_directory .
                ?url_directory survol:CIM_DirectoryContainsFile ?url_datafile .
                ?url_grandparent survol:Name ?grandparent_name .
                ?url_datafile survol:Name "%s" .
            }
        """ % (survol_namespace, tmp_pathname)

        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)
        temp_dir_path_dir = lib_util.standardized_file_path(os.path.dirname(_temp_dir_path))
        self.assertEqual(str(query_result[0][0]), temp_dir_path_dir)

    def _create_files_tree(self, prefix, files_tree):
        def _create_files_tree_aux(root_dir, files_tree):
            os.makedirs(root_dir)
            for key, value in files_tree.items():
                one_path = os.path.join(root_dir, key)
                if value:
                    assert isinstance(value, dict)
                    _create_files_tree_aux(one_path, value)
                else:
                    open(one_path, "w").close()

        root_dir = os.path.join(_temp_dir_path, "survol_temp_%s_%s" % (prefix, _unique_string))

        _create_files_tree_aux(root_dir, files_tree)
        return root_dir

    def test_sparql_grandchildren_files(self):
        rdflib_graph = _create_graph()

        files_tree = {
            "dir_1" : { "dir_1_1" : { "file_1_1_1.txt": None}},
            "dir_2": {"dir_2_1": {"file_2_1_1.txt": None, "file_2_1_2.txt": None, "file_2_1_3.txt": None}},
            "file_3.txt": None,
            "dir_4": {"dir_4_1": {"file_4_1_1.txt": None, "dir_4_1_1_1": {"file_4_1_1_1_1.txt": None, }, "file_4_2.txt":None}},
            "dir_5": {"file_5_1.txt": None},
        }

        test_root_dir = self._create_files_tree("tst_grand_children", files_tree)
        test_root_dir = lib_util.standardized_file_path(test_root_dir)

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?datafile_name WHERE {
                ?url_directory_0 a survol:CIM_Directory .
                ?url_directory_0 survol:Name "%s" .
                ?url_directory_0 survol:CIM_DirectoryContainsFile ?url_directory_1 .
                ?url_directory_1 a survol:CIM_Directory .
                ?url_directory_1 survol:Name ?directory_name_1 .
                ?url_directory_1 survol:CIM_DirectoryContainsFile ?url_directory_2 .
                ?url_directory_2 a survol:CIM_Directory .
                ?url_directory_2 survol:Name ?directory_name_2 .
                ?url_directory_2 survol:CIM_DirectoryContainsFile ?url_datafile .
                ?url_datafile a survol:CIM_DataFile .
                ?url_datafile survol:Name ?datafile_name .
            }
        """ % (survol_namespace, test_root_dir)

        query_result = list(rdflib_graph.query(sparql_query))

        def dir_depth(dir_path):
            return len(os.path.normpath(dir_path).split(os.path.sep))

        expected_files = []
        for root_dir, dir_lists, files_list in os.walk(test_root_dir):
            print("root=", root_dir, dir_depth(root_dir), dir_depth(test_root_dir))
            if dir_depth(root_dir) != dir_depth(test_root_dir) + 2:
                continue
            print("root_dir=", root_dir, dir_depth(root_dir))
            for one_file_name in files_list:
                sub_path_name = lib_util.standardized_file_path(os.path.join(root_dir, one_file_name))
                expected_files.append(sub_path_name)
        expected_files = sorted(expected_files)

        actual_files = sorted([str(one_path_url[0]) for one_path_url in query_result])
        print("actual_files  =", actual_files)
        print("expected_files=", expected_files)
        for x in zip(actual_files, expected_files):
            print(x)
        print("")
        self.assertEqual(actual_files, expected_files)

    def test_sparql_grandchildren_directories(self):
        rdflib_graph = _create_graph()

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?subdirectory_name WHERE {
                ?url_grandparent a survol:CIM_Directory .
                ?url_directory a survol:CIM_Directory .
                ?url_subdirectory a survol:CIM_Directory .
                ?url_grandparent survol:CIM_DirectoryContainsFile ?url_directory .
                ?url_directory survol:CIM_DirectoryContainsFile ?url_subdirectory .
                ?url_grandparent survol:Name "%s" .
                ?url_subdirectory survol:Name ?subdirectory_name .
            }
        """ % (survol_namespace, _temp_dir_path)

        query_result = list(rdflib_graph.query(sparql_query))

        expected_dirs = set()
        for root_dir, dir_lists, files_list in os.walk(_temp_dir_path):
            if lib_util.standardized_file_path(os.path.dirname(root_dir)) == _temp_dir_path:
                for one_file_name in dir_lists:
                    sub_path_name = lib_util.standardized_file_path(os.path.join(root_dir, one_file_name))
                    expected_dirs.add(sub_path_name)

        actual_dirs = set([str(one_path_url[0]) for one_path_url in query_result])
        print("actual_dirs=", actual_dirs)
        print("expected_dirs=", expected_dirs)
        self.assertEqual(actual_dirs, expected_dirs)

    def test_sparql_subdirectory_2(self):
        """Tests that a second-level directory is detected. """
        rdflib_graph = _create_graph()

        dir_path = os.path.join(_temp_dir_path,
            "survol_temp_dir%s_1" % _unique_string,
            "survol_temp_dir%s_2" % _unique_string)
        os.makedirs(dir_path)
        dir_path = lib_util.standardized_file_path(dir_path)

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?subdirectory_name WHERE {
                ?url_directory_0 a survol:CIM_Directory .
                ?url_directory_1 a survol:CIM_Directory .
                ?url_directory_2 a survol:CIM_Directory .
                ?url_directory_0 survol:CIM_DirectoryContainsFile ?url_directory_1 .
                ?url_directory_1 survol:CIM_DirectoryContainsFile ?url_directory_2 .
                ?url_directory_0 survol:Name "%s" .
                ?url_directory_2 survol:Name ?subdirectory_name .
            }
        """ % (survol_namespace, _temp_dir_path)

        query_result = list(rdflib_graph.query(sparql_query))

        print("dir_path=", dir_path)

        actual_files = set([str(one_path_url[0]) for one_path_url in query_result])
        print("actual_files=", actual_files)
        self.assertTrue(dir_path in actual_files)

    def test_sparql_subdirectory_3(self):
        """Tests that a third-level directory is detected. """
        rdflib_graph = _create_graph()

        dir_path = os.path.join(
            _temp_dir_path,
            "survol_temp_dir%s_1" % _unique_string,
            "survol_temp_dir%s_2" % _unique_string,
            "survol_temp_dir%s_3" % _unique_string)
        os.makedirs(dir_path)
        # Must be called if the directory exists, otherwise, on Windows, it can be correctly capitalized.
        dir_path = lib_util.standardized_file_path(dir_path)

        print("dir_path=", dir_path)

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?subdirectory_name WHERE {
                ?url_directory_0 a survol:CIM_Directory .
                ?url_directory_1 a survol:CIM_Directory .
                ?url_directory_2 a survol:CIM_Directory .
                ?url_directory_3 a survol:CIM_Directory .
                ?url_directory_0 survol:CIM_DirectoryContainsFile ?url_directory_1 .
                ?url_directory_1 survol:CIM_DirectoryContainsFile ?url_directory_2 .
                ?url_directory_2 survol:CIM_DirectoryContainsFile ?url_directory_3 .
                ?url_directory_0 survol:Name "%s" .
                ?url_directory_3 survol:Name ?subdirectory_name .
            }
        """ % (survol_namespace, _temp_dir_path)

        query_result = list(rdflib_graph.query(sparql_query))

        print("dir_path=", dir_path)

        actual_files = set([str(one_path_url[0]) for one_path_url in query_result])
        print("actual_files=", actual_files)
        self.assertTrue(dir_path in actual_files)

    def test_sparql_subdirectory_4(self):
        """Tests that a fourth-level directory is detected. """
        rdflib_graph = _create_graph()

        dir_path = os.path.join(
            _temp_dir_path,
            "survol_temp_dir%s_1" % _unique_string,
            "survol_temp_dir%s_2" % _unique_string,
            "survol_temp_dir%s_3" % _unique_string,
            "survol_temp_dir%s_4" % _unique_string)
        os.makedirs(dir_path)
        dir_path = lib_util.standardized_file_path(dir_path)

        print("dir_path=", dir_path)

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?subdirectory_name WHERE {
                ?url_directory_0 a survol:CIM_Directory .
                ?url_directory_1 a survol:CIM_Directory .
                ?url_directory_2 a survol:CIM_Directory .
                ?url_directory_3 a survol:CIM_Directory .
                ?url_directory_4 a survol:CIM_Directory .
                ?url_directory_0 survol:CIM_DirectoryContainsFile ?url_directory_1 .
                ?url_directory_1 survol:CIM_DirectoryContainsFile ?url_directory_2 .
                ?url_directory_2 survol:CIM_DirectoryContainsFile ?url_directory_3 .
                ?url_directory_3 survol:CIM_DirectoryContainsFile ?url_directory_4 .
                ?url_directory_0 survol:Name "%s" .
                ?url_directory_4 survol:Name ?subdirectory_name .
            }
        """ % (survol_namespace, _temp_dir_path)

        query_result = list(rdflib_graph.query(sparql_query))

        print("dir_path=", dir_path)

        actual_files = set([str(one_path_url[0]) for one_path_url in query_result])
        print("actual_files=", actual_files)
        self.assertTrue(dir_path in actual_files)

    @unittest.skipIf(is_windows7, "Does not work on Windows 7")
    def test_sparql_subdirectory_down_up_4(self):
        rdflib_graph = _create_graph()

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?directory_name WHERE {
                ?url_directory_0a a survol:CIM_Directory .
                ?url_directory_1a a survol:CIM_Directory .
                ?url_directory_2a a survol:CIM_Directory .
                ?url_directory_3a a survol:CIM_Directory .
                ?url_directory_4X a survol:CIM_Directory .
                ?url_directory_3b a survol:CIM_Directory .
                ?url_directory_2b a survol:CIM_Directory .
                ?url_directory_1b a survol:CIM_Directory .
                ?url_directory_0b a survol:CIM_Directory .
                ?url_directory_0a survol:CIM_DirectoryContainsFile ?url_directory_1a .
                ?url_directory_1a survol:CIM_DirectoryContainsFile ?url_directory_2a .
                ?url_directory_2a survol:CIM_DirectoryContainsFile ?url_directory_3a .
                ?url_directory_3a survol:CIM_DirectoryContainsFile ?url_directory_4X .
                ?url_directory_3b survol:CIM_DirectoryContainsFile ?url_directory_4X .
                ?url_directory_2b survol:CIM_DirectoryContainsFile ?url_directory_3b .
                ?url_directory_1b survol:CIM_DirectoryContainsFile ?url_directory_2b .
                ?url_directory_0b survol:CIM_DirectoryContainsFile ?url_directory_1b .
                ?url_directory_0a survol:Name "%s" .
                ?url_directory_0b survol:Name ?directory_name .
            }
        """ % (survol_namespace, _temp_dir_path)

        query_result = list(rdflib_graph.query(sparql_query))

        actual_files = [
            lib_util.standardized_file_path(str(one_path_url[0]))
            for one_path_url in query_result]
        print("actual_files=", actual_files)
        self.assertEqual(actual_files[0], _temp_dir_path)

        # All directories must be identical.
        unique_set = set(actual_files)
        self.assertEqual(len(unique_set), 1)

    def test_sparql_parent_process(self):
        """Display the parent process of the current one."""
        rdflib_graph = _create_graph()

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?the_ppid
            WHERE
            { ?url_proc survol:Handle %d .
              ?url_proc survol:ParentProcessId ?the_ppid .
              ?url_proc rdf:type survol:CIM_Process .
            }
        """ % (survol_namespace, CurrentPid)

        query_result = list(rdflib_graph.query(sparql_query))

        parent_pid = psutil.Process(CurrentPid).ppid()
        print("parent_pid=", parent_pid)
        actual_pid = [str(one_pid[0]) for one_pid in query_result]
        print("actual_pid=", actual_pid)
        self.assertTrue(int(actual_pid[0]) == parent_pid)

    def test_sparql_sub_processes(self):
        """All subprocesses of the current one."""
        rdflib_graph = _create_graph()

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?process_id
            WHERE
            { ?url_proc survol:Handle ?process_id .
              ?url_proc survol:ParentProcessId %d .
              ?url_proc rdf:type survol:CIM_Process .
            }
        """ % (survol_namespace, os.getpid())

        query_result = list(rdflib_graph.query(sparql_query))

        actual_pids = set([int(str(one_pid[0])) for one_pid in query_result])
        print("actual_pids=", actual_pids)
        # Comparaison with the list of sub-processes of the current one.
        expected_pids = set([proc.pid for proc in psutil.Process(os.getpid()).children(recursive=False)])
        print("expected_pids=", expected_pids)
        self.assertEqual(actual_pids, expected_pids)

    def test_sparql_all_processes(self):
        """All running processes on this machine."""
        rdflib_graph = _create_graph()

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?process_id
            WHERE
            { ?url_proc survol:Handle ?process_id .
              ?url_proc rdf:type survol:CIM_Process .
            }
        """ % survol_namespace

        # Comparison with the list of all processes.. This list must be built as close as possible
        # to the query execution, so the list do not change too much.
        # Very rarely, it might fail because of this rae condition. In this case, just rerun the test.
        expected_pids = set([proc.pid for proc in psutil.process_iter()])
        query_result = list(rdflib_graph.query(sparql_query))

        actual_pids = set([int(str(one_pid[0])) for one_pid in query_result])
        print("actual_pids=", actual_pids)

        print("expected_pids=", expected_pids)
        sets_difference =  [one_pid for one_pid in actual_pids if one_pid not in expected_pids]
        sets_difference += [one_pid for one_pid in expected_pids if one_pid not in actual_pids]
        print("sets_difference=", sets_difference)
        # Not too many processes were destroyed or deleted.
        self.assertTrue(len(sets_difference) < 10)
        self.assertTrue(CurrentPid in actual_pids)
        self.assertTrue(CurrentPid in expected_pids)

    def test_sparql_grandparent_process(self):
        """Grand-parent process of the current one."""
        rdflib_graph = _create_graph()

        parent_pid = psutil.Process(CurrentPid).ppid()
        print("parent_pid=", parent_pid)
        grandparent_pid = psutil.Process(parent_pid).ppid()
        print("grandparent_pid=", grandparent_pid)

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?pid_2
            WHERE
            {
              ?url_proc_0 survol:Handle %d .
              ?url_proc_0 survol:ParentProcessId ?pid_1 .
              ?url_proc_0 rdf:type survol:CIM_Process .
              ?url_proc_1 survol:Handle ?pid_1 .
              ?url_proc_1 survol:ParentProcessId ?pid_2 .
              ?url_proc_1 rdf:type survol:CIM_Process .
            }
        """ % (survol_namespace, CurrentPid)

        query_result = list(rdflib_graph.query(sparql_query))

        actual_pids = [int(str(one_pid[0])) for one_pid in query_result]
        print("actual_pids=", actual_pids)
        self.assertTrue(actual_pids[0] == grandparent_pid)

    def test_sparql_executable_process(self):
        """Executable run by the current process."""
        rdflib_graph = _create_graph()

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?datafile_name
            WHERE
            {
              ?url_proc survol:Handle %d .
              ?url_proc survol:CIM_ProcessExecutable ?url_datafile .
              ?url_proc rdf:type survol:CIM_Process .
              ?url_datafile rdf:type survol:CIM_DataFile .
              ?url_datafile survol:Name ?datafile_name .
            }
        """ % (survol_namespace, CurrentPid)

        query_result = list(rdflib_graph.query(sparql_query))
        print("query_result=", query_result)

        datafile_name = [str(one_value[0]) for one_value in query_result][0]
        print("datafile_name=", datafile_name)
        self.assertTrue(datafile_name == sys_executable_case)

    def test_sparql_processes_executing_python(self):
        """All processes running the current executable, i.e. Python"""
        rdflib_graph = _create_graph()

        # The Python variable sys.executable contains the currently running executable.
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?process_pid
            WHERE
            {
              ?url_proc survol:Handle ?process_pid .
              ?url_proc survol:CIM_ProcessExecutable ?url_datafile .
              ?url_proc rdf:type survol:CIM_Process .
              ?url_datafile rdf:type survol:CIM_DataFile .
              ?url_datafile survol:Name '%s' .
            }
        """ % (survol_namespace, sys_executable_case)

        query_result = list(rdflib_graph.query(sparql_query))
        print("query_result=", query_result)
        for s,p,o in rdflib_graph:
            print("    ", s, p, o)
        print("sparql_query=", sparql_query)

        # This must contain at least the current process.
        process_pids = [int(str(one_value[0])) for one_value in query_result]
        print("process_pids=", process_pids)
        self.assertTrue(CurrentPid in process_pids)

    def test_sparql_executable_process_dir(self):
        """Display the directory of the current process'executable."""
        rdflib_graph = _create_graph()

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?directory_name
            WHERE
            {
              ?url_proc survol:Handle %d .
              ?url_proc survol:CIM_ProcessExecutable ?url_datafile .
              ?url_proc rdf:type survol:CIM_Process .
              ?url_datafile rdf:type survol:CIM_DataFile .
              ?url_directory rdf:type survol:CIM_Directory .
              ?url_directory survol:CIM_DirectoryContainsFile ?url_datafile .
              ?url_directory survol:Name ?directory_name .
            }
        """ % (survol_namespace, CurrentPid)

        query_result = list(rdflib_graph.query(sparql_query))
        print("query_result=", query_result)

        directory_name = [str(one_value[0]) for one_value in query_result][0]
        print("directory_name=", directory_name)
        print("sys_executable_case=", sys_executable_case)
        self.assertEqual(directory_name, os.path.dirname(sys_executable_case))

    def test_sparql_files_in_executable_process_dir(self):
        """Display the files in the directory of the current process'executable."""
        rdflib_graph = _create_graph()

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?datafile_name
            WHERE
            {
              ?url_proc survol:Handle %d .
              ?url_proc survol:CIM_ProcessExecutable ?url_executable_datafile .
              ?url_proc rdf:type survol:CIM_Process .
              ?url_executable_datafile rdf:type survol:CIM_DataFile .
              ?url_datafile rdf:type survol:CIM_DataFile .
              ?url_directory rdf:type survol:CIM_Directory .
              ?url_directory survol:CIM_DirectoryContainsFile ?url_datafile .
              ?url_directory survol:CIM_DirectoryContainsFile ?url_executable_datafile .
              ?url_datafile survol:Name ?datafile_name .
            }
        """ % (survol_namespace, CurrentPid)

        query_result = list(rdflib_graph.query(sparql_query))

        files_names_result = {str(one_value[0]) for one_value in query_result}
        # print("files_names_result=", files_names_result)
        print("files_names_result len:", len(files_names_result))
        print("sys_executable_case=", sys_executable_case)
        self.assertTrue(sys_executable_case in files_names_result)

        # Compare with the list of the files the directory of the executable.
        path_names_set = set()
        for root_dir, dir_lists, files_list in os.walk(os.path.dirname(sys_executable_case)):
            for one_file_name in files_list:
                sub_path_name = lib_util.standardized_file_path(os.path.join(root_dir, one_file_name))
                path_names_set.add(sub_path_name)
            break
        # print("Expected list of files:", path_names_set)
        print("Expected list of files length:", len(path_names_set))
        print("Files differences A:", path_names_set.difference(files_names_result))
        print("Files differences B:", files_names_result.difference(path_names_set))
        self.assertEqual(path_names_set, files_names_result)

    def test_sparql_executable_process_grand_dir(self):
        """Display the directory of the directory of the current process'executable."""
        rdflib_graph = _create_graph()

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?grand_dir_name
            WHERE
            {
              ?url_proc survol:Handle %d .
              ?url_proc survol:CIM_ProcessExecutable ?url_datafile .
              ?url_proc rdf:type survol:CIM_Process .
              ?url_datafile rdf:type survol:CIM_DataFile .
              ?url_directory rdf:type survol:CIM_Directory .
              ?url_directory survol:CIM_DirectoryContainsFile ?url_datafile .
              ?url_grand_dir rdf:type survol:CIM_Directory .
              ?url_grand_dir survol:CIM_DirectoryContainsFile ?url_directory .
              ?url_grand_dir survol:Name ?grand_dir_name .
            }
        """ % (survol_namespace, CurrentPid)

        query_result = list(rdflib_graph.query(sparql_query))
        print("query_result=", query_result)

        directory_name = [str(one_value[0]) for one_value in query_result][0]
        print("directory_name=", directory_name)
        print("sys_executable_case=", sys_executable_case)
        self.assertEqual(directory_name, os.path.dirname((os.path.dirname(sys_executable_case))))

    def test_sparql_executable_parent_process(self):
        """Executable of the parent process."""
        rdflib_graph = _create_graph()

        print("CurrentParentPid=", CurrentParentPid)

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?executable_name
            WHERE
            {
              ?url_proc survol:Handle %d .
              ?url_proc survol:ParentProcessId ?CurrentParentPid .
              ?url_proc rdf:type survol:CIM_Process .
              ?url_parent_proc survol:Handle ?CurrentParentPid .
              ?url_parent_proc survol:CIM_ProcessExecutable ?url_executable_file .
              ?url_parent_proc rdf:type survol:CIM_Process .
              ?url_executable_file rdf:type survol:CIM_DataFile .
              ?url_executable_file survol:Name ?executable_name .
            }
        """ % (survol_namespace, CurrentPid)

        query_result = list(rdflib_graph.query(sparql_query))
        print("query_result=", query_result)

        actual_executable_name = [str(one_value[0]) for one_value in query_result][0]
        print("actual_executable_name=", actual_executable_name)
        expected_executable_name = lib_util.standardized_file_path(psutil.Process().parent().exe())
        print("expected_executable_name=", expected_executable_name)
        self.assertTrue(expected_executable_name == actual_executable_name)

    def test_sparql_sibling_processes(self):
        """Processes with the same parent process as the current one."""
        rdflib_graph = _create_graph()

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?sibling_process_id
            WHERE
            {
              ?url_proc survol:Handle %d .
              ?url_proc survol:ParentProcessId ?CurrentParentPid .
              ?url_proc rdf:type survol:CIM_Process .
              ?url_parent_proc survol:Handle ?CurrentParentPid .
              ?url_parent_proc rdf:type survol:CIM_Process .
              ?url_sibling_proc survol:ParentProcessId ?CurrentParentPid .
              ?url_sibling_proc survol:Handle ?sibling_process_id .
              ?url_sibling_proc rdf:type survol:CIM_Process .
            }
        """ % (survol_namespace, CurrentPid)

        query_result = list(rdflib_graph.query(sparql_query))
        print("query_result=", query_result)

        sibling_pids = [int(one_value[0]) for one_value in query_result]
        print("sibling_pids=", sibling_pids)
        self.assertTrue(CurrentPid in sibling_pids)

    # It also returns the process object, so it can be terminated.
    def create_process_tree_popen(self, depth):
        dir_path = os.path.dirname(__file__)
        sys.path.append(dir_path)

        # Modified Python path so it can find the special module to create a chain of subprocesses.
        my_env = os.environ.copy()
        # So Python can find the module create_process_chain which is in the current directory.
        my_env["PYTHONPATH"] = dir_path
        # Consider the option bufsize=0.
        proc = subprocess.Popen([sys.executable, '-m', 'create_process_chain',
                                 str(depth)], env=my_env,
                                 stdout = subprocess.PIPE, stderr=subprocess.PIPE, shell=False)

        print("create_process_tree_popen ", proc.pid)
        sys.stdout.flush()
        return_dict = {}
        for ix in range(depth+1):
            one_line = proc.stdout.readline()
            print("one_line=", one_line)
            one_depth, one_pid = map(int, one_line.split(b" "))
            return_dict[one_depth] = one_pid
        return proc, return_dict

    def test_processes_chain_creation(self):
        depth_processes = 5
        proc, return_dict = self.create_process_tree_popen(depth_processes)
        print("test_processes_chain_creation ", return_dict, "proc.pid=", proc.pid)
        # Because Shell=False when creating the subprocess.
        self.assertTrue(return_dict[depth_processes] == proc.pid)
        for ix in range(depth_processes):
            self.assertTrue(psutil.Process(return_dict[ix]).ppid() == return_dict[ix+1])
        time.sleep(1)
        proc.terminate()
        proc.wait()

    def process_chain_creation(self, depth_processes):
        """This helper function creates a chain of subprocesses which is used
        to check the detection of processes trees."""
        processes_list_first, pids_dict = self.create_process_tree_popen(depth_processes)
        pids_list = [pids_dict[index] for index in range(depth_processes, 0, -1)]
        return processes_list_first, pids_list

    def test_sparql_sub2_processes(self):
        rdflib_graph = _create_graph()

        processes_list_first, pids_list = self.process_chain_creation(2)

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?pid_1 ?pid_2
            WHERE
            {
              ?url_proc_1 survol:Handle ?pid_1 .
              ?url_proc_1 survol:ParentProcessId %d .
              ?url_proc_1 a survol:CIM_Process .
              ?url_proc_2 survol:Handle ?pid_2 .
              ?url_proc_2 survol:ParentProcessId ?pid_1  .
              ?url_proc_2 a survol:CIM_Process .
            }
        """ % (survol_namespace, CurrentPid)

        query_result = list(rdflib_graph.query(sparql_query))
        print("query_result=", query_result)

        print("Subprocesses start")
        _print_subprocesses(CurrentPid)
        print("Subprocesses end")

        actual_pids_list = [[int(one_pid[0]), int(one_pid[1])] for one_pid in query_result]
        print("pids_list=", pids_list)
        print("actual_pids_list=", actual_pids_list)
        self.assertTrue(pids_list in actual_pids_list)
        processes_list_first.terminate()
        processes_list_first.wait()

    def test_sparql_sub3_processes(self):
        rdflib_graph = _create_graph()

        processes_list_first, pids_list = self.process_chain_creation(3)

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?pid_1 ?pid_2 ?pid_3
            WHERE
            {
              ?url_proc_1 survol:Handle ?pid_1 .
              ?url_proc_1 survol:ParentProcessId %d .
              ?url_proc_1 a survol:CIM_Process .
              ?url_proc_2 survol:Handle ?pid_2 .
              ?url_proc_2 survol:ParentProcessId ?pid_1  .
              ?url_proc_2 a survol:CIM_Process .
              ?url_proc_3 survol:Handle ?pid_3 .
              ?url_proc_3 survol:ParentProcessId ?pid_2  .
              ?url_proc_3 a survol:CIM_Process .
            }
        """ % (survol_namespace, CurrentPid)

        query_result = list(rdflib_graph.query(sparql_query))
        print("query_result=", query_result)

        print("Subprocesses start")
        _print_subprocesses(CurrentPid)
        print("Subprocesses end")

        actual_pids_list = [[int(one_pid[0]), int(one_pid[1]), int(one_pid[2])] for one_pid in query_result]
        print("pids_list=", pids_list)
        print("actual_pids_list=", actual_pids_list)
        self.assertTrue(pids_list in actual_pids_list)
        processes_list_first.terminate()
        processes_list_first.wait()

    # It hangs on Travis with Linux:
    # No output has been received in the last 10m0s, this potentially ...
    # ... indicates a stalled build or something wrong with the build itself.
    @unittest.skipIf(is_travis_machine() and is_platform_linux, "Different implementation of processes. Test skipped.")
    def test_sparql_sub4_processes(self):
        rdflib_graph = _create_graph()

        processes_list_first, pids_list = self.process_chain_creation(4)

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?pid_1 ?pid_2 ?pid_3 ?pid_4
            WHERE
            {
              ?url_proc_1 survol:Handle ?pid_1 .
              ?url_proc_1 survol:ParentProcessId %d .
              ?url_proc_1 a survol:CIM_Process .
              ?url_proc_2 survol:Handle ?pid_2 .
              ?url_proc_2 survol:ParentProcessId ?pid_1  .
              ?url_proc_2 a survol:CIM_Process .
              ?url_proc_3 survol:Handle ?pid_3 .
              ?url_proc_3 survol:ParentProcessId ?pid_2  .
              ?url_proc_3 a survol:CIM_Process .
              ?url_proc_4 survol:Handle ?pid_4 .
              ?url_proc_4 survol:ParentProcessId ?pid_3  .
              ?url_proc_4 a survol:CIM_Process .
            }
        """ % (survol_namespace, CurrentPid)

        query_result = list(rdflib_graph.query(sparql_query))
        print("query_result=", query_result)

        print("Subprocesses start")
        _print_subprocesses(CurrentPid)
        print("Subprocesses end")

        actual_pids_list = [[int(one_pid[0]), int(one_pid[1]), int(one_pid[2]), int(one_pid[3])] for one_pid in query_result]
        print("pids_list=", pids_list)
        print("actual_pids_list=", actual_pids_list)
        self.assertTrue(pids_list in actual_pids_list)
        processes_list_first.terminate()
        processes_list_first.wait()

    # It hangs on Travis with Linux:
    # No output has been received in the last 10m0s, this potentially ...
    # ... indicates a stalled build or something wrong with the build itself.
    @unittest.skipIf(is_travis_machine() and is_platform_linux, "Different implementation of processes. Test skipped.")
    def test_sparql_sub5_processes(self):
        rdflib_graph = _create_graph()

        processes_list_first, pids_list = self.process_chain_creation(5)

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?pid_1 ?pid_2 ?pid_3 ?pid_4 ?pid_5
            WHERE
            {
              ?url_proc_1 survol:Handle ?pid_1 .
              ?url_proc_1 survol:ParentProcessId %d .
              ?url_proc_1 a survol:CIM_Process .
              ?url_proc_2 survol:Handle ?pid_2 .
              ?url_proc_2 survol:ParentProcessId ?pid_1  .
              ?url_proc_2 a survol:CIM_Process .
              ?url_proc_3 survol:Handle ?pid_3 .
              ?url_proc_3 survol:ParentProcessId ?pid_2  .
              ?url_proc_3 a survol:CIM_Process .
              ?url_proc_4 survol:Handle ?pid_4 .
              ?url_proc_4 survol:ParentProcessId ?pid_3  .
              ?url_proc_4 a survol:CIM_Process .
              ?url_proc_5 survol:Handle ?pid_5 .
              ?url_proc_5 survol:ParentProcessId ?pid_4  .
              ?url_proc_5 a survol:CIM_Process .
            }
        """ % (survol_namespace, CurrentPid)

        query_result = list(rdflib_graph.query(sparql_query))
        print("query_result=", query_result)

        print("Subprocesses start")
        _print_subprocesses(CurrentPid)
        print("Subprocesses end")

        actual_pids_list = [[int(one_pid[0]), int(one_pid[1]), int(one_pid[2]), int(one_pid[3]), int(one_pid[4])] for one_pid in query_result]
        print("pids_list=", pids_list)
        print("actual_pids_list=", actual_pids_list)
        self.assertTrue(pids_list in actual_pids_list)
        processes_list_first.terminate()
        processes_list_first.wait()


@unittest.skip("Not implemented yet.")
class Query_CIM_DataFile_find_Test(CUSTOM_EVALS_Survol_Base_Test):
    """
    This finds files using the linux command "find".

    These tests do not use custom filters.
    """

    def test_find_file(self):
        rdflib_graph = _create_graph()

    def test_find_filter_file(self):
        rdflib_graph = _create_graph()


@unittest.skip("Not implemented yet.")
class SelectEnumerationFromAttributes_CIM_DataFile_Test(CUSTOM_EVALS_Survol_Base_Test):
    """
    This uses Linux commands for querying and filtering CIM objects, or any other tool,
    implemented in the optional function SelectEnumerationFromAttributes in the Survol class definition.
    For example:
    - grep.
    """

    def test_Name(self):
        from sources_types import CIM_DataFile
        file_nodes = CIM_DataFile.SelectEnumerationFromAttributes(Name="abc.tmp")
        assert file_nodes is not None


@unittest.skip("Not implemented yet.")
class SelectEnumerationFromAttributes_CIM_Directory_Test(CUSTOM_EVALS_Survol_Base_Test):
    """
    This uses Linux commands for querying and filtering CIM objects, or any other tool,
    implemented in the optional function SelectEnumerationFromAttributes in the Survol class definition.
    For example:
    - grep.
    """

    def test_Name(self):
        from sources_types import CIM_Directory
        dir_nodes = CIM_Directory.SelectEnumerationFromAttributes(Name="abc.tmp")
        assert dir_nodes is not None


@unittest.skip("Not implemented yet.")
class SelectEnumerationFromAttributes_CIM_Process_Test(CUSTOM_EVALS_Survol_Base_Test):
    """
    This uses Linux commands for querying and filtering CIM objects, or any other tool,
    implemented in the optional function SelectEnumerationFromAttributes in the Survol class definition.
    For example:
    - grep.
    """

    def test_Handle(self):
        from sources_types import CIM_Process
        dir_nodes = CIM_Process.SelectEnumerationFromAttributes(Handle=os.getpid())
        assert dir_nodes is not None


    def test_dParentProcessI(self):
        from sources_types import CIM_Process
        dir_nodes = CIM_Process.SelectEnumerationFromAttributes(ParentProcessId=os.getpid())
        assert dir_nodes is not None


class SparqlMetaTest(CUSTOM_EVALS_Survol_Base_Test):
    """
    These tests focus on classes and properties, not on the objects.
    """

    def _get_survol_class_list(self):
        """
        This is a utility function to return the list of classes
        """
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_class
            WHERE
            { ?url_class rdf:type rdfs:Class .
            }""" % survol_namespace
        rdflib_graph = rdflib.Graph()
        query_result = set(rdflib_graph.query(sparql_query))
        if False:
            class_names = [str(class_name[0]).rpartition("#")[2] for class_name in query_result]
            print("class_names=", sorted(class_names))
        return query_result

    def test_cim_core_classes(self):
        """
        Minimum set of classes.
        These classes are also defined by CIM, WMI and WBEM.
        """
        query_result = self._get_survol_class_list()

        # A minimal set of classes must be present.
        self.assertTrue((lib_sparql_custom_evals.class_CIM_Process,) in query_result)
        self.assertTrue((lib_sparql_custom_evals.class_CIM_Directory,) in query_result)
        self.assertTrue((lib_sparql_custom_evals.class_CIM_DataFile,) in query_result)

    @unittest.skipIf(not is_platform_windows, "No Windows classes on Linux")
    def test_win32_classes(self):
        """
        Classes which are specific to WIN32.
        """
        query_result = self._get_survol_class_list()

        self.assertTrue((lib_kbase.class_node_uriref("Win32_Process"),) in query_result)

    def test_many_classes(self):
        """
        This tests the presence of classes which are specific to Survol,
        and are not defined by CIM, WMI, WBEM.
        """
        query_result = self._get_survol_class_list()

        # A minimal set of classes must be present.
        self.assertTrue((lib_kbase.class_node_uriref("addr"),) in query_result)
        self.assertTrue((lib_kbase.class_node_uriref("linker_symbol"),) in query_result)
        self.assertTrue((lib_kbase.class_node_uriref("memmap"),) in query_result)

    def test_nested_classes(self):
        """
        This tests the presence of classes which are specific to Survol,
        and are not defined by CIM, WMI, WBEM.
        """
        query_result = self._get_survol_class_list()

        list_of_classes = [
            "com.registered_type_lib",
            "com.type_lib",
            "com.type_lib_entry",
            "com.type_lib_entry.coclass",
            "com.type_lib_entry.dispatch",
            "com.type_lib_entry.enumeration",
            "com.type_lib_entry.module",

            "dbus.bus",
            "dbus.connection",
            "dbus.interface",
            "dbus.object",

            "java.mbean",

            "mysql.database",
            "mysql.instance",
            "mysql.query",
            "mysql.session",
            "mysql.table",

            "odbc",
            "odbc.column",
            "odbc.dsn",
            "odbc.procedure",
            "odbc.table",

            "oracle",
            "oracle.db",
            "oracle.function",
            "oracle.library",
            "oracle.package",
            "oracle.package_body",
            "oracle.procedure",
            "oracle.query",
            "oracle.schema",
            "oracle.sequence",
            "oracle.session",
            "oracle.synonym",
            "oracle.table",
            "oracle.trigger",
            "oracle.type",
            "oracle.view",

            "python.package",

            "rabbitmq",
            "rabbitmq.connection",
            "rabbitmq.exchange",
            "rabbitmq.manager",
            "rabbitmq.queue",
            "rabbitmq.user",
            "rabbitmq.vhost",

            "sql",
            "sql.query",
            "sql.sheet",

            "sqlite",
            "sqlite.column",
            "sqlite.file",
            "sqlite.query",
            "sqlite.table",
            "sqlite.view",

            "sqlserver",
            "sqlserver.dsn",
            "sqlserver.query",
            "sqlserver.schema",
            "sqlserver.session",
            "sqlserver.table",
            "sqlserver.view",
        ]

        for one_class in list_of_classes:
            self.assertTrue((lib_kbase.class_node_uriref(one_class),) in query_result)


    def test_win32_share_properties(self):
        """This returns all properties of the class Win32_Share."""
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?url_property
            WHERE
            { ?url_property rdf:type rdf:Property .
              ?url_property rdfs:domain survol:Win32_Share .
            }""" % survol_namespace
        rdflib_graph = rdflib.Graph()
        query_result = set(rdflib_graph.query(sparql_query))
        print("Properties of Win32_Share=", query_result)

        predicate_Name = rdflib.term.URIRef(lib_kbase.survol_url + "Name")

        self.assertTrue((predicate_Name,) in query_result)


if __name__ == '__main__':
    unittest.main()

