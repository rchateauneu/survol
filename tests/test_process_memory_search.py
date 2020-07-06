#!/usr/bin/env python

"""The intention is to test the capability to search for specific strigns in the memory of a running process."""

from __future__ import print_function

import unittest
import subprocess
import sys
import os

from init import *

# This loads the module from the source, so no need to install it, and no need of virtualenv.
update_test_path()

import lib_client
import lib_util

# For example r"C:\Perl64\bin\perl.exe" on Windows, "/usr/bin/perl" on Linux, or None if not installed.
_perl_path = check_program_exists("perl")
if _perl_path.decode(): _perl_path.decode()

sample_batch_script = os.path.join(os.path.dirname(__file__), "AnotherSampleDir", "CommandExample.bat")
sample_python_script = os.path.join(os.path.dirname(__file__), "AnotherSampleDir", "SampleSqlFile.py")
sample_perl_script = os.path.join(os.path.dirname(__file__), "AnotherSampleDir", "SamplePerlScript.pl")

def _start_subprocess(*command_args):
    exec_list = command_args
    proc_open = subprocess.Popen(exec_list, shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, bufsize=0)
    print("Started process:", exec_list, "pid=", proc_open.pid)
    return proc_open


class ProcessMemorySqlQueryTest(unittest.TestCase):
    """This searches with regular expressions in the memory of a running process.
    It does not need a Survol agent"""

    # This searches the content of a process memory which contains a SQL memory.
    @unittest.skip("TODO: Not working now")
    def test_from_batch(self):
        proc_open = _start_subprocess(sample_batch_script)

        (child_stdin, child_stdout_and_stderr) = (proc_open.stdin, proc_open.stdout)

        mySourceSqlQueries = lib_client.SourceLocal(
            "sources_types/CIM_Process/memory_regex_search/scan_sql_queries.py",
            "CIM_Process",
            Handle=procOpen.pid)

        tripleSqlQueries = mySourceSqlQueries.get_triplestore()
        print(len(tripleSqlQueries))
        #self.assertEqual(len(tripleSqlQueries.m_triplestore), 190)

        lstMatches = list(tripleSqlQueries.get_instances())
        print("Matches:",lstMatches)
        #self.assertEqual(len(lstMatches), 5)

        # Any string will do.
        child_stdin.write("Stop")

        print(lstMatches)
        proc_open.communicate()

    # This searches the content of a process memory which contains a SQL memory.
    @unittest.skipIf(is_travis_machine(), "TODO: Fix this on Travis")
    def test_from_python(self):
        # Runs this process: It allocates a variable containing a SQL query, then it waits.
        proc_open = _start_subprocess(sys.executable, sample_python_script)

        my_source_sql_queries = lib_client.SourceLocal(
            "sources_types/CIM_Process/memory_regex_search/scan_sql_queries.py",
            "CIM_Process",
            Handle=proc_open.pid)

        triple_sql_queries = my_source_sql_queries.get_triplestore()
        print("len(triple_sql_queries)=", len(triple_sql_queries))

        # This creates objects like:
        # "CIM_Process/embedded_sql_query.Query=SW5zZXJ0IGFuIGVudHJ5IGludG8gdGhlIGxpc3Qgb2Ygd2FybmluZ3MgZmlsdGVycyAoYXQgdGhlIGZyb250KS4=,Handle=15564"
        # Maybe, this is not the best representation. Possibly have a generic query ? Some inheritance ?
        # The specific detail about this query, is that it depends on the process.
        # This test focus on the parsing of memory, not on the queries representation.

        queries_set = set()
        for one_instance in triple_sql_queries.get_instances():
            if type(one_instance).__name__ == 'CIM_Process/embedded_sql_query':
                self.assertEqual(one_instance.Handle, str(proc_open.pid))
                decoded_query = lib_util.Base64Decode(one_instance.Query)
                queries_set.add(decoded_query)

        print("queries_set=", queries_set)
        self.assertTrue("select something from somewhere" in queries_set)
        self.assertTrue("select * from 'AnyTable'" in queries_set)
        self.assertTrue("select a,b,c from 'AnyTable'" in queries_set)
        self.assertTrue("select A.x,B.y from AnyTable A, OtherTable B" in queries_set)

        proc_open.communicate()

    # This searches the content of a process memory which contains a SQL memory.
    @unittest.skipIf(not _perl_path, "Perl must be installed.")
    @unittest.skipIf(is_travis_machine(), "TODO: Fix this on Travis")
    def test_from_perl(self):
        proc_open = _start_subprocess(_perl_path, sample_perl_script)

        my_source_sql_queries = lib_client.SourceLocal(
            "sources_types/CIM_Process/memory_regex_search/scan_sql_queries.py",
            "CIM_Process",
            Handle=proc_open.pid)

        triple_sql_queries = my_source_sql_queries.get_triplestore()

        queries_set = set()
        for one_instance in triple_sql_queries.get_instances():
            if type(one_instance).__name__ == 'CIM_Process/embedded_sql_query':
                self.assertEqual(one_instance.Handle, str(proc_open.pid))
                decoded_query = lib_util.Base64Decode(one_instance.Query)
                queries_set.add(decoded_query)

        print("queries_set=", queries_set)

        self.assertTrue("select column_a from table_a" in queries_set)
        self.assertTrue("select column_b from table_b" in queries_set)

        proc_open.communicate()


@unittest.skipIf(is_platform_linux, "No COM classes on Linux")
@unittest.skipIf(is_travis_machine(), "TODO: Not working on Travis yet")
class ProcessMemoryCOMClassesTest(unittest.TestCase):
    """This searches with regular expressions in the memory of a running process.
    It does not need a Survol agent"""

    # This searches COM classes ids in a process memory.
    @unittest.skipIf(is_travis_machine(), "TODO: Fix this on Travis")
    def test_from_python(self):
        proc_open = _start_subprocess(sys.executable, sample_python_script)

        my_source_com_classes = lib_client.SourceLocal(
            "sources_types/CIM_Process/memory_regex_search/search_com_classes.py",
            "CIM_Process",
            Handle=proc_open.pid)

        my_source_com_classes = my_source_com_classes.get_triplestore()
        print("len(my_source_com_classes)=", len(my_source_com_classes))

        proc_open.communicate()

    # This searches COM classes ids in a process memory.
    @unittest.skipIf(not _perl_path, "Perl must be installed.")
    def test_from_perl(self):
        proc_open = _start_subprocess(_perl_path, sample_perl_script)

        my_source_com_classes = lib_client.SourceLocal(
            "sources_types/CIM_Process/memory_regex_search/search_com_classes.py",
            "CIM_Process",
            Handle=proc_open.pid)

        triple_com_classes = my_source_com_classes.get_triplestore()
        print("len(triple_sql_queries)=", len(triple_com_classes))

        proc_open.communicate()


@unittest.skipIf(is_travis_machine(), "TODO: Not working on Travis yet")
class ProcessMemoryConnectionStringsTest(unittest.TestCase):
    """This searches with regular expressions in the mmemory of a running process.
    It does not need a Survol agent"""

    # This searches the content of a process memory which contains ODBC connection strings.
    def test_from_python(self):
        proc_open = _start_subprocess(sys.executable, sample_python_script)

        my_source_connection_strings = lib_client.SourceLocal(
            "sources_types/CIM_Process/memory_regex_search/search_connection_strings.py",
            "CIM_Process",
            Handle=proc_open.pid)

        triple_connection_strings = my_source_connection_strings.get_triplestore()
        print("len(triple_connection_strings_queries)=", len(triple_connection_strings))

        proc_open.communicate()

    # This searches the content of a process memory which contains ODBC connection strings.
    @unittest.skipIf(not _perl_path, "Perl must be installed.")
    def test_from_perl(self):
        proc_open = _start_subprocess(_perl_path, sample_perl_script)

        my_source_connection_strings = lib_client.SourceLocal(
            "sources_types/CIM_Process/memory_regex_search/search_connection_strings.py",
            "CIM_Process",
            Handle=proc_open.pid)

        triple_connection_strings = my_source_connection_strings.get_triplestore()
        print("len(triple_connection_strings_queries)=", len(triple_connection_strings))

        proc_open.communicate()


@unittest.skipIf(is_platform_linux, "No COM classes on Linux")
@unittest.skipIf(is_travis_machine(), "TODO: Not working on Travis yet")
class ProcessMemoryFilenamesTest(unittest.TestCase):
    """This searches with regular expressions in the memory of a running process.
    It does not need a Survol agent"""

    # This searches the content of a process memory which contains a SQL memory.
    def test_from_python(self):
        proc_open = _start_subprocess(sys.executable, sample_python_script)

        my_source_filenames = lib_client.SourceLocal(
            "sources_types/CIM_Process/memory_regex_search/search_filenames.py",
            "CIM_Process",
            Handle=proc_open.pid)

        triple_filenames = my_source_filenames.get_triplestore()

        filenames_set = set()
        for one_instance in triple_filenames.get_instances():
            if type(one_instance).__name__ == 'CIM_DataFile':
                filenames_set.add(one_instance.Name)

        for one_filename in sorted(filenames_set):
            print("    ", one_filename)

        # This filepath is calculated in the Python script
        filepath_a = os.path.join(os.path.dirname(sys.executable), "this_is_a_file_name_with_slashes.cpp").replace("\\", "/")
        self.assertTrue(filepath_a in filenames_set)

        self.assertTrue(windows_system32_cmd_exe.replace("\\", "/") in filenames_set)
        self.assertTrue(sys.executable.replace("\\", "/") in filenames_set)

        a, b = proc_open.communicate()
        print("ab=", a, b)

    # This searches the content of a process memory which contains a SQL memory.
    @unittest.skipIf(not _perl_path, "Perl must be installed.")
    def test_from_perl(self):
        proc_open = _start_subprocess(_perl_path, sample_perl_script)

        my_source_filenames = lib_client.SourceLocal(
            "sources_types/CIM_Process/memory_regex_search/search_filenames.py",
            "CIM_Process",
            Handle=proc_open.pid)

        sys.stdout.flush()

        triple_filenames = my_source_filenames.get_triplestore()
        print("len(triple_filenames)=", len(triple_filenames))
        filenames_set = set()
        for one_instance in triple_filenames.get_instances():
            if type(one_instance).__name__ == 'CIM_DataFile':
                filenames_set.add(one_instance.Name)

        for one_filename in sorted(filenames_set):
            print("    ", one_filename)

        self.assertTrue(_perl_path.replace("\\", "/") in filenames_set)
        self.assertTrue(windows_system32_cmd_exe.replace("\\", "/") in filenames_set)

        proc_open.communicate()


@unittest.skipIf(is_travis_machine(), "TODO: Not working on Travis yet")
class ProcessMemoryUrlsTest(unittest.TestCase):
    """This searches with regular expressions in the memory of a running process.
    It does not need a Survol agent"""

    # This searches the content of a process memory which contains a SQL memory.
    def test_from_python(self):
        proc_open = _start_subprocess(sys.executable, sample_python_script)

        my_source_urls = lib_client.SourceLocal(
            "sources_types/CIM_Process/memory_regex_search/search_urls.py",
            "CIM_Process",
            Handle=proc_open.pid)

        triple_urls = my_source_urls.get_triplestore()
        print("len(triple_urls)=", len(triple_urls))

        proc_open.communicate()

    # This searches URLs in a process memory.
    @unittest.skipIf(not _perl_path, "Perl must be installed.")
    def test_from_perl(self):
        proc_open = _start_subprocess(_perl_path, sample_perl_script)

        my_source_urls = lib_client.SourceLocal(
            "sources_types/CIM_Process/memory_regex_search/search_urls.py",
            "CIM_Process",
            Handle=proc_open.pid)

        triple_urls = my_source_urls.get_triplestore()
        print("len(triple_urls)=", len(triple_urls))

        proc_open.communicate()


if __name__ == '__main__':
    unittest.main()

