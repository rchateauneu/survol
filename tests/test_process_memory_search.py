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


class ProcessMemoryTest(unittest.TestCase):
    """This searches with regular expressions in the mmeory of a running process.
    It does not need a Survol agent"""

    # This searches the content of a process memory which contains a SQL memory.
    @unittest.skip("TODO: Not working now")
    def test_regex_sql_query_from_batch(self):
        sqlPathName = os.path.join( os.path.dirname(__file__), "AnotherSampleDir", "CommandExample.bat" )

        execList = [sqlPathName]

        procOpen = subprocess.Popen(execList, shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        print("Started process:",execList," pid=",procOpen.pid)

        (child_stdin, child_stdout_and_stderr) = (procOpen.stdin, procOpen.stdout)

        #print("child_stdout_and_stderr=",child_stdout_and_stderr.readline())

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

    # This searches the content of a process memory which contains a SQL memory.
    @unittest.skipIf(is_platform_linux, "TODO: Fix this on Linux")
    @unittest.skipIf(is_travis_machine(), "TODO: Fix this on Travis")
    def test_regex_sql_query_from_python(self):
        sql_path_name = os.path.join( os.path.dirname(__file__), "AnotherSampleDir", "SampleSqlFile.py" )

        exec_list = [sys.executable, sql_path_name]

        # Runs this process: It allocates a variable containing a SQL query, then it waits.
        proc_open = subprocess.Popen(exec_list, shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)

        print("Started process:", exec_list, "pid=", proc_open.pid)

        mySourceSqlQueries = lib_client.SourceLocal(
            "sources_types/CIM_Process/memory_regex_search/scan_sql_queries.py",
            "CIM_Process",
            Handle=proc_open.pid)

        triple_sql_queries = mySourceSqlQueries.get_triplestore()
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
    @unittest.skipIf(not check_program_exists("perl"), "Perl must be installed.")
    @unittest.skipIf(is_platform_linux, "TODO: Fix this on Linux")
    @unittest.skipIf(is_travis_machine(), "TODO: Fix this on Travis")
    def test_regex_sql_query_from_perl(self):
        sql_path_name = os.path.join(os.path.dirname(__file__), "AnotherSampleDir", "SamplePerlScript.pl")

        # For example r"C:\Perl64\bin\perl.exe" on Windows.
        perl_path = check_program_exists("perl")
        exec_list = [perl_path.decode(), sql_path_name]

        # Runs this process: It allocates a variable containing a SQL query, then it waits.
        proc_open = subprocess.Popen(exec_list, shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)

        print("Started process:", exec_list," pid=", proc_open.pid)

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

# TODO:
#search_com_classes.py
#search_connection_strings.py
#search_filenames.py
#search_urls.py




# TODO: Test pydbg.    def load (self, path_to_file, command_line=None, create_new_console=False, show_window=True):

if __name__ == '__main__':
    unittest.main()

