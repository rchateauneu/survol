#!/usr/bin/env python

"""The intention is to test the capability to search for specific strigns in the memory of a running process."""

from __future__ import print_function

import cgitb
import unittest
import subprocess
import sys
import os
import re
import time
import socket
import platform
import pkgutil

from init import *

# This loads the module from the source, so no need to install it, and no need of virtualenv.
update_test_path()

import lib_client
import lib_common
import lib_properties

isVerbose = ('-v' in sys.argv) or ('--verbose' in sys.argv)


class SurvolLocalMemoryRegexSearchTest(unittest.TestCase):
    """This searches with regular expressions in the mmeory of a running process.
    It does not need a Survol agent"""

    # This searches the content of a process memory which contains a SQL memory.
    def test_regex_sql_query_from_batch_process(self):
        print("test_regex_sql_query_from_batch_process: Broken")

        return

        try:
            if 'win' in sys.platform:
                import win32con
        except ImportError:
            print("Module win32con is not available so this test is not applicable")
            return

        sqlPathName = os.path.join( os.path.dirname(__file__), "AnotherSampleDir", "CommandExample.bat" )

        execList = [ sqlPathName ]

        # Runs this process: It allocates a variable containing a SQL query, then it waits.
        procOpen = subprocess.Popen(execList, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        print("Started process:",execList," pid=",procOpen.pid)

        (child_stdin, child_stdout_and_stderr) = (procOpen.stdin, procOpen.stdout)

        #print("child_stdout_and_stderr=",child_stdout_and_stderr.readline())

        mySourceSqlQueries = lib_client.SourceLocal(
            "sources_types/CIM_Process/memory_regex_search/scan_sql_queries.py",
            "CIM_Process",
            Handle=procOpen.pid)

        tripleSqlQueries = mySourceSqlQueries.get_triplestore()
        print(len(tripleSqlQueries))
        assert(len(tripleSqlQueries.m_triplestore)==190)

        lstMatches = list(tripleSqlQueries.get_instances("[Pp]ellentesque"))
        print("Matches:",lstMatches)
        assert( len(lstMatches) == 5 )

        # Any string will do.
        child_stdin.write("Stop")
        #procOpen.kill()
        #procOpen.communicate()
        #child_stdin.close()
        #child_stdout_and_stderr.close()

        print(lstMatches)

    # This searches the content of a process memory which contains a SQL memory.
    def test_regex_sql_query_from_python_process(self):
        print("test_regex_sql_query_from_python_process: Broken")
        return

        try:
            if 'win' in sys.platform:
                import win32con
        except ImportError:
            print("Module win32con is not available so this test is not applicable")
            return

        sqlPathName = os.path.join( os.path.dirname(__file__), "AnotherSampleDir", "SampleSqlFile.py" )

        execList = [ sys.executable, sqlPathName ]

        # Runs this process: It allocates a variable containing a SQL query, then it waits.
        procOpen = subprocess.Popen(execList, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)

        print("Started process:",execList," pid=",procOpen.pid)

        # Reading from procOpen.stdout is buffered and one cannot get data until trhe process leaves, or so.
        #print("child_stdout_and_stderr=",child_stdout_and_stderr.readline())

        mySourceSqlQueries = lib_client.SourceLocal(
            "sources_types/CIM_Process/memory_regex_search/scan_sql_queries.py",
            "CIM_Process",
            Handle=procOpen.pid)

        tripleSqlQueries = mySourceSqlQueries.get_triplestore()
        print("len(tripleSqlQueries)=",len(tripleSqlQueries))

        matchingTriples = list(tripleSqlQueries.get_all_strings_triples())
        print("mmm=",matchingTriples)

        (child_stdout_content, child_stderr_content) = procOpen.communicate()

    # This searches the content of a process memory which contains a SQL memory.
    def test_regex_sql_query_from_perl_process(self):
        print("test_regex_sql_query_from_perl_process: Broken")
        return

        sqlPathName = os.path.join( os.path.dirname(__file__), "AnotherSampleDir", "SamplePerlScript.pl" )

        execList = [ "perl", sqlPathName ]

        # Runs this process: It allocates a variable containing a SQL query, then it waits.
        procOpen = subprocess.Popen(execList, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)

        print("Started process:",execList," pid=",procOpen.pid)

        # Reading from procOpen.stdout is buffered and one cannot get data until trhe process leaves, or so.
        #print("child_stdout_and_stderr=",child_stdout_and_stderr.readline())

        mySourceSqlQueries = lib_client.SourceLocal(
            "sources_types/CIM_Process/memory_regex_search/scan_sql_queries.py",
            "CIM_Process",
            Handle=procOpen.pid)

        tripleSqlQueries = mySourceSqlQueries.get_triplestore()
        print("len(tripleSqlQueries)=",len(tripleSqlQueries))

        matchingTriples = list(tripleSqlQueries.get_all_strings_triples())
        print("mmm=",matchingTriples)

        (child_stdout_content, child_stderr_content) = procOpen.communicate()


#search_com_classes.py
#search_connection_strings.py
#search_filenames.py
#search_urls.py




# TODO: Test pydbg.    def load (self, path_to_file, command_line=None, create_new_console=False, show_window=True):

if __name__ == '__main__':
    unittest.main()

