#!/usr/bin/env python

"""Test of various URL, the content is checked in RDF.
It could be done in another output format. The goal is to maximize the coverage."""

from __future__ import print_function

import os
import sys
import socket
import unittest
import rdflib
import io
import lib_util
import lib_properties
from lib_properties import pc

from init import *

_current_machine = socket.gethostname()


@unittest.skip("Not implemented yet")
@unittest.skipIf(not is_platform_windows, "Windows only")
class SqlServerLocalTest(unittest.TestCase):
    """These tests do not need a Survol agent"""

    def test_dsn_processes_json(self):
        """
        This tests the list of processes of a DSN.
        """
        my_source_file_stat_local = lib_client.SourceLocal(
            "sources_types/sqlserver/dsn/sqlserver_dsn_processes.py",
            "sqlserver/dsn",
            Dsn=always_present_file)
        the_content_json = my_source_file_stat_local.content_json()
        print("test_create_source_local_json: Json content=%s ..."%str(the_content_json)[:100])

    def test_dsn_queries_json(self):
        """
        This tests the queries of a Sql Server DSN.
        """
        my_source_file_stat_local = lib_client.SourceLocal(
            "sources_types/sqlserver/dsn/sqlserver_dsn_queries.py",
            "sqlserver/dsn",
            Dsn=always_present_file)
        the_content_json = my_source_file_stat_local.content_json()
        print("test_create_source_local_json: Json content=%s ..."%str(the_content_json)[:100])

    def test_dsn_sessions_json(self):
        """
        This tests the sessions of a Sql Server DSN.
        """
        my_source_file_stat_local = lib_client.SourceLocal(
            "sources_types/sqlserver/dsn/sqlserver_dsn_sessions.py",
            "sqlserver/dsn",
            Dsn=always_present_file)
        the_content_json = my_source_file_stat_local.content_json()
        print("test_create_source_local_json: Json content=%s ..."%str(the_content_json)[:100])

    def test_query_dependencies_json(self):
        """
        This tests the dependencies of a SqlServer query.
        """
        my_source_file_stat_local = lib_client.SourceLocal(
            "sources_types/sqlserver/query/sqlserver_query_dependencies.py",
            "sqlserver/query",
            Dsn=always_present_file,
            Query=always_present_file)
        the_content_json = my_source_file_stat_local.content_json()
        print("test_create_source_local_json: Json content=%s ..."%str(the_content_json)[:100])

    def test_session_informations_json(self):
        """
        This tests the display of information about a SQL session.
        """
        my_source_file_stat_local = lib_client.SourceLocal(
            "sources_types/sqlserver/session/sqlserver_session_informations.py",
            "sqlserver/session",
            Dsn=always_present_file,
            Query=always_present_file)
        the_content_json = my_source_file_stat_local.content_json()
        print("test_create_source_local_json: Json content=%s ..."%str(the_content_json)[:100])


if __name__ == '__main__':
    unittest.main()

