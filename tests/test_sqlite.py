#!/usr/bin/env python

from __future__ import print_function

"""This sqlite scripts."""

import cgitb
import unittest
import subprocess

import rdflib

from init import *

update_test_path()

import lib_util
import lib_client
import lib_kbase

# Otherwise, Python callstack would be displayed in HTML.
cgitb.enable(format="txt")


class SqliteTest(unittest.TestCase):
    """
    These tests use chinook SQLite sample database
    https://www.sqlitetutorial.net/sqlite-sample-database/
    """

    _chinook_db = os.path.join(os.path.dirname(__file__), "input_test_data", "chinook.db")

    def _get_column_names_from_graph(self, the_graph):
        table_class_node = lib_kbase.class_node_uriref("sqlite/table")
        table_nodes = [table_node
                       for table_node, _, _ in the_graph.triples((None, rdflib.namespace.RDF.type, table_class_node))]

        table_names = set(
            str(table_name)
            for table_name in [
                list(the_graph.triples((table_node, rdflib.namespace.RDFS.label, None)))[0][2]
                for table_node in table_nodes
            ]
        )
        return table_names

    def test_sqlite_tables_and_views(self):
        """
        This extracts the tables and views of a sqllite database.
        """
        my_source = lib_client.SourceLocal(
            "sources_types/sqlite/file/sqlite_tables_and_views.py",
            "sqlite/file",
            File=self._chinook_db)
        the_graph = my_source.get_graph()
        table_names = self._get_column_names_from_graph(the_graph)
        print("table_names=", table_names)
        self.assertEqual(
            table_names,
            {
                'playlist_track@chinook.db', 'invoices@chinook.db', 'customers@chinook.db', 'genres@chinook.db',
                'playlists@chinook.db', 'employees@chinook.db', 'albums@chinook.db', 'media_types@chinook.db',
                'sqlite_stat1@chinook.db', 'invoice_items@chinook.db', 'artists@chinook.db', 'tracks@chinook.db',
                'sqlite_sequence@chinook.db'
            }
        )

    def test_sqlite_table_fields(self):
        """
        This extracts the columns of a table in a sqlite database.
        """
        my_source = lib_client.SourceLocal(
            "sources_types/sqlite/table/sqlite_table_fields.py",
            "sqlite/table",
            File=self._chinook_db,
            Table="invoices")
        print("query=%s" % my_source.create_url_query())
        the_graph = my_source.get_graph()

        column_class_node = lib_kbase.class_node_uriref("sqlite/column")
        column_nodes = [column_node
                       for column_node, _, _ in the_graph.triples((None, rdflib.namespace.RDF.type, column_class_node))]

        column_names = set(
            str(column_name)
            for column_name in [
                list(the_graph.triples((column_node, rdflib.namespace.RDFS.label, None)))[0][2]
                for column_node in column_nodes
            ]
        )
        print("column_names=", column_names)
        self.assertEqual(
            column_names,
            {
                'invoices.BillingCity@chinook.db', 'invoices.BillingAddress@chinook.db',
                'invoices.BillingCountry@chinook.db', 'invoices.InvoiceId@chinook.db', 'invoices.Total@chinook.db',
                'invoices.BillingState@chinook.db', 'invoices.BillingPostalCode@chinook.db',
                'invoices.CustomerId@chinook.db', 'invoices.InvoiceDate@chinook.db'
            }
        )

    def test_sqlite_query_dependencies_simple_select(self):
        """
        This extracts the dependencies of a SQL query on a sqlite database.
        It also tests the correct encoding of a SQL query in a URL.
        """
        query_clear = "select * from invoices"
        my_source = lib_client.SourceLocal(
            "sources_types/sqlite/query/sqlite_query_dependencies.py",
            "sqlite/query",
            File=self._chinook_db,
            Query=query_clear)
        the_graph = my_source.get_graph()
        for one_triple in the_graph.triples((None, None, None)):
            print("    ", one_triple)
        table_names = self._get_column_names_from_graph(the_graph)
        print("table_names=", table_names)
        self.assertEqual(
            table_names,
            {'invoices@chinook.db'})

    def test_sqlite_query_dependencies_select_case_insensitive(self):
        """
        This extracts the dependencies of a SQL query on a sqlite database.
        The query must be case-insensitive.
        It also tests the correct encoding of a SQL query in a URL.
        """
        query_clear = "select * from Invoices, INVOICE_ITEMS where INVOICES.InvoiceId = Invoice_Items.InvoiceId"
        my_source = lib_client.SourceLocal(
            "sources_types/sqlite/query/sqlite_query_dependencies.py",
            "sqlite/query",
            File=self._chinook_db,
            Query=query_clear)
        the_graph = my_source.get_graph()
        table_names = self._get_column_names_from_graph(the_graph)
        print("table_names=", table_names)
        self.assertEqual(
            table_names,
            {'invoices@chinook.db', 'invoice_items@chinook.db'})

