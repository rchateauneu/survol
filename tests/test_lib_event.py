#!/usr/bin/env python

from __future__ import print_function

import os
#import re
import sys
import string
import unittest
import rdflib
import threading
import queue
import multiprocessing
import tempfile

from init import *

# This loads the module from the source, so no need to install it, and no need of virtualenv.
update_test_path()

import lib_event
import lib_kbase


class IndividualEventsTest(unittest.TestCase):
    """Very fast tests in memory. No multiprocessing, nor multithreading.
    Just testing data strctures."""
    def setUp(self):
        lib_kbase.set_storage_style("IOMemory",)

    def tearDown(self):
        lib_kbase.set_storage_style(None,)

    def test_pure_memory_retrieve_all_events_empty(self):
        """This reads all events twice, and the second time it should return nothing. """
        # To start with, this cleans all events.
        new_graph = lib_kbase.MakeGraph()
        lib_kbase.retrieve_all_events_to_graph_then_clear(new_graph)
        new_graph = lib_kbase.MakeGraph()
        lib_kbase.retrieve_all_events_to_graph_then_clear(new_graph)
        self.assertEqual(len(new_graph), 0)

    def test_pure_memory_put_retrieve_events(self):
        triples_data_set = [
            {
                "subject": ("CIM_Process", {"Handle": 123}),
                "predicate": "priority",
                "object": 255
            },
            {
                "subject": ("CIM_Process", {"Handle": 123}),
                "predicate": "user",
                "object": ("Win32_UserAccount", {"Name": "my_user", "Domain": "my_domain"}),
            },
            ]
        files_updates_total_number = lib_event.store_events_as_json_triples_list(triples_data_set)
        new_graph = lib_kbase.MakeGraph()
        lib_kbase.retrieve_all_events_to_graph_then_clear(new_graph)
        print("files_updates_total_number=", files_updates_total_number)
        print("len(triples_list)=", len(new_graph))
        #for one_triple in new_graph:
        #    print("    one_triple=", one_triple)
        self.assertEqual(files_updates_total_number, 2)
        # When the subject and object of a triple are urls, this triple is stored twice.
        self.assertEqual(len(new_graph), 2)

    def test_pure_memory_put_duplicate_retrieve_events(self):
        triples_count_a = 10
        triples_a = _create_dummy_graph(triples_count_a)
        triples_count_b = 20
        triples_b = _create_dummy_graph(triples_count_b)
        triples_count_c = 30
        triples_c = _create_dummy_graph(triples_count_c)

        returned_number_a = lib_kbase.write_graph_to_events(None, triples_a)
        self.assertEqual(returned_number_a, triples_count_a)
        returned_number_b = lib_kbase.write_graph_to_events(None, triples_b)
        self.assertEqual(returned_number_b, max(triples_count_a, triples_count_b))
        returned_number_c = lib_kbase.write_graph_to_events(None, triples_c)
        self.assertEqual(returned_number_c, max(triples_count_a, triples_count_b, triples_count_c))

    def test_pure_memory_insert_write_nourl_read_all_subprocess(self):
        triples_count = 100
        test_graph_input = _create_dummy_graph(triples_count)

        count_events = lib_kbase.write_graph_to_events(None, test_graph_input)
        self.assertEqual(count_events, triples_count)

        graph_whole_content = lib_kbase.MakeGraph()
        lib_kbase.retrieve_all_events_to_graph_then_clear(graph_whole_content)

        input_triples = _graph_to_triples_set(test_graph_input)
        output_triples = _graph_to_triples_set(graph_whole_content)

        # The two lists of triples must be identical: Comparison of the string representations.
        self.assertEqual(input_triples, output_triples)

    def test_pure_memory_write_two_urls_plus_none(self):

        graph_cleanup = lib_kbase.MakeGraph()
        lib_kbase.retrieve_all_events_to_graph_then_clear(graph_cleanup)

        triples_count_a = 10
        test_graph_input_a = _create_dummy_graph(triples_count_a)
        test_url_a = "http://dummy.xyz/url_a"
        count_events_url_a = lib_kbase.write_graph_to_events(test_url_a, test_graph_input_a)
        self.assertEqual(count_events_url_a, triples_count_a)
        actual_events_count_1 = lib_kbase.events_count()
        self.assertEqual(actual_events_count_1, triples_count_a)

        triples_count_b = 20
        test_graph_input_b = _create_dummy_graph(triples_count_b)
        test_url_b = "http://dummy.xyz/url_b"
        count_events_url_b = lib_kbase.write_graph_to_events(test_url_b, test_graph_input_b)
        self.assertEqual(count_events_url_b, max(triples_count_a, triples_count_b))
        actual_events_count_2 = lib_kbase.events_count()
        self.assertEqual(actual_events_count_2, count_events_url_b)

        triples_count_z = 100
        test_graph_input_z = _create_dummy_graph(triples_count_z)
        count_events_url_z = lib_kbase.write_graph_to_events(None, test_graph_input_z)
        self.assertEqual(count_events_url_z, max(triples_count_a, triples_count_b, triples_count_z))
        actual_events_count_3 = lib_kbase.events_count()
        self.assertEqual(count_events_url_z, count_events_url_z)

        test_graph_output_a = rdflib.Graph()
        count_events_output_a = lib_kbase.read_events_to_graph(test_url_a, test_graph_output_a)
        self.assertEqual(count_events_url_a, count_events_output_a)
        actual_events_count_3 = lib_kbase.events_count()
        self.assertEqual(actual_events_count_3, max(triples_count_b, triples_count_z))

        test_graph_output_b = rdflib.Graph()
        count_events_output_b = lib_kbase.read_events_to_graph(test_url_b, test_graph_output_b)
        self.assertEqual(count_events_url_b, count_events_output_b)
        actual_events_count_4 = lib_kbase.events_count()
        self.assertEqual(actual_events_count_4, triples_count_z)

        test_graph_output_z = rdflib.Graph()
        count_events_output_z = lib_kbase.retrieve_all_events_to_graph_then_clear(test_graph_output_z)
        self.assertEqual(count_events_url_z, count_events_output_z)
        actual_events_count_5 = lib_kbase.events_count()
        self.assertEqual(actual_events_count_5, 0)

    def test_pure_memory_write_read_write_read(self):
        graph_cleanup = lib_kbase.MakeGraph()
        lib_kbase.retrieve_all_events_to_graph_then_clear(graph_cleanup)

        triples_count_a = 100
        test_graph_input_a = _create_dummy_graph(triples_count_a)
        test_url_a = "http://dummy.xyz/url_a"
        count_events_url_a = lib_kbase.write_graph_to_events(test_url_a, test_graph_input_a)
        self.assertEqual(count_events_url_a, triples_count_a)
        actual_events_count_1 = lib_kbase.events_count()
        self.assertEqual(actual_events_count_1, triples_count_a)

        triples_count_b = 50
        test_graph_input_b = _create_dummy_graph(triples_count_b)
        test_url_b = "http://dummy.xyz/url_b"
        count_events_url_b = lib_kbase.write_graph_to_events(test_url_b, test_graph_input_b)
        self.assertEqual(count_events_url_b, triples_count_b)
        actual_events_count_2 = lib_kbase.events_count()
        self.assertEqual(actual_events_count_2, max(triples_count_a, triples_count_b))

        test_graph_output_a = rdflib.Graph()
        count_events_output_a = lib_kbase.read_events_to_graph(test_url_a, test_graph_output_a)
        self.assertEqual(count_events_url_a, count_events_output_a)
        actual_events_count_3 = lib_kbase.events_count()
        self.assertEqual(actual_events_count_3, triples_count_b)

        triples_count_z = 10
        test_graph_input_z = _create_dummy_graph(triples_count_z)
        count_events_url_z = lib_kbase.write_graph_to_events(None, test_graph_input_z)
        self.assertEqual(count_events_url_z, triples_count_z)
        actual_events_count_4 = lib_kbase.events_count()
        self.assertEqual(actual_events_count_4, max(triples_count_b, triples_count_z))

        test_graph_output_b = rdflib.Graph()
        count_events_output_b = lib_kbase.read_events_to_graph(test_url_b, test_graph_output_b)
        self.assertEqual(count_events_url_b, count_events_output_b)
        actual_events_count_5 = lib_kbase.events_count()
        self.assertEqual(actual_events_count_5, triples_count_z)

        test_graph_output_z = rdflib.Graph()
        count_events_output_z = lib_kbase.retrieve_all_events_to_graph_then_clear(test_graph_output_z)
        self.assertEqual(count_events_url_z, count_events_output_z)
        actual_events_count_6 = lib_kbase.events_count()
        self.assertEqual(actual_events_count_6, 0)


class EventsGraphTest(unittest.TestCase):

    def setUp(self):
        lib_kbase.set_storage_style("IOMemory",)

    def tearDown(self):
        lib_kbase.set_storage_style(None,)

    def test_write_graph_to_events(self):
        """Writes a RDF graph and its URL as a context."""
        test_graph_input = rdflib.Graph().parse("tests/input_test_data/test_events_tcp_sockets.xml")
        # The URL is not important because it is not accessed.
        # However, it must be correctly handled by rdflib when it creates a UriRef
        test_url = "http://vps516494.ovh.net/Survol/survol/sources_types/Linux/tcp_sockets.py?xid=."

        count_events = lib_kbase.write_graph_to_events(test_url, test_graph_input)
        self.assertEqual(count_events, 43)

    def test_write_read_graph_to_events_one(self):
        """Writes then reads a RDF graph and its URL as a context."""
        test_graph_input = rdflib.Graph().parse("tests/input_test_data/test_events_enumerate_CIM_Process.xml")

        test_url = "http://vps516494.ovh.net/Survol/survol/sources_types/enumerate_CIM_Process.py?xid=."

        count_events = lib_kbase.write_graph_to_events(test_url, test_graph_input)
        self.assertEqual(count_events, 682)

        test_graph_output = rdflib.Graph()
        count_events_output = lib_kbase.read_events_to_graph(test_url, test_graph_output)

        self.assertEqual(count_events, count_events_output)
        #self.assertEqual(test_graph_input, test_graph_output)

    def test_read_graph_to_events_twice(self):
        """Writes then reads twice a RDF graph and its URL as a context.
        The second time, it must be empty."""

        # This is the format="application/rdf+xml"
        test_graph_input = rdflib.Graph().parse("tests/input_test_data/test_events_enumerate_CIM_Process.xml")

        test_url = "http://vps516494.ovh.net/Survol/survol/sources_types/enumerate_CIM_Process.py?xid=."

        count_events = lib_kbase.write_graph_to_events(test_url, test_graph_input)
        self.assertEqual(count_events, 682)

        test_graph_output_1 = rdflib.Graph()
        count_events_output_1 = lib_kbase.read_events_to_graph(test_url, test_graph_output_1)

        self.assertEqual(count_events, count_events_output_1)

        test_graph_output_2 = rdflib.Graph()
        count_events_output_2 = lib_kbase.read_events_to_graph(test_url, test_graph_output_2)

        self.assertEqual(0, count_events_output_2)

    def test_write_read_graph_to_events_two(self):
        """This loads two different graphs corresponding to two different URLs.
        They must be properly reloaded. """
        test_graph_input_a = rdflib.Graph().parse("tests/input_test_data/test_events_enumerate_CIM_Process.xml")
        test_url_a = "http://vps516494.ovh.net/Survol/survol/sources_types/enumerate_CIM_Process.py?xid=."

        test_graph_input_b = rdflib.Graph().parse("tests/input_test_data/test_events_enumerate_python_package.xml")
        test_url_b = "http://vps516494.ovh.net/Survol/survol/sources_types/test_events_enumerate_python_package.py?xid=."

        count_events_a = lib_kbase.write_graph_to_events(test_url_a, test_graph_input_a)
        self.assertEqual(count_events_a, 682)

        count_events_b = lib_kbase.write_graph_to_events(test_url_b, test_graph_input_b)
        self.assertEqual(count_events_b, 1090)

        test_graph_output_a = rdflib.Graph()
        count_events_output_a = lib_kbase.read_events_to_graph(test_url_a, test_graph_output_a)
        self.assertEqual(count_events_a, count_events_output_a)

        test_graph_output_b = rdflib.Graph()
        count_events_output_b = lib_kbase.read_events_to_graph(test_url_b, test_graph_output_b)
        self.assertEqual(count_events_b, count_events_output_b)

    def test_write_read_graph_to_events_with_other_nodes(self):
        triples_data_set = [
            {
                "subject": ("CIM_Process", {"Handle": 123}),
                "predicate": "ParentProcessId",
                "object": 1
            },
            {
                "subject": ("CIM_Directory", {"Name": "/tmp"}),
                "predicate": "CIM_DirectoryContainsFile",
                "object": ("CIM_DataFile", {"Name": "/tmp/anyfile.tmp"})
            }
            ]

        updates_total_number = lib_event.store_events_as_json_triples_list(triples_data_set)

        test_graph_input = rdflib.Graph().parse("tests/input_test_data/test_events_enumerate_CIM_Process.xml")

        test_url = "http://vps516494.ovh.net/Survol/survol/sources_types/enumerate_CIM_Process.py?xid=."

        count_events = lib_kbase.write_graph_to_events(test_url, test_graph_input)
        self.assertEqual(count_events, 682)

        test_graph_output = rdflib.Graph()
        count_events_output = lib_kbase.read_events_to_graph(test_url, test_graph_output)
        self.assertEqual(count_events, count_events_output)

        new_graph = lib_kbase.MakeGraph()
        lib_kbase.retrieve_all_events_to_graph_then_clear(new_graph)
        print("files_updates_total_number=", updates_total_number)
        print("len(triples_list)=", len(new_graph))
        self.assertEqual(updates_total_number, 2)
        self.assertEqual(len(new_graph), 2)


def _graph_to_triples_set(input_graph):
    set_triples = set()
    for one_triple in input_graph:
        set_triples.add((
            str(one_triple[0]),
            str(one_triple[1]),
            str(one_triple[2])))
    return set_triples


def _read_triples_from_queue(count_events, shared_queue):
    output_list = []
    while len(output_list) < count_events:
        # Huge timeout because the rdf store might be delayed if a lot of data, which is acceptable.
        triple_message = shared_queue.get(timeout=20)
        output_list.append(triple_message)
    return output_list


def _read_all_events_from_graph(expected_triple_numbers, pqueue):
    """This function is used by EventsMultiprocessGraphTest.test_write_here_read_there to run
    a subprocess which reads events (triples) from the shared graph which contains all events.
    These triples are then returned with a shared queue, and the main process compares with the initial content."""

    grph = rdflib.Graph()

    num_triples = lib_kbase.retrieve_all_events_to_graph_then_clear(grph)

    if num_triples != expected_triple_numbers:
        # This is just an information, because a complete comparison is done later.
        sys.stderr.write("_read_all_events_from_graph Wrong number of events:%d %d\n" % (num_triples, expected_triple_numbers))

    for one_triple in grph:
        pqueue.put(one_triple)


def _create_thread(count_events, shared_queue):
    """This starts a thread which reads the events from the store where they are written."""
    print("About to start thread")
    created_thread = threading.Thread(
        target=_read_all_events_from_graph,
        args=(count_events, shared_queue))
    created_thread.start()
    return created_thread


def _connect_then_read_all_events_from_graph(expected_triple_numbers, pqueue, sqlite_path):
    lib_kbase.set_storage_style("SQLAlchemy", sqlite_path)
    _read_all_events_from_graph(expected_triple_numbers, pqueue)


def _create_subprocess(count_events, shared_queue, sqlite_path):
    """This starts a subprocess which reads the events from the store where they are written."""
    print("About to start process")
    created_process = multiprocessing.Process(
        target=_connect_then_read_all_events_from_graph,
        args=(count_events, shared_queue, sqlite_path))
    created_process.start()
    print("created_process=", created_process.pid)
    return created_process


def _create_dummy_graph(triples_count):
    """This creates test data of a given size."""
    test_graph_input = rdflib.Graph()
    for triples_index in range(triples_count):
        test_graph_input.add((
            rdflib.term.URIRef("subject:%d" % triples_index),
            rdflib.term.URIRef("predicate:%d" % triples_index),
            rdflib.term.URIRef("object:%d" % triples_index),
        ))
    return test_graph_input


def _create_temporary_filename():
    use_temporary_file = True

    if use_temporary_file:
        temporary_database_file = tempfile.NamedTemporaryFile(delete=False, suffix=".sqlite")
        database_path = temporary_database_file.name
        temporary_database_file.close()
    else:
        database_path = r"C:\Users\rchateau\survol_events.sqlite"
    return database_path


@unittest.skipIf(not pkgutil.find_loader('sqlalchemy'), "sqlalchemy cannot be imported.")
class EventsSQLAlchemyMemoryTest(unittest.TestCase):
    """All these tests assume that the global events graph is empty."""

    database_path = _create_temporary_filename()

    # database_path = "memdb1"
    # sqlite_path = "sqlite:///memdb1?mode=memory&cache=shared"
    sqlite_path = "sqlite:///%s?mode=memory&cache=shared" % database_path

    def setUp(self):
        """
        https://www.sqlite.org/inmemorydb.html
        The most common way to force an SQLite database to exist purely in memory is to open the database
        using the special filename ":memory:". In other words, instead of passing the name of a real disk file,
        pass in the string ":memory:".

        When this is done, no disk file is opened. Instead, a new database is created purely in memory.
        The database ceases to exist as soon as the database connection is closed.
        Every :memory: database is distinct from every other.
        So, opening two database connections each with the filename ":memory:"
        will create two independent in-memory databases.

        In-memory databases are allowed to use shared cache if they are opened using a URI filename.
        If the unadorned ":memory:" name is used to specify the in-memory database,
        then that database always has a private cache and is this only visible to the database connection
        that originally opened it.
        However, the same in-memory database can be opened by two or more database connections as follows:

        rc = sqlite3_open("file::memory:?cache=shared", &db);

        If two or more distinct but shareable in-memory databases are needed in a single process,
        then the mode=memory query parameter can be used with a URI filename to create a named in-memory database:

        rc = sqlite3_open("file:memdb1?mode=memory&cache=shared", &db);

        https://stackoverflow.com/questions/27910829/sqlalchemy-and-sqlite-shared-cache

        """
        lib_kbase.set_storage_style("SQLAlchemy", self.sqlite_path)

    def tearDown(self):
        lib_kbase.set_storage_style(None,)

    def test_sqlalchemy_memory_url_events_count(self):

        graph_cleanup = lib_kbase.MakeGraph()
        lib_kbase.retrieve_all_events_to_graph_then_clear(graph_cleanup)

        test_graph_input = rdflib.Graph().parse("tests/input_test_data/test_events_tcp_sockets.xml")

        test_url = "http://vps516494.ovh.net/Survol/survol/sources_types/Linux/tcp_sockets.py?xid=."

        count_events = lib_kbase.write_graph_to_events(test_url, test_graph_input)
        self.assertEqual(count_events, 43)
        actual_events_count = lib_kbase.events_count()
        self.assertEqual(count_events, actual_events_count)

        graph_from_sql_alchemy = lib_kbase.MakeGraph()
        lib_kbase.retrieve_all_events_to_graph_then_clear(graph_from_sql_alchemy)

        read_events_count = len(graph_from_sql_alchemy)
        self.assertEqual(read_events_count, actual_events_count)

    @unittest.skip("SQLite objects created in a thread can only be used in that same thread.")
    def test_sqlalchemy_memory_write_nourl_read_all_thread(self):
        """Writes into a RDF graph, then reads from a Python thread."""

        triples_count = 100
        test_graph_input = _create_dummy_graph(triples_count)

        count_events = lib_kbase.write_graph_to_events(None, test_graph_input)
        sys.stderr.write("test_sqlalchemy_write_nourl_read_all_thread count_events=%d\n" % count_events)
        self.assertEqual(count_events, triples_count)

        actual_events_count = lib_kbase.events_count()
        self.assertEqual(count_events, actual_events_count)

        # This shared queue is used by a thread reading the events, to send them back to this process.
        shared_queue = queue.Queue()

        created_thread = _create_thread(count_events, shared_queue)

        # Reads the triples sent by the thread.
        output_list = _read_triples_from_queue(count_events, shared_queue)

        # The thread is not needed any longer.
        created_thread.join()

        input_triples = _graph_to_triples_set(test_graph_input)
        output_triples = _graph_to_triples_set(output_list)

        # The two lists of triples must be identical: Comparison of the string representations.
        self.assertEqual(input_triples, output_triples)

    def test_sqlalchemy_memory_write_nourl_read_all_subprocess(self):
        triples_count = 1000
        test_graph_input = _create_dummy_graph(triples_count)

        count_events = lib_kbase.write_graph_to_events(None, test_graph_input)
        self.assertEqual(count_events, triples_count)

        # This shared queue is used by a subprocess reading the events, to send them back to this process.
        shared_queue = multiprocessing.Queue()

        created_process = _create_subprocess(count_events, shared_queue, self.sqlite_path)

        # Reads the triples sent by the subprocess.
        output_list = _read_triples_from_queue(count_events, shared_queue)

        # The subprocess is not needed any longer.
        created_process.terminate()
        created_process.join()
        print("Killing pid=", created_process.pid)

        input_triples = _graph_to_triples_set(test_graph_input)
        output_triples = _graph_to_triples_set(output_list)

        # The two lists of triples must be identical: Comparison of the string representations.
        self.assertEqual(input_triples, output_triples)


    def test_sqlalchemy_memory_write_two_urls(self):

        graph_cleanup = rdflib.Graph()
        lib_kbase.retrieve_all_events_to_graph_then_clear(graph_cleanup)

        triples_count_a = 10
        test_graph_input_a = _create_dummy_graph(triples_count_a)
        test_url_a = "http://dummy.xyz/url_a"
        count_events_url_a = lib_kbase.write_graph_to_events(test_url_a, test_graph_input_a)
        actual_events_count_1 = lib_kbase.events_count()
        self.assertEqual(actual_events_count_1, triples_count_a)

        triples_count_b = 20
        test_graph_input_b = _create_dummy_graph(triples_count_b)
        test_url_b = "http://dummy.xyz/url_b"
        count_events_url_b = lib_kbase.write_graph_to_events(test_url_b, test_graph_input_b)
        actual_events_count_2 = lib_kbase.events_count()
        self.assertEqual(actual_events_count_2, triples_count_a + triples_count_b)

        test_graph_output_b = rdflib.Graph()
        count_events_output_b = lib_kbase.read_events_to_graph(test_url_b, test_graph_output_b)
        self.assertEqual(count_events_url_b, count_events_output_b)
        actual_events_count_3 = lib_kbase.events_count()
        self.assertEqual(actual_events_count_3, triples_count_a)

        test_graph_output_a = rdflib.Graph()
        count_events_output_a = lib_kbase.read_events_to_graph(test_url_a, test_graph_output_a)
        self.assertEqual(count_events_url_a, count_events_output_a)
        actual_events_count_4 = lib_kbase.events_count()
        self.assertEqual(actual_events_count_4, 0)


@unittest.skipIf(not pkgutil.find_loader('sqlalchemy'), "sqlalchemy cannot be imported.")
class EventsSQLAlchemySqliteTest(unittest.TestCase):
    """IO based on sqlite and database files. Shared with threads and processes."""

    def setUp(self):
        self.database_path = _create_temporary_filename()

        self.sqlite_path = r"sqlite:///%s" % self.database_path
        lib_kbase.set_storage_style("SQLAlchemy", self.sqlite_path)

    def tearDown(self):
        lib_kbase.set_storage_style(None,)

        # This destroys the database file so all tests are completely isolated.
        # TODO: Does not work with multiprocessing.
        assert os.path.exists(self.database_path)
        os.unlink(self.database_path)
        assert not os.path.exists(self.database_path)

    def test_sqlalchemy_read_all_twice(self):
        """Just writes."""

        actual_events_count = lib_kbase.events_count()

        graph_from_sql_alchemy = lib_kbase.MakeGraph()
        lib_kbase.retrieve_all_events_to_graph_then_clear(graph_from_sql_alchemy)

        read_events_count = len(graph_from_sql_alchemy)
        self.assertEqual(read_events_count, actual_events_count)

        events_count_after_read = lib_kbase.events_count()
        self.assertEqual(events_count_after_read, 0)

        # Second read empties all.
        graph_from_sql_alchemy = lib_kbase.MakeGraph()
        lib_kbase.retrieve_all_events_to_graph_then_clear(graph_from_sql_alchemy)
        self.assertEqual(len(graph_from_sql_alchemy), 0)

    def test_sqlalchemy_nourl_events_count(self):
        """Just writes."""

        graph_cleanup = lib_kbase.MakeGraph()
        lib_kbase.retrieve_all_events_to_graph_then_clear(graph_cleanup)

        test_graph_input = rdflib.Graph().parse("tests/input_test_data/test_events_tcp_sockets.xml")

        count_events = lib_kbase.write_graph_to_events(None, test_graph_input)
        self.assertEqual(count_events, 43)
        actual_events_count = lib_kbase.events_count()
        self.assertEqual(count_events, actual_events_count)

        graph_from_sql_alchemy = lib_kbase.MakeGraph()
        lib_kbase.retrieve_all_events_to_graph_then_clear(graph_from_sql_alchemy)

        read_events_count = len(graph_from_sql_alchemy)
        self.assertEqual(read_events_count, actual_events_count)

    def test_sqlalchemy_url_events_count(self):

        graph_cleanup = lib_kbase.MakeGraph()
        lib_kbase.retrieve_all_events_to_graph_then_clear(graph_cleanup)

        test_graph_input = rdflib.Graph().parse("tests/input_test_data/test_events_tcp_sockets.xml")

        test_url = "http://vps516494.ovh.net/Survol/survol/sources_types/Linux/tcp_sockets.py?xid=."

        count_events = lib_kbase.write_graph_to_events(test_url, test_graph_input)
        self.assertEqual(count_events, 43)
        actual_events_count = lib_kbase.events_count()
        self.assertEqual(count_events, actual_events_count)

        graph_from_sql_alchemy = lib_kbase.MakeGraph()
        lib_kbase.retrieve_all_events_to_graph_then_clear(graph_from_sql_alchemy)

        read_events_count = len(graph_from_sql_alchemy)
        self.assertEqual(read_events_count, actual_events_count)

    def test_sqlalchemy_write_twice_nourl_events_count(self):
        """Writes with no url then reads all."""

        test_graph_input = rdflib.Graph().parse("tests/input_test_data/test_events_tcp_sockets.xml")

        count_events = lib_kbase.write_graph_to_events(None, test_graph_input)
        self.assertEqual(count_events, 43)
        actual_events_count = lib_kbase.events_count()
        self.assertEqual(count_events, actual_events_count)

        count_events = lib_kbase.write_graph_to_events(None, test_graph_input)
        self.assertEqual(count_events, 43)
        actual_events_count = lib_kbase.events_count()
        # TODO: BEWARE, WHY 63 WITH IN-MEMORY SQLITE ??
        self.assertEqual(63, actual_events_count)

        graph_from_sql_alchemy_again = lib_kbase.MakeGraph()
        lib_kbase.retrieve_all_events_to_graph_then_clear(graph_from_sql_alchemy_again)

        read_events_count = len(graph_from_sql_alchemy_again)
        print("read_events_count=", read_events_count)
        self.assertEqual(read_events_count, 43)

        actual_events_count_again = lib_kbase.events_count()
        self.assertEqual(0, actual_events_count_again)

    def test_sqlalchemy_write_url_read_all_only(self):
        """Writes for an URL then reads all."""

        test_graph_input = rdflib.Graph().parse("tests/input_test_data/test_events_tcp_sockets.xml")

        # The URL is not important because it is not accessed.
        # However, it must be correctly handled by rdflib when it creates a UriRef
        test_url = "http://vps516494.ovh.net/Survol/survol/sources_types/Linux/tcp_sockets.py?xid=."

        count_events = lib_kbase.write_graph_to_events(test_url, test_graph_input)
        self.assertEqual(count_events, 43)

        graph_from_sql_alchemy = lib_kbase.MakeGraph()
        lib_kbase.retrieve_all_events_to_graph_then_clear(graph_from_sql_alchemy)
        self.assertEqual(count_events, len(graph_from_sql_alchemy))

    def test_sqlalchemy_write_nourl_read_all_thread(self):
        """Writes into a RDF graph, then reads from a Python thread."""

        triples_count = 1000
        test_graph_input = _create_dummy_graph(triples_count)

        count_events = lib_kbase.write_graph_to_events(None, test_graph_input)
        sys.stderr.write("test_sqlalchemy_write_nourl_read_all_thread count_events=%d\n" % count_events)
        self.assertEqual(count_events, triples_count)

        actual_events_count = lib_kbase.events_count()
        self.assertEqual(count_events, actual_events_count)

        # This shared queue is used by a thread reading the events, to send them back to this process.
        shared_queue = queue.Queue()

        created_thread = _create_thread(count_events, shared_queue)

        # Reads the triples sent by the thread.
        output_list = _read_triples_from_queue(count_events, shared_queue)

        # The thread is not needed any longer.
        created_thread.join()

        input_triples = _graph_to_triples_set(test_graph_input)
        output_triples = _graph_to_triples_set(output_list)

        # The two lists of triples must be identical: Comparison of the string representations.
        self.assertEqual(input_triples, output_triples)

    def test_sqlalchemy_write_url_read_all_thread(self):
        """Writes a RDF graph, then reads from a Python thread."""

        test_graph_input = rdflib.Graph().parse("tests/input_test_data/test_events_tcp_sockets.xml")

        # The URL is not important because it is not accessed.
        # However, it must be correctly handled by rdflib when it creates a UriRef
        test_url = "http://vps516494.ovh.net/Survol/survol/sources_types/Linux/tcp_sockets.py?xid=."

        count_events = lib_kbase.write_graph_to_events(test_url, test_graph_input)
        self.assertEqual(count_events, 43)

        actual_events_count = lib_kbase.events_count()
        self.assertEqual(count_events, actual_events_count)

        sys.stderr.write("WRITE lib_kbase.events_count()=%s\n" % lib_kbase.events_count())

        # This shared queue is used by a thread reading the events, to send them back to this process.
        shared_queue = queue.Queue()

        created_thread = _create_thread(count_events, shared_queue)

        # Reads the triples sent by the thread.
        output_list = _read_triples_from_queue(count_events, shared_queue)

        # The thread is not needed any longer.
        created_thread.join()

        input_triples = _graph_to_triples_set(test_graph_input)
        output_triples = _graph_to_triples_set(output_list)

        # The two lists of triples must be identical: Comparison of the string representations.
        self.assertEqual(input_triples, output_triples)

    def test_sqlalchemy_write_nourl_read_all_subprocess(self):
        triples_count = 1000
        test_graph_input = _create_dummy_graph(triples_count)

        count_events = lib_kbase.write_graph_to_events(None, test_graph_input)
        self.assertEqual(count_events, triples_count)

        # This shared queue is used by a subprocess reading the events, to send them back to this process.
        shared_queue = multiprocessing.Queue()

        created_process = _create_subprocess(count_events, shared_queue, self.sqlite_path)

        # Reads the triples sent by the subprocess.
        output_list = _read_triples_from_queue(count_events, shared_queue)

        # The subprocess is not needed any longer.
        created_process.terminate()
        created_process.join()
        print("Killing pid=", created_process.pid)

        input_triples = _graph_to_triples_set(test_graph_input)
        output_triples = _graph_to_triples_set(output_list)

        # The two lists of triples must be identical: Comparison of the string representations.
        self.assertEqual(input_triples, output_triples)

    def test_sqlalchemy_write_url_read_all_subprocess(self):
        """Writes a RDF graph, then reads from another process."""

        graph_cleanup = lib_kbase.MakeGraph()
        lib_kbase.retrieve_all_events_to_graph_then_clear(graph_cleanup)

        test_graph_input = rdflib.Graph().parse("tests/input_test_data/test_events_tcp_sockets.xml")

        # The URL is not important because it is not accessed.
        # However, it must be correctly handled by rdflib when it creates a UriRef
        test_url = "http://vps516494.ovh.net/Survol/survol/sources_types/Linux/tcp_sockets.py?xid=."

        count_events = lib_kbase.write_graph_to_events(test_url, test_graph_input)
        self.assertEqual(count_events, 43)

        # This shared queue is used by a subprocess reading the events, to send them back to this process.
        shared_queue = multiprocessing.Queue()

        created_process = _create_subprocess(count_events, shared_queue, self.sqlite_path)

        # Reads the triples sent by the subprocess.
        output_list = _read_triples_from_queue(count_events, shared_queue)

        # The subprocess is not needed any longer.
        created_process.terminate()
        created_process.join()
        print("Killing pid=", created_process.pid)

        input_triples = _graph_to_triples_set(test_graph_input)
        output_triples = _graph_to_triples_set(output_list)

        # The two lists of triples must be identical: Comparison of the string representations.
        self.assertEqual(input_triples, output_triples)

    def test_sqlalchemy_sqlite_write_mixed_read_all_subprocess(self):
        """Writes a RDF graph, then reads from another process."""

        graph_cleanup = lib_kbase.MakeGraph()
        lib_kbase.retrieve_all_events_to_graph_then_clear(graph_cleanup)

        triples_count = 1000
        test_graph_input_nourl = _create_dummy_graph(triples_count)
        count_events_nourl = lib_kbase.write_graph_to_events(None, test_graph_input_nourl)

        test_graph_input_url = rdflib.Graph().parse("tests/input_test_data/test_events_tcp_sockets.xml")

        # The URL is not important because it is not accessed.
        # However, it must be correctly handled by rdflib when it creates a UriRef
        test_url = "http://vps516494.ovh.net/Survol/survol/sources_types/Linux/tcp_sockets.py?xid=."
        count_events_url = lib_kbase.write_graph_to_events(test_url, test_graph_input_url)

        count_events = count_events_nourl + count_events_url

        # This shared queue is used by a subprocess reading the events, to send them back to this process.
        shared_queue = multiprocessing.Queue()

        created_process = _create_subprocess(count_events, shared_queue, self.sqlite_path)

        # Reads the triples sent by the subprocess.
        output_list = _read_triples_from_queue(count_events, shared_queue)

        # The subprocess is not needed any longer.
        created_process.terminate()
        created_process.join()
        print("Killing pid=", created_process.pid)

        input_triples_nourl = _graph_to_triples_set(test_graph_input_nourl)
        input_triples_url = _graph_to_triples_set(test_graph_input_url)
        input_triples = input_triples_nourl | input_triples_url
        output_triples = _graph_to_triples_set(output_list)

        # The two lists of triples must be identical: Comparison of the string representations.
        self.assertEqual(input_triples, output_triples)

    def test_sqlalchemy_sqlite_write_nourl_read_all_subprocess(self):
        triples_count = 1000
        test_graph_input = _create_dummy_graph(triples_count)

        count_events = lib_kbase.write_graph_to_events(None, test_graph_input)
        self.assertEqual(count_events, triples_count)

        # This shared queue is used by a subprocess reading the events, to send them back to this process.
        shared_queue = multiprocessing.Queue()

        created_process = _create_subprocess(count_events, shared_queue, self.sqlite_path)

        # Reads the triples sent by the subprocess.
        output_list = _read_triples_from_queue(count_events, shared_queue)

        # The subprocess is not needed any longer.
        created_process.terminate()
        created_process.join()
        print("Killing pid=", created_process.pid)

        input_triples = _graph_to_triples_set(test_graph_input)
        output_triples = _graph_to_triples_set(output_list)

        # The two lists of triples must be identical: Comparison of the string representations.
        self.assertEqual(input_triples, output_triples)

    def test_sqlalchemy_sqlite_write_two_urls(self):

        graph_cleanup = lib_kbase.MakeGraph()
        lib_kbase.retrieve_all_events_to_graph_then_clear(graph_cleanup)

        triples_count_a = 1000
        test_graph_input_a = _create_dummy_graph(triples_count_a)
        test_url_a = "http://dummy.xyz/url_a"
        count_events_url_a = lib_kbase.write_graph_to_events(test_url_a, test_graph_input_a)
        actual_events_count_1 = lib_kbase.events_count()
        self.assertEqual(actual_events_count_1, triples_count_a)

        triples_count_b = 2000
        test_graph_input_b = _create_dummy_graph(triples_count_b)
        test_url_b = "http://dummy.xyz/url_b"
        count_events_url_b = lib_kbase.write_graph_to_events(test_url_b, test_graph_input_b)
        actual_events_count_2 = lib_kbase.events_count()
        self.assertEqual(actual_events_count_2, triples_count_a + triples_count_b)

        test_graph_output_a = rdflib.Graph()
        count_events_output_a = lib_kbase.read_events_to_graph(test_url_a, test_graph_output_a)
        self.assertEqual(count_events_url_a, count_events_output_a)
        actual_events_count_3 = lib_kbase.events_count()
        self.assertEqual(actual_events_count_3, triples_count_b)

        test_graph_output_b = rdflib.Graph()
        count_events_output_b = lib_kbase.read_events_to_graph(test_url_b, test_graph_output_b)
        self.assertEqual(count_events_url_b, count_events_output_b)
        actual_events_count_4 = lib_kbase.events_count()
        self.assertEqual(actual_events_count_4, 0)



if __name__ == '__main__':
    unittest.main()

