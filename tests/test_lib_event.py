#!/usr/bin/env python

from __future__ import print_function

import os
import re
import sys
import string
import unittest

from init import *

# This loads the module from the source, so no need to install it, and no need of virtualenv.
update_test_path()

import lib_event

class LowLevelFunctionsTest(unittest.TestCase):
    """
    Test of low-level features of lib_event.
    """

    def test_string_to_filename(self):
        test_data_set = [
            ("", ""),
            ("abcd", "abcd"),
            (string.ascii_letters, string.ascii_letters),
            (string.digits, string.digits),
            ("a/bc\\d", "a_bc_d"),
            (",=_.()-", ",=_.()-"),
            ("*!\"%^&+[]", ""),
            ("{}@~#?><|;:", ""),
            (" ", "_"),
            ("\t", "_"),
            (" \t\r\n", "____"),
        ]
        for one_test_pair in test_data_set:
            actual_filename = lib_event._string_to_filename(one_test_pair[0])
            print(one_test_pair[0], "=>", actual_filename, "/", one_test_pair[1])
            self.assertTrue(actual_filename == one_test_pair[1])

    def test_moniker_to_event_filename(self):
        test_data_set = [
            (("CIM_Process", {"Handle":123}),
             "CIM_Process/CIM_Process.Handle=123"),
            (("CIM_DataFile", {"Name": "C:/Windows/Explorer.exe"}),
             "CIM_DataFile/CIM_DataFile.Name=C_Windows_Explorer.exe"),
        ]
        for json_moniker, expected_basename in test_data_set:
            expected_pathname = lib_event.events_directory + expected_basename + lib_event.events_file_extension
            actual_pathname = lib_event._moniker_to_event_filename(json_moniker)
            print(actual_pathname, "=>", expected_pathname, "/", json_moniker)
            self.assertTrue(actual_pathname == expected_pathname)

    def test_retrieve_all_events_empty(self):
        # Cleanup first.
        lib_event.retrieve_all_events()
        triples_list = lib_event.retrieve_all_events()
        self.assertTrue(triples_list == [])

    def test_put_retrieve_events(self):
        triples_data_set = [
            {
                "subject": ("CIM_Process", {"Handle":123}),
                "predicate": "priority",
                "object":255
            },
            {
                "subject": ("CIM_Process", {"Handle": 123}),
                "predicate": "user",
                "object": ("Win32_UserAccount", {"Name": "my_user", "Domain": "my_domain"}),
            },
            ]
        print("time=", time.time())
        files_updates_total_number = lib_event.store_events_triples_list(triples_data_set)
        print("time=", time.time())
        triples_list = lib_event.retrieve_all_events()
        print("time=", time.time())
        print("files_updates_total_number=", files_updates_total_number)
        print("len(triples_list)=", len(triples_list))
        for one_triple in triples_list:
            print("    one_triple=", one_triple)
        self.assertTrue(files_updates_total_number == 3)
        # When the subject and object of a triple are urls, this triple is stored twice.
        self.assertTrue(len(triples_list) == 3)

    def test_retrieve_events_by_entity(self):
        triples_data_set = [
            {
                "subject": ("CIM_Process", {"Handle":123}),
                "predicate": "priority",
                "object":255
            },
            {
                "subject": ("CIM_Process", {"Handle": 123}),
                "predicate": "user",
                "object": ("Win32_UserAccount", {"Name": "my_user", "Domain": "my_domain"}),
            },
            ]
        files_updates_total_number = lib_event.store_events_triples_list(triples_data_set)
        self.assertTrue(files_updates_total_number == 3)

        events_a = lib_event.retrieve_events_by_entity("CIM_Process", {"Handle":123})
        print("events_a=", events_a)
        # events_a= [(rdflib.term.URIRef(u'http://rchateau-hp:80/LocalExecution/entity.py?xid=CIM_Process.Handle=123'), rdflib.term.URIRef(u'h
        # ttp://www.primhillcomputers.com/survol#priority'), rdflib.term.Literal(u'255', datatype=rdflib.term.URIRef(u'http://www.w3.org/2001/
        # XMLSchema#integer'))), (rdflib.term.URIRef(u'http://rchateau-hp:80/LocalExecution/entity.py?xid=CIM_Process.Handle=123'), rdflib.ter
        # m.URIRef(u'http://www.primhillcomputers.com/survol#user'), rdflib.term.Literal(u"[u'Win32_UserAccount', {u'Domain': u'my_domain', u'
        # Name': u'my_user'}]"))]

        # Simple check of predicates, whcih should detect most of errors.
        predicates_only = sorted([str(one_triple[1]).rpartition('#')[-1] for one_triple in events_a])
        print("predicates_only=", predicates_only)
        self.assertTrue(predicates_only == ['priority', 'user'])

        events_b = lib_event.retrieve_events_by_entity("Win32_UserAccount", {"Name": "my_user", "Domain": "my_domain"})
        print("events_b=", events_b)
        # events_b= [(rdflib.term.URIRef(u'http://rchateau-hp:80/LocalExecution/entity.py?xid=CIM_Process.Handle=123'), rdflib.term.URIRef(u'h
        # ttp://www.primhillcomputers.com/survol#user'), rdflib.term.Literal(u"[u'Win32_UserAccount', {u'Domain': u'my_domain', u'Name': u'my_
        # user'}]"))]
        # Simple check of predicates, whcih should detect most of errors.
        predicates_only = sorted([str(one_triple[1]).rpartition('#')[-1] for one_triple in events_b])
        print("predicates_only=", predicates_only)
        self.assertTrue(predicates_only == ['user'])


if __name__ == '__main__':
    unittest.main()

