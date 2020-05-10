#!/usr/bin/env python

from __future__ import print_function

import os
import re
import sys
import string
import unittest

from init import *

import lib_event

class DockitComponentsTest(unittest.TestCase):
    """
    Test parsing of strace output.
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
            ({"entity_type":"CIM_Process", "Handle":123},
             "CIM_Process/CIM_Process.Handle=123"),
            ({"entity_type": "CIM_DataFile", "Name": "C:/Windows/Explorer.exe"},
             "CIM_DataFile/CIM_DataFile.Name=C_Windows_Explorer.exe"),
        ]
        for json_moniker, expected_basename in test_data_set:
            expected_pathname = lib_event.events_directory + expected_basename + ".events"
            actual_pathname = lib_event._moniker_to_event_filename(json_moniker)
            print(actual_pathname, "=>", expected_pathname, "/", json_moniker)
            self.assertTrue(actual_pathname == expected_pathname)


if __name__ == '__main__':
    unittest.main()

