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
            (" \t\r\n", "____"),
            (",=_.()-", ",=_.()-"),
            ("*!\"%^&+[]", "*!\"%^&+[]"),
            ("{}@~#?><|;:", "{}@~#?><|;:"),
        ]
        for one_test_pair in test_data_set:
            actual_filename = lib_event._string_to_filename(one_test_pair[0])
            print(one_test_pair[0], "=>", actual_filename, "/", one_test_pair[1])
            self.assertTrue(actual_filename == one_test_pair[1])


if __name__ == '__main__':
    unittest.main()

