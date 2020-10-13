#!/usr/bin/env python

"""Tests the ability to detect repetieion in sequences of symbols.
This is designed for sequences of system calls.
"""

from __future__ import print_function

__author__      = "Remi Chateauneu"
__copyright__   = "Copyright 2020, Primhill Computers"
__license__ = "GPL"

import unittest

from init import *

from survol import lib_naming_conventions

_sfp = lib_naming_conventions.standardized_file_path

@unittest.skipIf(is_platform_linux, "Windows.")
class StandardizedFilePathWindowsTest(unittest.TestCase):

    # os.path._getfinalpathname("c:/python27/python.exe") => '\\\\?\\C:\\Python27\\python.exe'
    # os.path._getfinalpathname("c:/python27/python.exe").lstrip(r'\?') => 'C:\\Python27\\python.exe'

    @unittest.skipIf(is_py3, "Windows py2 test.")
    def test_filenames_windows_py2(self):
        self.assertEqual(_sfp("c:/uSeRs"), "C:/Users")

    @unittest.skipIf(not is_py3, "Windows py3 test.")
    def test_filenames_windows_py3(self):
        self.assertEqual(_sfp("c:/uSeRs"), "C:/Users")

    def test_filenames_relative_to_absolute(self):
        self.assertEqual(_sfp("SampleDirSymbolicLinks"), "SampleDirSymbolicLinks")


@unittest.skipIf(is_platform_windows, "Linux.")
class StandardizedFilePathLinuxTest(unittest.TestCase):

    def test_filenames_linux_existent(self):
        self.assertEqual(_sfp("/tmp"), "/tmp")

    def test_filenames_linux_non_existent(self):
        self.assertEqual(_sfp("/this_does_not_exist"), "/this_does_not_exist")

    def test_filenames_linux_symlinks(self):
        self.assertEqual(_sfp("SampleDirSymbolicLinks"), "/SampleDirSymbolicLinks")
        self.assertEqual(_sfp("SampleDirSymbolicLinks/symlink_to_physical_file"), "/tmp")
        self.assertEqual(_sfp("SampleDirSymbolicLinks/symlink_to_physical_directory"), "/tmp")



