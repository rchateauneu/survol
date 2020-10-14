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
        # /home/travis/build/rchateauneu/survol/SampleDirSymbolicLinks
        symlinks_dir = "SampleDirSymbolicLinks"
        root_directory = os.path.join(os.path.dirname(__file__), symlinks_dir)

        # This checks the current directory, otherwise the test cannot work.
        relative_symlinks_dir = os.path.join("tests", "SampleDirSymbolicLinks")
        expected_root = os.path.join(os.getcwd(), relative_symlinks_dir)

        self.assertEqual(root_directory, expected_root)

        self.assertEqual(
            _sfp(relative_symlinks_dir),
            root_directory)
        self.assertEqual(
            _sfp("%s/symlink_to_physical_file" % relative_symlinks_dir),
            os.path.join(root_directory, "physical_file.dat"))
        self.assertEqual(
            _sfp("%s/symlink_to_physical_directory" % relative_symlinks_dir),
            os.path.join(root_directory, "physical_directory.dir"))
        self.assertEqual(
            _sfp("%s/symlink_to_subphysical_file" % relative_symlinks_dir),
            os.path.join(root_directory, "physical_directory.dir", "physical_subfile.dat"))
        self.assertEqual(
            _sfp("%s/physical_directory.dir/physical_subfile.dat" % relative_symlinks_dir),
            os.path.join(root_directory, "physical_directory.dir", "physical_subfile.dat"))



