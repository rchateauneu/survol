#!/usr/bin/env python

from __future__ import print_function

import unittest
import sys
import os
import re

from init import *

# This loads the module from the source, so no need to install it, and no need of virtualenv.
update_test_path()

import lib_util


class SurvolLibUtilTest(unittest.TestCase):

    def test_parse_xid_trivial(self):
        entity_type, entity_id, entity_host = lib_util.ParseXid("")
        self.assertEqual(entity_type, "")
        self.assertEqual(entity_id, "")
        self.assertEqual(entity_host, "")

    def test_parse_xid_local(self):
        entity_type, entity_id, entity_host = lib_util.ParseXid("CIM_ComputerSystem.Name=Unknown-30-b5-c2-02-0c-b5-2")
        self.assertEqual(entity_type, "CIM_ComputerSystem")
        self.assertEqual(entity_id, "Name=Unknown-30-b5-c2-02-0c-b5-2")
        self.assertEqual(entity_host, "")

        entity_type, entity_id, entity_host = lib_util.ParseXid("oracle/table.Name=MY_TABLE")
        self.assertEqual(entity_type, "oracle/table")
        self.assertEqual(entity_id, "Name=MY_TABLE")
        self.assertEqual(entity_host, "")

        entity_type, entity_id, entity_host = lib_util.ParseXid(
            "CIM_DataFile.Name=anyfile.txt")
        self.assertEqual(entity_type, "CIM_DataFile")
        self.assertEqual(entity_id, "Name=anyfile.txt")
        self.assertEqual(entity_host, "")

        entity_type, entity_id, entity_host = lib_util.ParseXid(
            "CIM_DataFile.Name=C%3A%2F%2FUsers%2Fxyz%2FLes%20Ringards%20-%20Aldo%252C%20Mireille%252C%20Julien.txt")
        self.assertEqual(entity_type, "CIM_DataFile")
        self.assertEqual(entity_id, "Name=C://Users/xyz/Les Ringards - Aldo%2C Mireille%2C Julien.txt")
        self.assertEqual(entity_host, "")

        entity_type, entity_id, entity_host = lib_util.ParseXid(
            "CIM_DummyClass.Name=C%3A%2F%2FUsers%2Fxyz%2FLes%20Ringards%20-%20Aldo%252C%20Mireille%252C%20Julien.txt"
            + ",OtherArg=Something")
        self.assertEqual(entity_type, "CIM_DummyClass")
        self.assertEqual(entity_id, "Name=C://Users/xyz/Les Ringards - Aldo%2C Mireille%2C Julien.txt,OtherArg=Something")
        self.assertEqual(entity_host, "")

    def test_parse_xid_wmi(self):
        entity_type, entity_id, entity_host = lib_util.ParseXid(r"\\myhost-HP\root\CIMV2\Applications%3A.")
        self.assertEqual(entity_type, r"root\CIMV2\Applications:")
        self.assertEqual(entity_id, "")
        self.assertEqual(entity_host, "myhost-HP")

        entity_type, entity_id, entity_host = lib_util.ParseXid(r"\\myhost-HP\root\CIMV2%3AWin32_PerfFormattedData_Counters_IPHTTPSGlobal.")
        self.assertEqual(entity_type, r"root\CIMV2:Win32_PerfFormattedData_Counters_IPHTTPSGlobal")
        self.assertEqual(entity_id, "")
        self.assertEqual(entity_host, "myhost-HP")

        entity_type, entity_id, entity_host = lib_util.ParseXid(r"\\MYHOST-HP\root\CIMV2%3AWin32_PerfFormattedData_Counters_IPHTTPSGlobal.Name%3D%22Default%22")
        self.assertEqual(entity_type, r"root\CIMV2:Win32_PerfFormattedData_Counters_IPHTTPSGlobal")
        self.assertEqual(entity_id, 'Name="Default"')
        self.assertEqual(entity_host, "MYHOST-HP")

    def test_parse_xid_wbem(self):
        entity_type, entity_id, entity_host = lib_util.ParseXid("https://jdd:test@acme.com:5959/cimv2:Win32_SoftwareFeature.Name=\"Havana\",ProductName=\"Havana\",Version=\"1.0\"")
        self.assertEqual(entity_type, "cimv2:Win32_SoftwareFeature")
        self.assertEqual(entity_id, "Name=\"Havana\",ProductName=\"Havana\",Version=\"1.0\"")
        self.assertEqual(entity_host, "https://jdd:test@acme.com:5959")

        entity_type, entity_id, entity_host = lib_util.ParseXid("http://192.168.1.88:5988/root/PG_Internal:PG_WBEMSLPTemplate")
        self.assertEqual(entity_type, "root/PG_Internal:PG_WBEMSLPTemplate")
        self.assertEqual(entity_id, "")
        self.assertEqual(entity_host, "http://192.168.1.88:5988")

        entity_type, entity_id, entity_host = lib_util.ParseXid("http://192.168.1.88:5988/.")
        self.assertEqual(entity_type, "")
        self.assertEqual(entity_id, "")
        self.assertEqual(entity_host, "http://192.168.1.88:5988")

    def test_check_program_exists(self):
        """
        This tests the presence or absence of a command.
        """
        self.assertTrue(check_program_exists(sys.executable))
        self.assertTrue(check_program_exists("python"))
        self.assertTrue(check_program_exists("pytest"))
        self.assertFalse(check_program_exists("this__program_does_not_exist"))


if __name__ == '__main__':
    unittest.main()
