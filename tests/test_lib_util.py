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

    def test_parse_xid_local(self):
        # "WORKGROUP\MYHOST-HP@CIM_ComputerSystem.Name=Unknown-30-b5-c2-02-0c-b5-2"
        # "WORKGROUP\MYHOST-HP@oracle/table.Name=MY_TABLE"
        # "http://rchateau-hp:8000/survol/entity.py?xid=CIM_DataFile.Name=C%3A%2F%2FUsers%2Frchateau%2FLes%20Ringards%20-%20Aldo%20Maccione%252C%20Mireille%20Darc%252C%20Julien%20Guiomar.avi
        entity_type, entity_id, entity_host = lib_util.ParseXid("")
        self.assertEqual(entity_type, "")
        self.assertEqual(entity_id, "")
        self.assertEqual(entity_host, "")

    def test_parse_xid_wmi(self):
        # http://127.0.0.1:8000/survol/objtypes_wmi.py?xid=\\myhost-HP\root\CIMV2\Applications%3A.
        # http://127.0.0.1:8000/survol/class_wmi.py?xid=\\myhost-HP\root\CIMV2%3AWin32_PerfFormattedData_Counters_IPHTTPSGlobal.
        # http://127.0.0.1:8000/survol/entity_wmi.py?xid=\\MYHOST-HP\root\CIMV2%3AWin32_PerfFormattedData_Counters_IPHTTPSGlobal.Name%3D%22Default%22
        entity_type, entity_id, entity_host = lib_util.ParseXid("")
        self.assertEqual(entity_type, "")
        self.assertEqual(entity_id, "")
        self.assertEqual(entity_host, "")

    def test_parse_xid_wbem(self):
        # https://jdd:test@acme.com:5959/cimv2:Win32_SoftwareFeature.Name="Havana",ProductName="Havana",Version="1.0"
        # http://192.168.1.88:5988/root/PG_Internal:PG_WBEMSLPTemplate
        # "http://127.0.0.1:8000/survol/namespaces_wbem.py?xid=http://192.168.1.83:5988/."
        # "xid=http://192.168.1.88:5988/."
        entity_type, entity_id, entity_host = lib_util.ParseXid("")
        self.assertEqual(entity_type, "")
        self.assertEqual(entity_id, "")
        self.assertEqual(entity_host, "")


if __name__ == '__main__':
    unittest.main()
