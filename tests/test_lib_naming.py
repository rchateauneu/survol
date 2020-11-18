#!/usr/bin/env python

"""Tests the file lib_naming.py.
"""

from __future__ import print_function

__author__      = "Remi Chateauneu"
__copyright__   = "Copyright 2020, Primhill Computers"
__license__ = "GPL"

import unittest

from init import *

from survol import lib_naming
from survol.sources_types import CIM_ComputerSystem

class ParseEntityUriWithHostTest(unittest.TestCase):

    def test_plain_url(self):
        input_url = "/survol/entity.py?xid=CIM_ComputerSystem.Name=my_machine"
        full_title, entity_class, entity_id, entity_host = lib_naming.ParseEntityUriWithHost(
                    input_url,
                    long_display=False,
                    force_entity_ip_addr=None)
        print("full_title=", full_title)
        print("entity_class=", entity_class)
        print("entity_id=", entity_id)
        print("entity_host=", entity_host)
        self.assertEqual(full_title, "my_machine")
        self.assertEqual(entity_class, "CIM_ComputerSystem")
        self.assertEqual(entity_id, "Name=my_machine")
        self.assertEqual(entity_host, "")

    def test_after_edit_url(self):
        input_url = "/survol/entity.py?edimodargs_Domain=my_machine&edimodargs_Name=INTERACTIVE&Show+all+scripts=True&edimodtype=Win32_Group&xid=Win32_Group.Domain%3Drchateau-hp%2CName%3DINTERACTIVE"
        full_title, entity_class, entity_id, entity_host = lib_naming.ParseEntityUriWithHost(
                    input_url,
                    long_display=False,
                    force_entity_ip_addr=None)
        print("full_title=", full_title)
        print("entity_class=", entity_class)
        print("entity_id=", entity_id)
        print("entity_host=", entity_host)
        self.assertEqual(full_title, r"rchateau-hp\\INTERACTIVE")
        self.assertEqual(entity_class, "Win32_Group")
        self.assertEqual(entity_id, "Domain=rchateau-hp,Name=INTERACTIVE")
        self.assertEqual(entity_host, "")






