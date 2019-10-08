#!/usr/bin/env python

# Many SPARQL examples.
# http://api.talis.com/stores/space/items/tutorial/spared.html?query=SELECT+%3Fp+%3Fo%0D%0A{+%0D%0A++%3Chttp%3A%2F%2Fnasa.dataincubator.org%2Fspacecraft%2F1968-089A%3E+%3Fp+%3Fo%0D%0A}
#
# This is equivalent to:
# Special characters encoded in hexadecimal.
#
# The goal is to extract triples, for two different purposes:
# (1) Transform a Sparql query into WQL: This might work in very simple cases;, for WMI and WBEM.
# (2) Or identify which scripts should be run to feed a local triplestore and get useful data.
# Both purposes need the triples and the classes.

from __future__ import print_function

import os
import sys
import json
import unittest
import pkgutil

from init import *

update_test_path()

# This is what we want to test.
import lib_sparql
import lib_util
import lib_properties
import lib_kbase
import lib_wmi
import lib_sparql_callback_survol



################################################################################


class SparqlCallWbemTest(unittest.TestCase):

    @unittest.skipIf(not pkgutil.find_loader('wbem'), "wbem cannot be imported. test_wbem_query not executed.")
    def test_wbem_query(self):
        pass


if __name__ == '__main__':
    unittest.main()

