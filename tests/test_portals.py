#!/usr/bin/env python

"""Various tests of top-level scripts about objects types and classes in Survol, WMI and WBEM."""

from __future__ import print_function

import os
import sys
import rdflib
import unittest

from init import *

class PortalsTest(unittest.TestCase):
    def setUp(self):
        # If a Survol agent does not run on this machine with this port, this script starts a local one.
        self._remote_html_test_agent, self._agent_url = start_cgiserver(RemotePortalTestServerPort)
        print("AgentUrl=", self._agent_url)

    def tearDown(self):
        stop_cgiserver(self._remote_html_test_agent)

    def _check_script(self, script_suffix):
        full_url = self._agent_url + script_suffix
        print("full_url=", full_url)
        # Some scripts take a long time to run.
        rdf_url_response = portable_urlopen(full_url, timeout=30)
        rdf_content = rdf_url_response.read()  # Py3:bytes, Py2:str
        return rdf_content

    def test_portal_wbem_main(self):
        rdf_content = self._check_script("/survol/portal_wbem.py?mode=rdf")
        portal_graph = rdflib.Graph().parse(data=rdf_content, format="application/rdf+xml")
        self.assertTrue(portal_graph)

    @unittest.skipIf(is_platform_linux, "WMI on Windows only.")
    def test_portal_wmi_main(self):
        rdf_content = self._check_script("/survol/portal_wmi.py?mode=rdf")
        portal_graph = rdflib.Graph().parse(data=rdf_content, format="application/rdf+xml")
        self.assertTrue(portal_graph)

    @unittest.skipIf(is_platform_linux, "WMI on Windows only.")
    def test_namespaces_wmi_main(self):
        rdf_content = self._check_script("/survol/namespaces_wmi.py?mode=rdf")
        objtypes_graph = rdflib.Graph().parse(data=rdf_content, format="application/rdf+xml")
        self.assertTrue(objtypes_graph)

    @unittest.skip("Not implemented yet.")
    def test_namespaces_wbem_main(self):
        rdf_content = self._check_script("/survol/namespaces_wbem.py?mode=rdf")
        objtypes_graph = rdflib.Graph().parse(data=rdf_content, format="application/rdf+xml")
        self.assertTrue(objtypes_graph)

    @unittest.skipIf(is_platform_linux, "WMI on Windows only.")
    def test_objtypes_wmi_main(self):
        rdf_content = self._check_script("/survol/objtypes_wmi.py?mode=rdf")
        objtypes_graph = rdflib.Graph().parse(data=rdf_content, format="application/rdf+xml")
        self.assertTrue(objtypes_graph)

    def test_objtypes_wbem_main(self):
        rdf_content = self._check_script("/survol/objtypes_wbem.py?mode=rdf")
        objtypes_graph = rdflib.Graph().parse(data=rdf_content, format="application/rdf+xml")
        self.assertTrue(objtypes_graph)

    def test_objtypes_main(self):
        rdf_content = self._check_script("/survol/objtypes.py?mode=rdf")
        objtypes_graph = rdflib.Graph().parse(data=rdf_content, format="application/rdf+xml")
        self.assertTrue(objtypes_graph)


if __name__ == '__main__':
    unittest.main()

