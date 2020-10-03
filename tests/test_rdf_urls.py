#!/usr/bin/env python

"""Test of various URL, the content is checked in RDF.
It could be done in another output format. The goal is to maximize the coverage."""

from __future__ import print_function

import os
import sys
import unittest
import rdflib
from lib_properties import pc

from init import *


class RdfLocalAgentTest(unittest.TestCase):
    """
    Test parsing of the RDF output on a locally running agent.
    """

    def setUp(self):
        # If a Survol agent does not run on this machine with this port, this script starts a local one.
        self._remote_rdf_test_agent, self._agent_url = start_cgiserver(RemoteRdf0TestServerPort)
        print("AgentUrl=", self._agent_url)

    def tearDown(self):
        stop_cgiserver(self._remote_rdf_test_agent)

    def _check_script(self, script_suffix):
        """This runs a URL and returns the result as a rdflib graph"""
        full_url = self._agent_url + script_suffix
        if full_url.find("?") >= 0:
            full_url += "&mode=rdf"
        else:
            full_url += "?mode=rdf"
        print("full_url=", full_url)
        # Some scripts take a long time to run.
        rdf_url_response = portable_urlopen(full_url, timeout=30)
        rdf_content = rdf_url_response.read()  # Py3:bytes, Py2:str
        result_graph = rdflib.Graph().parse(data=rdf_content, format="application/rdf+xml")
        return result_graph

    @unittest.skipIf(not is_platform_windows, "Windows only")
    def test_rdf_SMB_net_share(self):
        result_graph = self._check_script("/survol/sources_types/SMB/net_share.py?xid=.")
        self.assertTrue(len(result_graph) > 0)
        for s, p, o in result_graph.triples((None, pc.property_smbshare, None)):
            print("    ", s, p, o)

    # TODO: Test
    # win_resource_icons.
    # http://rchateau-hp:8000/survol/sources_types/SMB/net_share.py?xid=.
    # http://rchateau-hp:8000/survol/entity.py?xid=smbshr.Id=%2F%2Frchateau-hp/IPC$
    # http://rchateau-hp:8000/survol/sources_types/smbshr/smbshare_netshare.py?xid=smbshr.Id%3D%2F%2Frchateau-hp%2FIPC%24


if __name__ == '__main__':
    unittest.main()

