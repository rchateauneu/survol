#!/usr/bin/env python

"""Test of various URL, the content is checked in RDF.
It could be done in another output format. The goal is to maximize the coverage."""

from __future__ import print_function

import os
import sys
import unittest
import rdflib
import lib_util
import lib_properties
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

        # Typical SMB shares:
        # smbshr.Id=//machine-name/IPC$
        # smbshr.Id=//machine-name/C$
        # smbshr.Id=//machine-name/Users
        # smbshr.Id=//machine-name/ADMIN$

        shares_set = set()
        for url_subject, url_predicate, url_object in result_graph.triples((None, pc.property_smbshare, None)):
            url_path, entity_type, entity_id_dict = lib_util.split_url_to_entity(url_object)
            shares_set.add(entity_id_dict['Id'])
        print("Shares=", shares_set)

        self.assertTrue( "//%s/IPC$" % lib_util.currentHostname in shares_set)
        self.assertTrue( "//%s/C$" % lib_util.currentHostname in shares_set)
        self.assertTrue( "//%s/Users" % lib_util.currentHostname in shares_set)

    @unittest.skipIf(not is_platform_windows, "Windows only")
    def test_rdf_windows_resource_icons(self):
        # This file contains at least one icon.
        file_path = "C:/Windows/System32/notepad.exe"
        result_graph = self._check_script(
            "/survol/sources_types/CIM_DataFile/win_resource_icons.py?xid=CIM_DataFile.Name=%s"
            % file_path)
        print("result_graph=", result_graph)
        for s, p, o in result_graph:
            if p.find("label") < 0 and p.find("comment") < 0 and p.find("domain") < 0 and p.find("range") < 0:
                print(s, p, o)
                print("")

        icon_url = None
        icon_attributes = None
        resource_icons = []
        resource_property = lib_properties.MakeProp("win32/resource")
        resources_triples = result_graph.triples((None, rdflib.namespace.RDF.type, resource_property))
        for url_subject, url_predicate, url_object in resources_triples:
            url_path, entity_type, entity_id_dict = lib_util.split_url_to_entity(url_subject)
        print("Resource icons=", resource_icons)
        self.assertEqual(entity_type, "win32/resource")
        self.assertEqual(entity_id_dict, {u'GroupName': u'2', u'Name': u'C:/Windows/System32/notepad.exe'})


@unittest.skip("Not ready yet.")
class MimeLocalAgentTest(unittest.TestCase):
    """
    Test parsing of the MIME output on a locally running agent.
    """

    def setUp(self):
        self._remote_mime_test_agent, self._agent_url = start_cgiserver(RemoteMimeTestServerPort)
        print("AgentUrl=", self._agent_url)

    def tearDown(self):
        stop_cgiserver(self._remote_mime_test_agent)

    def _check_script(self, script_suffix):
        """This runs a URL and returns the result as a ????? graph"""
        full_url = self._agent_url + script_suffix
        print("full_url=", full_url)

        # Some scripts take a long time to run.
        mime_url_response = portable_urlopen(full_url, timeout=30)
        mime_content = mime_url_response.read()  # Py3:bytes, Py2:str
        return mime_content

    @unittest.skipIf(not is_platform_windows, "Windows only")
    def test_entity_mime(self):
        # This file contains at least one icon.
        # BEWARE: Ne pas utiliser RDF car on va recevoir du mime de toute facon.
        file_path = "C:/Windows/System32/notepad.exe"
        result_graph = self._check_script(
            # "/survol/entity_mime.py?xid=win32/resource.Name=%s,GroupName=2?mode=mime:image/bmp"
            "/survol/entity_mime.py?xid=win32/resource.Name=%s,GroupName=2?mode=mime:image/bmp"
            % file_path)



    # http://rchateau-hp:8000/survol/sources_types/CIM_DataFile/win_resource_icons.py?xid=CIM_DataFile.Name%3DC%3A%2F%2F%2FWindows%2FSystem32%2Fnotepad.exe
    # http://rchateau-hp:8000/survol/entity_mime.py?xid=win32/resource.Name=C:///Windows/System32/notepad.exe,GroupName=2&amp;mode=mime:image/bmp
    # http://rchateau-hp:8000/survol/entity.py?xid=smbshr.Id=%2F%2Frchateau-hp/IPC$
    # http://rchateau-hp:8000/survol/sources_types/smbshr/smbshare_netshare.py?xid=smbshr.Id%3D%2F%2Frchateau-hp%2FIPC%24


if __name__ == '__main__':
    unittest.main()

