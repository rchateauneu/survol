#!/usr/bin/env python

from __future__ import print_function

import os
import sys
import unittest

from init import *

from survol.scripts import dockit


class HtmlCommon(unittest.TestCase):
    def _check_script(self, script_suffix):
        full_url = self._agent_url + script_suffix
        if full_url.find("?") >= 0:
            full_url += "&mode=html"
        else:
            full_url += "?mode=html"
        print("full_url=", full_url)
        # Some scripts take a long time to run.
        html_url_response = portable_urlopen(full_url, timeout=30)
        html_content = html_url_response.read()  # Py3:bytes, Py2:str
        return html_content

    def _test_html_main(self):
        html_page_content = self._check_script("/survol/entity.py")

        # Some strings must be displayed.
        # This checks that the entry page of Survol is a correct HTML document.
        # It does not intent to be very exact, but just checks that the HTML display runs.
        self.assertTrue(b'<title>Overview entity.py</title>' in html_page_content)

    def _test_html_file_directory(self):
        html_page_content = self._check_script("/survol/sources_types/CIM_Directory/file_directory.py?xid=CIM_Directory.Name=/usr/lib")

        # Some strings must be displayed.
        # This checks that the entry page of Survol is a correct HTML document.
        # It does not intent to be very exact, but just checks that the HTML display runs.
        self.assertTrue(b'<title>Files in directory' in html_page_content)


# Graphviz/dot must be installed on the test platform, for example Travis.
class HtmlLocalAgentTest(HtmlCommon):
    """
    Test parsing of the HTML output on an agent locally running.
    """

    def setUp(self):
        # If a Survol agent does not run on this machine with this port, this script starts a local one.
        self._remote_html_test_agent, self._agent_url = start_cgiserver(RemoteHtmlTestServerPort)
        print("AgentUrl=", self._agent_url)

    def tearDown(self):
        stop_cgiserver(self._remote_html_test_agent)

    def test_local_html(self):
        # This starts a local server on the test machine.
        self._test_html_main()

    @unittest.skipIf(not is_platform_linux, "Linux only")
    def test_local_file_directory(self):
        self._test_html_file_directory()


# Graphviz/dot must be installed on the test platform, for example Travis.
class HtmlRemoteAgentTest(HtmlCommon):
    """
    Test parsing of the HTML output from the "official" demo server.
    """
    def setUp(self):
        self._agent_url = SurvolServerAgent


    # Loads a remote SVG url and parses the SVG document to check the presence of important tags.
    # It relies on the public Primhill Computers server.
    def test_remote_html(self):
        self._test_html_main()

    def test_remote_file_directory(self):
        self._test_html_file_directory()


if __name__ == '__main__':
    unittest.main()

