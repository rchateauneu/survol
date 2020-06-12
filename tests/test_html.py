#!/usr/bin/env python

from __future__ import print_function

import os
import sys
import unittest

from init import *

from survol.scripts import dockit


class HtmlCommon(unittest.TestCase):
    # This checks that the entry page of Survol is a correct HTML document.
    # It does not intent to be very exact, but just checks that the HTML display runs.
    def _check_html_main_page(self, html_page_content):
        print(html_page_content)

        # Some strings must be displayed.
        self.assertTrue(b'<title>Overview entity.py</title>' in html_page_content)

    def _check_page_entity(self, agent_url):
        html_url_response = portable_urlopen(agent_url + "/survol/entity.py?mode=html", timeout=5)
        svg_content = html_url_response.read()  # Py3:bytes, Py2:str
        self._check_html_main_page(svg_content)

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

    def test_local_agent_html(self):
        # This starts a local server on the test machine.
        self._check_page_entity(self._agent_url)


# Graphviz/dot must be installed on the test platform, for example Travis.
class HtmlRemoteAgentTest(HtmlCommon):
    """
    Test parsing of the HTML output from the "official" demo server.
    """

    # Loads a remote SVG url and parses the SVG document to check the presence of important tags.
    # It relies on the public Primhill Computers server.
    def test_remote_agent_html(self):
        self._check_page_entity(SurvolServerAgent)


if __name__ == '__main__':
    unittest.main()

