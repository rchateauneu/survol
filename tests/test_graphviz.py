#!/usr/bin/env python

from __future__ import print_function

import os
import sys
from xml.dom import minidom
import unittest

from init import *

from survol.scripts import dockit


class SvgCommon(unittest.TestCase):
    # This tests the content of the main page of Survol.
    # The content is not accurately check, just that it is a XML document with some strings
    def _check_svg_main_page(self, svg_content):
        dom = minidom.parseString(svg_content)

        text_content = set([text_tag.childNodes[0].nodeValue for text_tag in dom.getElementsByTagName('text')])
        print(text_content)

        # Some strings must be displayed.
        self.assertTrue('Classes hierarchy' in text_content)
        self.assertTrue('Processes tree' in text_content)
        self.assertTrue('System-wide open files' in text_content)


    def _check_page_entity(self, agent_url):
        svg_url_response = portable_urlopen(agent_url + "/survol/entity.py?mode=svg", timeout=5)
        svg_content = svg_url_response.read()  # Py3:bytes, Py2:str
        self._check_svg_main_page(svg_content)


def _is_dot_available():
    dot_status = os.system("dot -?")
    return dot_status == 0


# Graphviz/dot must be installed on the test platform, for example Travis.
@unittest.skipIf(not _is_dot_available(), "Graphviz Must be available.")
class SvgLocalAgentTest(SvgCommon):
    """
    Test parsing of the SVG output.
    """

    def setUp(self):
        # If a Survol agent does not run on this machine with this port, this script starts a local one.
        self._remote_graphviz_test_agent, self._agent_url = start_cgiserver(RemoteGraphvizTestServerPort)
        print("AgentUrl=", self._agent_url)

    def tearDown(self):
        stop_cgiserver(self._remote_graphviz_test_agent)

    def test_local_agent_svg(self):
        # This starts a local server on the test machine.
        self._check_page_entity(self._agent_url)


# Graphviz/dot must be installed on the test platform, for example Travis.
class SvgRemoteAgentTest(SvgCommon):
    """
    Test parsing of the SVG output.
    """

    # Loads a remote SVG url and parses the SVG document to check the presence of important tags.
    # It relies on the public Primhill Computers server.
    def test_remote_agent_svg(self):
        self._check_page_entity(SurvolServerAgent)

# TODO: Test loadbookmark

if __name__ == '__main__':
    unittest.main()

