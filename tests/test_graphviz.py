#!/usr/bin/env python

from __future__ import print_function

import os
import sys
from xml.dom import minidom
import unittest

from init import *

from survol.scripts import dockit


class SvgCommon(unittest.TestCase):
    def _check_script(self, script_suffix):
        full_url = self._agent_url + script_suffix
        if full_url.find("?") >= 0:
            full_url += "&mode=svg"
        else:
            full_url += "?mode=svg"
        print("full_url=", full_url)
        svg_url_response = portable_urlopen(full_url, timeout=5)
        svg_content = svg_url_response.read()  # Py3:bytes, Py2:str
        return svg_content

    # This tests the content of the main page of Survol.
    # The content is not accurately checked, just that it is a SVG XML document with some strings
    def _test_svg_main(self):
        svg_content = self._check_script("/survol/entity.py")

        dom = minidom.parseString(svg_content)

        text_content = set([text_tag.childNodes[0].nodeValue for text_tag in dom.getElementsByTagName('text')])
        print(text_content)

        # Some strings must be displayed.
        self.assertTrue('Classes hierarchy' in text_content)
        self.assertTrue('Processes tree' in text_content)
        self.assertTrue('System-wide open files' in text_content)

    def _test_svg_linux_user_group(self):
        self._check_script("/survol/sources_types/LMI_Group/linux_user_group.py?xid=LMI_Group.Name%3Dfedora")

    def _test_svg_user_processes(self):
        self._check_script(
            "/survol/sources_types/LMI_Account/user_processes.py?xid=LMI_Account.Name=root,Domain=%s"
            % SurvolServerHostname)

    def _test_svg_user_linux_id(self):
        self._check_script(
            "/survol/sources_types/LMI_Account/user_linux_id.py?xid=LMI_Account.Name=root,Domain=%s"
            % SurvolServerHostname)


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
        # This stops the local agent, an HTTP server.
        stop_cgiserver(self._remote_graphviz_test_agent)

    def test_local_agent_svg(self):
        self._test_svg_main()

    @unittest.skipIf(not is_platform_linux, "Linux only")
    def test_local_svg_linux_user_group(self):
        self._test_svg_linux_user_group()

    @unittest.skipIf(not is_platform_linux, "Linux only")
    def test_local_svg_user_processes(self):
        self._test_svg_user_processes()

    @unittest.skipIf(not is_platform_linux, "Linux only")
    def test_local_svg_user_linux_id(self):
        self._test_svg_user_linux_id()


# This targets Primhill Computers test machine.
class SvgRemoteAgentTest(SvgCommon):
    """
    Test parsing of the SVG output.
    """

    def setUp(self):
        self._agent_url = SurvolServerAgent

    # Loads a remote SVG url and parses the SVG document to check the presence of important tags.
    # It relies on the public Primhill Computers server.
    def test_remote_svg_main(self):
        self._test_svg_main()

    def test_remote_svg_linux_user_group(self):
        self._test_svg_linux_user_group()

    def test_remote_svg_user_processes(self):
        self._test_svg_user_processes()

    def test_remote_svg_user_linux_id(self):
        self._test_svg_user_linux_id()


# TODO: Test loadbookmark

if __name__ == '__main__':
    unittest.main()

