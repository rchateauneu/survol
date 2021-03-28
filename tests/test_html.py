#!/usr/bin/env python

"""Test of various URL, the content is checked in HTML.
It could be done in another output format. The goal is to maximize the coverage."""

from __future__ import print_function

import os
import sys
import unittest

from init import *


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

    def base_html_main(self):
        """This checks that the entry page of Survol is a correct HTML document.
        It does not intent to be very exact, but just checks that the HTML display runs.
        Some strings must be displayed."""
        html_page_content = self._check_script("/survol/entity.py")
        self.assertTrue(b'<title>Overview entity.py</title>' in html_page_content)

    def base_html_file_directory(self):
        """This checks that the entry page of Survol is a correct HTML document.
        It does not intent to be very exact, but just checks that the HTML display runs.
        Some strings must be displayed."""
        html_page_content = self._check_script(
            "/survol/sources_types/CIM_Directory/file_directory.py?xid=CIM_Directory.Name=/usr/lib")
        self.assertTrue(b'<title>Files in directory' in html_page_content)

    def base_hostname_shares_smbclient(self):
        """This script might often return an error depending on the platform.
        But it must always return a correct page HTML."""
        html_page_content = self._check_script(
            "/survol/sources_types/CIM_ComputerSystem/hostname_shares_smbclient.py")


# Graphviz/dot does not have to be installed on the test platform.
class HtmlLocalAgentTest(HtmlCommon):
    """
    Test parsing of the HTML output on an agent locally running.
    """

    def setUp(self):
        """If a Survol agent does not run on this machine with this port, this script starts a local one."""
        self._remote_html_test_agent, self._agent_url = start_cgiserver(RemoteHtmlTestServerPort)
        print("AgentUrl=", self._agent_url)

    def tearDown(self):
        stop_cgiserver(self._remote_html_test_agent)

    def test_local_html(self):
        """This starts a local server on the test machine."""
        self.base_html_main()

    @unittest.skipIf(not is_platform_linux, "Linux only")
    def test_local_file_directory(self):
        self.base_html_file_directory()

    def test_hostname_shares_smbclient(self):
        self.base_hostname_shares_smbclient()

    def test_edit_configuration(self):
        html_page_content = self._check_script(
            "/survol/edit_configuration.py")
        self.assertTrue(b'Edit Survol configuration' in html_page_content)

    def test_edit_credentials(self):
        html_page_content = self._check_script(
            "/survol/edit_credentials.py")
        # This might return an error page if the supervisor is not started but it must respond.

    def test_edit_supervisor(self):
        html_page_content = self._check_script(
            "/survol/edit_supervisor.py")
        # This might return an error page but it must respond.


class HtmlRemoteAgentTest(HtmlCommon):
    """
    Test parsing of the HTML output from the "official" demo server.
    """
    def setUp(self):
        self._agent_url = SurvolServerAgent

    def test_remote_html(self):
        self.base_html_main()

    def test_remote_file_directory(self):
        self.base_html_file_directory()

    def test_hostname_shares_smbclient(self):
        self.base_hostname_shares_smbclient()


class HtmlParametersEdition(unittest.TestCase):
    def setUp(self):
        """If a Survol agent does not run on this machine with this port, this script starts a local one."""
        self._remote_html_test_agent, self._agent_url = start_cgiserver(RemoteHtmlTestServerPort)
        print("AgentUrl=", self._agent_url)

    def tearDown(self):
        stop_cgiserver(self._remote_html_test_agent)

    def _check_edition_script(self, script_suffix):
        full_url = self._agent_url + script_suffix
        print("full_url=", full_url)
        html_url_response = portable_urlopen(full_url, timeout=10)
        html_content = html_url_response.read()  # Py3:bytes, Py2:str
        return html_content

    @unittest.skipIf(not is_platform_windows, "base_html_edition_cim_datafile_form for Windows only.")
    def test_html_edition_cim_logical_disk_form(self):
        """Minimal check to ensure that an edition returns a valid HTML page."""

        html_page_content = self._check_edition_script(
            "/survol/entity.py?xid=CIM_LogicalDisk.DeviceID=C:&mode=edit")
        self.assertTrue(html_page_content.find(b'<input type="submit" value="Submit">') >= 0)

    @unittest.skipIf(not is_platform_windows, "base_html_edition_cim_datafile_html for Windows only.")
    def test_html_edition_cim_logical_disk_html(self):
        """Minimal check to ensure that an edition returns a valid HTML page."""

        html_page_content = self._check_edition_script(
            "/survol/entity.py?edimodargs_DeviceID=C%3A&xid=CIM_LogicalDisk.DeviceID%3DC%3A&mode=html&edimodtype=CIM_LogicalDisk")
        self.assertTrue(html_page_content.find(b'Script parameters') >= 0)

    def test_html_edition_cim_process_form(self):
        """This is the URL after validation of parameters edition."""

        # Any PID is OK.
        html_page_content = self._check_edition_script(
            "/survol/entity.py?xid=CIM_Process.Handle=6744&mode=edit")
        self.assertTrue(html_page_content.find(b'<input type="submit" value="Submit">') >= 0)

    def test_html_edition_cim_process_html(self):
        """This is the URL after validation of parameters edition."""

        # Any PID is OK.
        html_page_content = self._check_edition_script(
            "/survol/entity.py?edimodargs_Handle=6744&Show+all+scripts=True&edimodtype=CIM_Process&xid=CIM_Process.Handle%3D6744&mode=html")
        self.assertTrue(html_page_content.find(b'Script parameters') >= 0)


if __name__ == '__main__':
    unittest.main()

