#!/usr/bin/env python

from __future__ import print_function

import os
import re
import sys
import rdflib
import unittest
from init import *

update_test_path()

# This is used by CGI scripts only.
import lib_daemon
import lib_common

# Otherwise the supervisor will not be loaded in pytest.
os.environ["START_DAEMON_FACTORY"] = "1"

# This is used by HTTP servers only.
from scripts import daemon_factory


def setUpModule():
    daemon_factory.supervisor_startup()
    # So the scripts started in daemon mode write their events in a shared graph.
    lib_common.set_events_credentials()


def tearDownModule():
    daemon_factory.supervisor_stop()


class CgiScriptTest(unittest.TestCase):
    _dummy_url_prefix = "http://any.machine/any_directory/"

    def test_url_to_process_name(self):
        """This tests the transformation of a script URL into an unique process name."""
        test_url_a = self._dummy_url_prefix + "this_url_does_not_exist.py?arg=%d" % (os.getpid() + 1)
        process_name_a = lib_daemon._url_to_process_name(test_url_a)

        test_url_b = self._dummy_url_prefix + "this_url_does_not_exist.py?arg=%d" % (os.getpid() + 2)
        process_name_b = lib_daemon._url_to_process_name(test_url_b)
        self.assertTrue(process_name_a != process_name_b)

    def test_is_events_generator_daemon_not_running(self):
        test_url = self._dummy_url_prefix + "non_existent_url.py?arg=%d" % os.getpid()
        status_running = lib_daemon.is_events_generator_daemon_running(test_url)
        self.assertTrue(not status_running)

    @unittest.skipIf(is_platform_windows and is_travis_machine(), "TEMPORARY DISABLED")
    def test_start_events_generator_daemon(self):
        # http://vps516494.ovh.net/Survol/survol/sources_types/enumerate_CIM_Process.py?xid=.
        test_url = self._dummy_url_prefix + "/survol/sources_types/events_generator_one_tick_per_second.py?parama=123&paramb=START"
        created_process_id = lib_daemon.start_events_generator_daemon(test_url)

        content_stdout = lib_daemon.get_events_generator_stdout(test_url)
        print("content_stdout=", content_stdout)

        content_stderr = lib_daemon.get_events_generator_stderr(test_url)
        print("content_stderr=", content_stderr)

        self.assertTrue(psutil.pid_exists(created_process_id))

        # PYTEST_CURRENT_TEST= tests/test_lib_daemon.py::CgiScriptTest::test_start_events_generator_daemon
        print("PYTEST_CURRENT_TEST=", os.environ["PYTEST_CURRENT_TEST"])

        self.assertTrue(created_process_id)

        status_running = lib_daemon.is_events_generator_daemon_running(test_url)
        content_stdout = lib_daemon.get_events_generator_stdout(test_url)
        print("content_stdout=", content_stdout)

        content_stderr = lib_daemon.get_events_generator_stderr(test_url)
        print("content_stderr=", content_stderr)

        self.assertTrue(status_running)
        content_stdout = lib_daemon.get_events_generator_stdout(test_url)
        print("content_stdout=", content_stdout)

        content_stderr = lib_daemon.get_events_generator_stderr(test_url)
        print("content_stderr=", content_stderr)

        self.assertTrue(psutil.pid_exists(created_process_id))
        time.sleep(1)
        content_stdout = lib_daemon.get_events_generator_stdout(test_url)
        print("content_stdout=", content_stdout)

        content_stderr = lib_daemon.get_events_generator_stderr(test_url)
        print("content_stderr=", content_stderr)

        self.assertTrue(psutil.pid_exists(created_process_id))

        content_stdout = lib_daemon.get_events_generator_stdout(test_url)
        print("content_stdout=", content_stdout)

        content_stderr = lib_daemon.get_events_generator_stderr(test_url)
        print("content_stderr=", content_stderr)

        status_stopped = lib_daemon.stop_events_generator_daemon(test_url)
        self.assertTrue(status_stopped)
        # Supervisor may need a bit of time to stop the user process.
        time.sleep(3)
        self.assertFalse(psutil.pid_exists(created_process_id))

    def test_start_events_generator_non_daemon(self):
        """Events generator must return something even if started in non-daemon mode."""
        # http://vps516494.ovh.net/Survol/survol/sources_types/enumerate_CIM_Process.py?xid=.

        try:
            rdf_test_agent, agent_url = start_cgiserver(RemoteRdfTestServerPort)
            script_suffix = "events_generator_one_tick_per_second.py?parama=456&paramb=START&mode=html"
            test_url = agent_url + "/survol/sources_types/" + script_suffix
            html_url_response = portable_urlopen(test_url, timeout=10)
            html_content = html_url_response.read()  # Py3:bytes, Py2:str
            # The format is not important, this just tests that the script started.
        except Exception as exc:
            print("test_start_events_generator_non_daemon: Caught:", exc)
            html_content = None
        finally:
            stop_cgiserver(rdf_test_agent)

        self.assertTrue(html_content)


#@unittest.skipIf(is_travis_machine(), "TEMPORARY DISABLED")
class CgiScriptStartThenKillTest(unittest.TestCase):
    """This tests all known events generator and at least checks of they start and stop properly."""

    def setUp(self):
        # If a Survol agent does not run on this machine with this port, this script starts a local one.
        self._rdf_test_agent, self._agent_url = start_cgiserver(RemoteRdfTestServerPort)
        print("AgentUrl=", self._agent_url)

    def tearDown(self):
        stop_cgiserver(self._rdf_test_agent)

    def _run_non_daemon_script(self, full_url):
        """Runs the script normally, without a daemon.
        is_snapshot_behaviour() returns True.

        If the daemon is running, it starts this daemon with the script and mode="daemon",
        and then immediately runs the script in snapshot mode, as a CGI script, to get some basic data."""
        rdf_url = full_url
        if full_url.find("?") >= 0:
            rdf_url += "&mode=rdf"
        else:
            rdf_url += "?mode=rdf"
        print("rdf_url=", rdf_url)
        # Some scripts take a long time to run.
        rdf_url_response = portable_urlopen(rdf_url, timeout=10)
        rdf_content = rdf_url_response.read()  # Py3:bytes, Py2:str
        print("rdf_content=", rdf_content)
        try:
            result_graph = rdflib.Graph().parse(data=rdf_content, format="application/rdf+xml")
        except Exception as exc:
            print("Cannot parse exc=", exc)
            print("rdf_content=", rdf_content)
            self.assertTrue(False)
        return result_graph

    def _check_script(self, script_suffix):
        # The url must not contain the mode
        full_url = self._agent_url + "/survol/sources_types/" + script_suffix
        graph_daemon_result_a = self._run_non_daemon_script(full_url)
        graph_daemon_result_b = self._run_non_daemon_script(full_url)
        return graph_daemon_result_a, graph_daemon_result_b

    def test_events_generator_psutil_processes_perf(self):
        url_suffix = "events_generator_psutil_processes_perf.py"
        daemon_result, non_daemon_result = self._check_script(url_suffix)
        self.assertTrue(daemon_result)
        self.assertTrue(non_daemon_result)

    def test_events_generator_sockets_promiscuous_mode(self):
        url_suffix = "events_generator_sockets_promiscuous_mode.py"
        daemon_result, non_daemon_result = self._check_script(url_suffix)
        self.assertTrue(daemon_result)
        self.assertTrue(non_daemon_result)

    @unittest.skipIf(is_platform_linux and is_travis_machine(), "Linux and Travis do not work. FIXME.")
    def test_events_generator_tcpdump(self):
        url_suffix = "events_generator_tcpdump.py"
        daemon_result, non_daemon_result = self._check_script(url_suffix)
        self.assertTrue(daemon_result)
        self.assertTrue(non_daemon_result)

    @unittest.skipIf(is_platform_linux, "Windows only")
    def test_events_generator_windows_directory_changes(self):
        # There is not much actovity in these directories: The goal is to test that the script starts correctly.
        if is_platform_linux:
            checked_directory = "/tmp"
        else:
            checked_directory = r"C:\\Users"
        url_suffix = "CIM_Directory/events_generator_windows_directory_changes.py?xid=CIM_Directory.Name=%s" % checked_directory
        daemon_result, non_daemon_result = self._check_script(url_suffix)
        self.assertTrue(daemon_result)
        self.assertTrue(non_daemon_result)

    def test_events_generator_system_calls(self):
        proc_open = None
        try:
            # This starts a dummy process.
            subprocess_command = [
                sys.executable,
                "-m",
                "supervisor.supervisord",
                "-c",
                "import time;time.sleep(10)" ]
            sys.stderr.write("test_events_generator_system_calls supervisor_command=%s\n" % subprocess_command)

            # No Shell, otherwise the subprocess running supervisor, will not be stopped.
            proc_popen = subprocess.Popen(subprocess_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)

            sys.stderr.write("proc_popen.pid=%s\n" % proc_popen.pid)

            url_suffix = "CIM_Process/events_generator_system_calls.py?xid=CIM_Process.Handle=%d" % proc_popen.pid
            # This attaches to the subprocess and gets its system calls.
            daemon_result, non_daemon_result = self._check_script(url_suffix)

            self.assertTrue(daemon_result)
            self.assertTrue(non_daemon_result)
        finally:
            # The subprocess will exit anyway.
            if proc_open:
                proc_popen.kill()
                proc_popen.communicate()
                proc_popen.terminate()

    def test_events_generator_iostat_all_disks(self):
        url_suffix = "Linux/events_generator_iostat_all_disks.py"
        daemon_result, non_daemon_result = self._check_script(url_suffix)
        self.assertTrue(daemon_result)
        self.assertTrue(non_daemon_result)


if __name__ == '__main__':
    unittest.main()

