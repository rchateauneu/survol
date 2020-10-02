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
import lib_kbase
import lib_properties


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

    def setUp(self):
        # If a Survol agent does not run on this machine with this port, this script starts a local one.
        self._rdf_test_agent, self._agent_url = start_cgiserver(RemoteRdfTestServerPort)

    def tearDown(self):
        stop_cgiserver(self._rdf_test_agent)

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

    @unittest.skipIf(is_platform_windows and is_travis_machine(), "FIXME: This hangs")
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

        script_suffix = "events_generator_one_tick_per_second.py?parama=456&paramb=START&mode=html"
        test_url = self._agent_url + "/survol/sources_types/" + script_suffix
        html_url_response = portable_urlopen(test_url, timeout=10)
        html_content = html_url_response.read()  # Py3:bytes, Py2:str
        # The format is not important, this just tests that the script started.

        self.assertTrue(html_content)


def _run_daemon_script_in_snapshot_mode(full_url):
    """Runs the script normally, without a daemon.
    The function is_snapshot_behaviour(), which is called in all events generators, returns True.

    If the daemon is running, it starts this daemon with the script and mode="daemon",
    and then immediately runs the script in snapshot mode, as a CGI script, to get some basic data.
    At this stage, the daemon for this url (script + CGI args) was not started yet. """
    rdf_url = full_url
    if full_url.find("?") >= 0:
        rdf_url += "&mode=rdf"
    else:
        rdf_url += "?mode=rdf"
    print("rdf_url=", rdf_url)
    # Some scripts take a long time to run.
    rdf_url_response = portable_urlopen(rdf_url, timeout=20)
    rdf_content = rdf_url_response.read()
    #print("rdf_content=", rdf_content)
    try:
        result_graph = rdflib.Graph().parse(data=rdf_content, format="application/rdf+xml")
    except Exception as exc:
        print("Cannot parse exc=", exc)
        print("rdf_content=", rdf_content)
        raise
    print("len(result_graph)=", len(result_graph))
    return result_graph


def _triple_to_three_strings(*one_triple):
    """This helper function is used to transform nodes into strings. Nodes are not uniquely generated."""
    return str(one_triple[0]), str(one_triple[1]), str(one_triple[2])


def _graph_to_process_nodes(graph_result):
    return sorted(set([str(subj) for subj, pred, obj in graph_result]))


class CgiScriptIOMemoryStartOnlyTest(unittest.TestCase):
    """This tests all known events generator and at least checks if they start and stop properly.
    They expect that the supervisor is freshly started and do not contain events.
    Many tests also work even if the scripts immediately exit for whatever reason."""

    def setUp(self):
        # If a Survol agent does not run on this machine with this port, this script starts a local one.
        self._rdf_test_agent, self._agent_url = start_cgiserver(RemoteRdfTestServerPort)
        print("AgentUrl=", self._agent_url)
        lib_kbase.set_storage_style("IOMemory",)

    def tearDown(self):
        stop_cgiserver(self._rdf_test_agent)
        lib_kbase.set_storage_style(None,)

    def _agent_box(self):
        agent_prefix = self._agent_url + "/survol"
        return lib_common.OtherAgentBox(agent_prefix)

    def _run_script_as_snapshot(self, script_suffix):
        """This runs the script just once, in snapshot mode. The url must not contain the mode. """
        full_url = self._agent_url + "/survol/sources_types/" + script_suffix
        graph_daemon_result_snapshot = _run_daemon_script_in_snapshot_mode(full_url)

        # The result should not be empty, and contain at least a couple of triples.
        self.assertTrue(graph_daemon_result_snapshot)

        return graph_daemon_result_snapshot

    def test_events_generator_psutil_processes_perf(self):
        url_suffix = "events_generator_psutil_processes_perf.py"
        result_snapshot = self._run_script_as_snapshot(url_suffix)


        print("len(result_snapshot)=", len(result_snapshot))

        # The node of the current process must be in the result.
        current_process_node = self._agent_box().UriMakeFromDict("CIM_Process", {"Handle": CurrentPid})
        current_process_triples = list(result_snapshot.triples((current_process_node, None, None)))
        self.assertTrue(len(current_process_triples) > 0)

        # The node of the parent process must be in the result.
        parent_process_node = self._agent_box().UriMakeFromDict("CIM_Process", {"Handle": CurrentParentPid})
        parent_process_triples = list(result_snapshot.triples((parent_process_node, None, None)))
        self.assertTrue(len(parent_process_triples) > 0)

    @unittest.skipIf(is_platform_windows and is_travis_machine(), "FIXME: Broken on Windows and Travis")
    def test_events_generator_psutil_system_counters(self):
        url_suffix = "events_generator_psutil_system_counters.py"
        result_snapshot = self._run_script_as_snapshot(url_suffix)
        self.assertTrue(result_snapshot)
        triples_count = len(result_snapshot)
        # result_snapshot= [a rdfg:Graph;rdflib:storage [a rdflib:Store;rdfs:label 'IOMemory']].
        print("triples_count=", triples_count)
        # Many counters: Memory, network etc....
        self.assertTrue(triples_count > 10)

    @unittest.skipIf(is_platform_windows and is_travis_machine(), "Windows and Travis do not work. WHY ? FIXME.")
    def test_events_generator_sockets_promiscuous_mode(self):
        url_suffix = "events_generator_sockets_promiscuous_mode.py"
        result_snapshot = self._run_script_as_snapshot(url_suffix)
        self.assertTrue(result_snapshot)

    @unittest.skipIf(is_platform_linux and is_travis_machine(), "Linux and Travis do not work. WHY ? FIXME.")
    def test_events_generator_tcpdump(self):
        url_suffix = "events_generator_tcpdump.py"
        result_snapshot = self._run_script_as_snapshot(url_suffix)
        self.assertTrue(result_snapshot)

    @unittest.skipIf(is_platform_linux, "Windows only")
    def test_events_generator_windows_directory_changes(self):
        """There is not much activity in these directories: The goal is to test that the script starts correctly."""
        if is_platform_linux:
            checked_directory = "/tmp"
        else:
            checked_directory = r"C:\\Users"
        url_suffix = "CIM_Directory/events_generator_windows_directory_changes.py?xid=CIM_Directory.Name=%s" % checked_directory
        result_snapshot = self._run_script_as_snapshot(url_suffix)
        self.assertTrue(result_snapshot)

    @unittest.skipIf(is_platform_windows and is_travis_machine(), "FIXME: Broken on Windows and Travis")
    def test_events_generator_system_calls_sleep(self):
        proc_open = None
        try:
            # This starts a dummy process, whose system calls will be monitored.
            subprocess_command = [
                sys.executable,
                "-c",
                "import time;time.sleep(5)"]
            sys.stderr.write("test_events_generator_system_calls supervisor_command=%s\n" % subprocess_command)

            # No Shell, otherwise we cannot know which process is created.
            proc_popen = subprocess.Popen(
                subprocess_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)

            print("proc_popen.pid=%s\n" % proc_popen.pid)

            # This node must be in the result. Dockit is run within a temporary agent,
            # therefore this agent is used as a URL for the created nodes.
            created_process_node = self._agent_box().UriMakeFromDict("CIM_Process", {"Handle": proc_popen.pid})
            literal_pid = lib_kbase.MakeNodeLiteral(proc_popen.pid)

            url_suffix = "CIM_Process/events_generator_system_calls.py?xid=CIM_Process.Handle=%d" % proc_popen.pid
            # This attaches to the subprocess and gets its system calls.
            result_snapshot = self._run_script_as_snapshot(url_suffix)

            print("Triple=", created_process_node, lib_properties.pc.property_pid, literal_pid)

            self.assertTrue(
                _triple_to_three_strings(created_process_node, lib_properties.pc.property_pid, literal_pid)
                in [_triple_to_three_strings(*one_triple) for one_triple in result_snapshot])

        finally:
            # The subprocess will exit anyway.
            if proc_open:
                proc_popen.kill()
                proc_popen.communicate()
                proc_popen.terminate()

    @unittest.skipIf(is_platform_windows and is_travis_machine(), "FIXME: Broken on Windows and Travis")
    def test_events_generator_iostat_all_disks(self):
        url_suffix = "Linux/events_generator_iostat_all_disks.py"
        daemon_result = self._run_script_as_snapshot(url_suffix)
        self.assertTrue(daemon_result)

    def test_events_generator_vmstat(self):
        url_suffix = "Linux/events_generator_vmstat.py"
        daemon_result = self._run_script_as_snapshot(url_suffix)
        self.assertTrue(daemon_result)


@unittest.skip("FIXME")
class CgiScriptSQLAlchemyStartOnlyTest(unittest.TestCase):
    """This tests some events generator with SQLite events storage."""

    def setUp(self):
        lib_common.set_events_credentials()


        # Cleanup of a previous run.
        lib_kbase.retrieve_all_events_to_graph_then_clear(rdflib.Graph())

        # If a Survol agent does not run on this machine with this port, this script starts a local one.
        self._rdf_test_agent, self._agent_url = start_cgiserver(RemoteRdfTestServerPort)
        print("AgentUrl=", self._agent_url)

        # A shared database is needed because several processes use it simultaneously.
        #database_path = create_temporary_sqlite_filename()
        #sqlite_path = "sqlite:///%s?mode=memory&cache=shared" % database_path

        #lib_kbase.set_storage_style("SQLAlchemy", sqlite_path)

    def tearDown(self):
        stop_cgiserver(self._rdf_test_agent)
        lib_kbase.set_storage_style(None,)

    def _agent_box(self):
        agent_prefix = self._agent_url + "/survol"
        return lib_common.OtherAgentBox(agent_prefix)

    def _run_script_as_snapshot(self, script_suffix):
        # The url must not contain the mode
        full_url = self._agent_url + "/survol/sources_types/" + script_suffix
        print("full_url=", full_url)
        graph_daemon_result_snapshot = _run_daemon_script_in_snapshot_mode(full_url)

        # The result should not be empty, and contain at least a couple of triples.
        self.assertTrue(graph_daemon_result_snapshot)

        return graph_daemon_result_snapshot

    def test_events_generator_psutil_processes_perf_sqlalchemy(self):
        """Results are stored in a SQLite database"""
        url_suffix = "events_generator_psutil_processes_perf.py"
        result_snapshot = self._run_script_as_snapshot(url_suffix)
        print("len(result_snapshot)=", len(result_snapshot))

        # The node of the current process must be in the result.
        current_process_node = self._agent_box().UriMakeFromDict("CIM_Process", {"Handle": CurrentPid})
        print("current_process_node=", current_process_node)
        print("_graph_to_process_nodes(result_snapshot)=", _graph_to_process_nodes(result_snapshot))
        self.assertTrue( str(current_process_node) in _graph_to_process_nodes(result_snapshot))


        current_process_triples = list(result_snapshot.triples((current_process_node, None, None)))
        print("Nodes of current process:", CurrentPid)
        for s, p, o in current_process_triples:
            print("    ", s, p, o)
        self.assertTrue(len(current_process_triples) > 0)

        # The node of the parent process must be in the result.
        parent_process_node = self._agent_box().UriMakeFromDict("CIM_Process", {"Handle": CurrentParentPid})
        parent_process_triples = list(result_snapshot.triples((parent_process_node, None, None)))
        print("Nodes of current process:", CurrentParentPid)
        for s, p, o in parent_process_triples:
            print("    ", s, p, o)
        self.assertTrue(len(parent_process_triples) > 0)


class CgiScriptStartThenEventsTest(unittest.TestCase):
    """This tests scripts which also return events and stay running for a long time."""

    def setUp(self):
        # If a Survol agent does not run on this machine with this port, this script starts a local one.
        self._rdf_test_agent, self._agent_url = start_cgiserver(RemoteRdfTestServerPort)
        print("AgentUrl=", self._agent_url)

        # A shared database is needed because several processes use it simultaneously.
        # When reading the events, this uses the default SQLAlchemy database also used by the CGI scripts.
        lib_common.set_events_credentials()

    def tearDown(self):
        stop_cgiserver(self._rdf_test_agent)
        lib_kbase.set_storage_style(None,)

    def _agent_box(self):
        return lib_common.OtherAgentBox(self._agent_url + "/survol")

    def _run_script_snapshot_then_events(self, script_suffix):
        # Check that the supervisor is running, it is started by cgiserver.py.

        # The url must not contain the mode
        local_url = "/survol/sources_types/" + script_suffix
        full_url = self._agent_url + local_url
        graph_daemon_result_snapshot = _run_daemon_script_in_snapshot_mode(full_url)

        # The result should not be empty, and contain at least a couple of triples.
        self.assertTrue(graph_daemon_result_snapshot)
        # graph_daemon_result_snapshot= [a rdfg:Graph;rdflib:storage [a rdflib:Store;rdfs:label 'IOMemory']].
        print("graph_daemon_result_snapshot=", graph_daemon_result_snapshot)

        time.sleep(20)

        # Now, the daemon process must have been started and must still be running.
        is_daemon_running = lib_daemon.is_events_generator_daemon_running(local_url)
        self.assertTrue(is_daemon_running)

        graph_daemon_result_events = rdflib.Graph()

        triples_count = lib_kbase.read_events_to_graph(local_url, graph_daemon_result_events)
        print("triples_count=", triples_count)

        # Now, loads events from the events graph. After a bit of time, some events might be there.
        return graph_daemon_result_snapshot, graph_daemon_result_events

    @unittest.skip("FIXME. Temporarily disabled.")
    def test_events_generator_psutil_processes_perf(self):
        url_suffix = "events_generator_psutil_processes_perf.py"
        result_snapshot, result_events = self._run_script_snapshot_then_events(url_suffix)
        self.assertTrue(result_snapshot)
        self.assertTrue(result_events)

    @unittest.skipIf(is_platform_windows and is_travis_machine(), "FIXME: Broken on Windows and Travis")
    def test_events_generator_psutil_system_counters(self):
        url_suffix = "events_generator_psutil_system_counters.py"
        result_snapshot, result_events = self._run_script_snapshot_then_events(url_suffix)
        self.assertTrue(result_snapshot)
        self.assertTrue(result_events)

    @unittest.skip("Temporarily disabled")
    def test_events_generator_system_calls_loop(self):
        proc_open = None
        try:
            # This starts a dummy process, whose system calls will be monitored.
            subprocess_command = [
                sys.executable,
                "-c",
                "import time;time.sleep(3)"]
            sys.stderr.write("test_events_generator_system_calls supervisor_command=%s\n" % subprocess_command)

            # No Shell, otherwise we cannot know which process is created.
            proc_popen = subprocess.Popen(
                subprocess_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)

            print("proc_popen.pid=%s\n" % proc_popen.pid)

            # This node must be in the result. Dockit is run within a temporary agent,
            # therefore this agent is used as a URL for the created nodes.
            agent_prefix = self._agent_url + "/survol"
            created_process_node = lib_common.OtherAgentBox(agent_prefix).UriMakeFromDict(
                "CIM_Process", {"Handle": proc_popen.pid})
            literal_pid = lib_kbase.MakeNodeLiteral(proc_popen.pid)

            url_suffix = "CIM_Process/events_generator_system_calls.py?xid=CIM_Process.Handle=%d" % proc_popen.pid
            # This attaches to the subprocess and gets its system calls.
            result_snapshot, result_events = self._run_script_snapshot_then_events(url_suffix)

            self.assertTrue(result_snapshot)
            #print("daemon_result=", daemon_result)
            for daemon_subject, daemon_predicate, daemon_object in result_snapshot:
                if str(daemon_object) == str(proc_popen.pid):
                    print("xxxxxx=", daemon_subject, daemon_predicate, daemon_object)

            print("Triple=", created_process_node, lib_properties.pc.property_pid, literal_pid)

            find_triple = result_snapshot.triples((created_process_node, lib_properties.pc.property_pid, literal_pid))
            print("find_triple=", find_triple)
            print("len(find_triple)=", len(list(find_triple)))

            # This is used to transform nodes into strings. Nodes are not uniquely generated.
            def triple_to_three_strings(*one_triple):
                return str(one_triple[0]), str(one_triple[1]), str(one_triple[2])

            self.assertTrue(
                triple_to_three_strings(created_process_node, lib_properties.pc.property_pid, literal_pid)
                in [triple_to_three_strings(*one_triple) for one_triple in result_snapshot])

            self.assertTrue(result_events)

        finally:
            # The subprocess will exit anyway.
            if proc_open:
                proc_popen.kill()
                proc_popen.communicate()
                proc_popen.terminate()


if __name__ == '__main__':
    unittest.main()

