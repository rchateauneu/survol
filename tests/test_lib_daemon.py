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
import lib_util
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


def _supervisor_reset():
    """This is used between tests involving the supervisor and evets processes,
    because triples from the former tests might be written, if the daemons are still here."""
    daemon_factory.supervisor_stop()
    daemon_factory.supervisor_startup()
    # So the scripts started in daemon mode write their events in a shared graph.
    lib_common.set_events_credentials()


class CgiScriptTest(unittest.TestCase):
    _dummy_url_prefix = "http://any.machine/any_directory/"

    def setUp(self):
        # If a Survol agent does not run on this machine with this port, this script starts a local one.
        self._rdf_test_agent, self._agent_url = start_cgiserver(RemoteRdf1TestServerPort)

    def tearDown(self):
        stop_cgiserver(self._rdf_test_agent)

    def test_url_to_process_name(self):
        """This tests the transformation of a script URL into an unique process name."""
        test_url_a = self._dummy_url_prefix + "this_url_does_not_exist.py?arg=%d" % (os.getpid() + 1)
        process_name_a = lib_daemon._url_to_process_name(test_url_a)

        test_url_b = self._dummy_url_prefix + "this_url_does_not_exist.py?arg=%d" % (os.getpid() + 2)
        process_name_b = lib_daemon._url_to_process_name(test_url_b)
        self.assertNotEqual(process_name_a, process_name_b)

        result_url_a = lib_daemon._process_name_to_url(process_name_a)
        self.assertEqual(test_url_a, result_url_a)

        result_url_b = lib_daemon._process_name_to_url(process_name_b)
        self.assertEqual(test_url_b, result_url_b)

    def test_is_events_feeder_daemon_not_running(self):
        test_url = self._dummy_url_prefix + "non_existent_url.py?arg=%d" % os.getpid()
        status_running = lib_daemon.is_events_feeder_daemon_running(test_url)
        self.assertTrue(not status_running)

    @unittest.skipIf(is_platform_windows and is_travis_machine(), "FIXME: This hangs")
    def test_start_events_feeder_daemon(self):
        # http://vps516494.ovh.net/Survol/survol/sources_types/enumerate_CIM_Process.py?xid=.
        test_url = self._dummy_url_prefix + "/survol/sources_types/events_feeder_one_tick_per_second.py?parama=123&paramb=START"

        created_process_id = lib_daemon.start_events_feeder_daemon(test_url)

        content_stdout = lib_daemon.get_events_feeder_stdout(test_url)
        print("content_stdout=", content_stdout)

        content_stderr = lib_daemon.get_events_feeder_stderr(test_url)
        print("content_stderr=", content_stderr)

        self.assertTrue(psutil.pid_exists(created_process_id))

        # PYTEST_CURRENT_TEST= tests/test_lib_daemon.py::CgiScriptTest::test_start_events_feeder_daemon
        print("PYTEST_CURRENT_TEST=", os.environ["PYTEST_CURRENT_TEST"])

        self.assertTrue(created_process_id)

        status_running = lib_daemon.is_events_feeder_daemon_running(test_url)
        content_stdout = lib_daemon.get_events_feeder_stdout(test_url)
        print("content_stdout=", content_stdout)

        content_stderr = lib_daemon.get_events_feeder_stderr(test_url)
        print("content_stderr=", content_stderr)

        self.assertTrue(status_running)
        content_stdout = lib_daemon.get_events_feeder_stdout(test_url)
        print("content_stdout=", content_stdout)

        content_stderr = lib_daemon.get_events_feeder_stderr(test_url)
        print("content_stderr=", content_stderr)

        self.assertTrue(psutil.pid_exists(created_process_id))
        time.sleep(1)
        content_stdout = lib_daemon.get_events_feeder_stdout(test_url)
        print("content_stdout=", content_stdout)

        content_stderr = lib_daemon.get_events_feeder_stderr(test_url)
        print("content_stderr=", content_stderr)

        self.assertTrue(psutil.pid_exists(created_process_id))

        content_stdout = lib_daemon.get_events_feeder_stdout(test_url)
        print("content_stdout=", content_stdout)

        content_stderr = lib_daemon.get_events_feeder_stderr(test_url)
        print("content_stderr=", content_stderr)

        status_stopped = lib_daemon.stop_events_feeder_daemon(test_url)
        self.assertTrue(status_stopped)
        # Supervisor may need a bit of time to stop the user process.
        time.sleep(3)
        self.assertFalse(psutil.pid_exists(created_process_id))

    def test_start_events_feeder_non_daemon(self):
        """Events generator must return something even if started in non-daemon mode."""
        # http://vps516494.ovh.net/Survol/survol/sources_types/enumerate_CIM_Process.py?xid=.

        script_suffix = "events_feeder_one_tick_per_second.py?parama=456&paramb=START&mode=html"
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
    print("rdf_url=", rdf_url, "len(result_graph)=", len(result_graph))
    return result_graph


def _triple_to_three_strings(*one_triple):
    """This helper function is used to transform nodes into strings. Nodes are not uniquely generated."""
    return str(one_triple[0]), str(one_triple[1]), str(one_triple[2])


def _check_events_feeder_psutil_processes_perf(test_object, text_message, result_graph):
    """This checks the result of events_feeder_psutil_processes_perf.py"""

    test_object.assertTrue(result_graph)
    print(text_message, "len(result_graph)=", len(result_graph))
    print("CurrentPid=", CurrentPid, "CurrentParentPid=", CurrentParentPid)
    property_process_perf = lib_properties.MakeProp("Processes performances")

    def check_one_process(process_id):
        # There should be at least one sample. Normally only one if this is a snapshot,
        # but this is not an important constraint.
        print(text_message, "Checking process", process_id)
        process_node = test_object._agent_box().UriMakeFromDict("CIM_Process", {"Handle": process_id})
        samples_number = 0
        for _, _, sample_root_node in result_graph.triples((process_node, property_process_perf, None)):
            def check_present(property_name):
                print("Checking property", property_name)
                """Now look for some randomly-chosen counters which must be here on all platforms."""
                property_node = lib_properties.MakeProp(property_name)
                value_triples_list = list(result_graph.triples((sample_root_node, property_node, None)))
                test_object.assertEqual(len(value_triples_list), 1)
                test_object.assertEqual(type(value_triples_list[0][2]), rdflib.Literal)

            print("Checking sample", sample_root_node)
            check_present("cpu")
            check_present("rss")
            check_present("vms")
            samples_number += 1
        print(text_message, "pid=", process_id, "samples number=", samples_number)
        if samples_number == 0:
            def _simpler(the_node):
                cleaner_str = str(the_node)
                cleaner_str = cleaner_str.replace("http://www.primhillcomputers.com/survol", "")
                cleaner_str = cleaner_str.replace(test_object._agent_url + "/survol", "")
                return cleaner_str

            for a, b, c in result_graph:
                print("    ", _simpler(a), _simpler(b), _simpler(c))
        test_object.assertTrue(samples_number >= 1)

    property_process_handle = lib_properties.MakeProp("Handle")

    # This lists processes with available data.
    process_handles_list = sorted([
        int(process_id)
        for process_node, _, process_id
        in result_graph.triples((None, property_process_handle, None))])
    print("Process handles=", len(process_handles_list), process_handles_list)

    samples_list = sorted([
        process_node
        for process_node, _, sample_node
        in result_graph.triples((None, property_process_perf, None))])
    print("Samples=", len(samples_list))

    test_object.assertTrue(CurrentPid in process_handles_list)
    test_object.assertTrue(CurrentParentPid in process_handles_list)

    # The node of the current process must be in the detected processes.
    check_one_process(CurrentPid)

    # The node of the parent process must be in the detected processes.
    check_one_process(CurrentParentPid)


def _check_events_feeder_psutil_system_counters(test_object, text_message, result_graph):
    """This checks the result of events_feeder_psutil_system_counters.py"""

    # The result should not be empty, and contain at least a couple of triples.
    test_object.assertTrue(result_graph)
    print(text_message, "len(result_graph)=", len(result_graph))

    samples_number = 0

    # There should be at least one sample. Normally only one if this is a snapshot,
    # but this is not an important constraint.
    property_system_counters = lib_properties.MakeProp("system_counters")
    for host_node, _, sample_node in result_graph.triples((None, property_system_counters, None)):
        def check_present(property_name):
            """Now look for some randomly-chosen counters which must be here on all platforms."""
            property_node = lib_properties.MakeProp(property_name)
            value_triples_list = list(result_graph.triples((sample_node, property_node, None)))
            test_object.assertEqual(len(value_triples_list), 1)
            test_object.assertEqual(type(value_triples_list[0][2]), rdflib.Literal)

        check_present("disk_io_counters.read_count")
        check_present("virtual_memory.free")
        check_present("net_io_counters.errin")
        samples_number += 1
    test_object.assertTrue(samples_number >= 1)
    print(text_message, "samples number=", samples_number)


def _check_events_feeder_win32_dir_changes(test_object, text_message, result_graph, updated_files):
    test_object.assertTrue(result_graph)
    print(text_message, "len(result_graph)=", len(result_graph))
    print("updated_files=", updated_files)

    property_notified_file_change = lib_properties.MakeProp("file change")
    property_notified_change_type = lib_properties.MakeProp("change type")

    found_files = set()

    for one_updated_file in updated_files:
        print("one_updated_file=", one_updated_file)
        node_path = test_object._agent_box().FileUri(one_updated_file)
        for _, _, sample_root_node in result_graph.triples((node_path, property_notified_file_change, None)):
            for _, _, action_node in result_graph.triples((sample_root_node, property_notified_change_type, None)):
                print("Updated file:", one_updated_file, "action=", action_node)
                found_files.add(one_updated_file)
    test_object.assertEqual(sorted(updated_files), sorted(list(found_files)))


class CgiScriptIOMemoryStartOnlyTest(unittest.TestCase):
    """This tests all known events generator and at least checks if they start and stop properly.
    They expect that the supervisor is freshly started and do not contain events.
    Many tests also work even if the scripts immediately exit for whatever reason."""

    def setUp(self):
        # If a Survol agent does not run on this machine with this port, this script starts a local one.
        _supervisor_reset()
        lib_kbase.clear_all_events()
        self._rdf_test_agent, self._agent_url = start_cgiserver(RemoteRdf2TestServerPort)
        print("AgentUrl=", self._agent_url)
        lib_kbase.set_storage_style("IOMemory",)

    def tearDown(self):
        stop_cgiserver(self._rdf_test_agent)
        lib_kbase.clear_all_events()
        lib_kbase.set_storage_style(None,)

    def _agent_box(self):
        agent_prefix = self._agent_url + "/survol"
        return lib_common.OtherAgentBox(agent_prefix)

    def _run_script_as_snapshot(self, script_suffix):
        """This runs the script just once, in snapshot mode. The url must not contain the mode. """
        full_url = self._agent_url + "/survol/sources_types/" + script_suffix
        graph_daemon_result_snapshot = _run_daemon_script_in_snapshot_mode(full_url)
        return graph_daemon_result_snapshot

    def test_events_feeder_psutil_processes_perf(self):
        url_suffix = "events_feeder_psutil_processes_perf.py"
        result_snapshot = self._run_script_as_snapshot(url_suffix)
        _check_events_feeder_psutil_processes_perf(self, "Snapshot only", result_snapshot)

    # @unittest.skipIf(is_platform_windows and is_travis_machine(), "FIXME: Broken on Windows and Travis")
    def test_events_feeder_psutil_system_counters(self):
        url_suffix = "events_feeder_psutil_system_counters.py"
        result_snapshot = self._run_script_as_snapshot(url_suffix)
        _check_events_feeder_psutil_system_counters(self, "Snapshot only", result_snapshot)

    @unittest.skipIf(is_platform_windows and is_travis_machine(), "Windows and Travis do not work. WHY ? FIXME.")
    def test_events_feeder_sockets_promiscuous_mode(self):
        url_suffix = "events_feeder_sockets_promiscuous_mode.py"
        result_snapshot = self._run_script_as_snapshot(url_suffix)
        self.assertTrue(result_snapshot)

    @unittest.skipIf(is_platform_linux and is_travis_machine(), "Linux and Travis do not work. WHY ? FIXME.")
    def test_events_feeder_tcpdump(self):
        url_suffix = "events_feeder_tcpdump.py"
        result_snapshot = self._run_script_as_snapshot(url_suffix)
        self.assertTrue(result_snapshot)

    @unittest.skipIf(is_platform_linux or is_travis_machine(), "Windows only")
    def test_events_feeder_win32_dir_changes(self):
        """There is not much activity in these directories: The goal is to test that the script starts correctly."""
        checked_directory = lib_util.global_temp_directory
        url_suffix = "CIM_Directory/events_feeder_win32_dir_changes.py?xid=CIM_Directory.Name=%s" \
                   % checked_directory
        result_snapshot = self._run_script_as_snapshot(url_suffix)
        self.assertTrue(result_snapshot)

    @unittest.skipIf(is_platform_windows and is_travis_machine(), "FIXME: Broken on Windows and Travis")
    def test_events_feeder_system_calls_sleep(self):
        proc_open = None
        try:
            # This starts a dummy process, whose system calls will be monitored.
            subprocess_command = [
                sys.executable,
                "-c",
                "import time;time.sleep(5)"]
            sys.stderr.write("test_events_feeder_system_calls supervisor_command=%s\n" % subprocess_command)

            # No Shell, otherwise we cannot know which process is created.
            proc_popen = subprocess.Popen(
                subprocess_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)

            print("proc_popen.pid=%s\n" % proc_popen.pid)

            # This node must be in the result. Dockit is run within a temporary agent,
            # therefore this agent is used as a URL for the created nodes.
            created_process_node = self._agent_box().UriMakeFromDict("CIM_Process", {"Handle": proc_popen.pid})
            literal_pid = rdflib.Literal(proc_popen.pid)

            url_suffix = "CIM_Process/events_feeder_system_calls.py?xid=CIM_Process.Handle=%d" % proc_popen.pid
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

    @unittest.skipIf(is_platform_windows, "Windows only")
    @unittest.skipIf(is_travis_machine(), "FIXME: Broken Travis")
    def test_events_feeder_iostat_all_disks(self):
        url_suffix = "Linux/events_feeder_iostat_all_disks.py"
        daemon_result = self._run_script_as_snapshot(url_suffix)
        self.assertTrue(daemon_result)

    def test_events_feeder_vmstat(self):
        url_suffix = "Linux/events_feeder_vmstat.py"
        daemon_result = self._run_script_as_snapshot(url_suffix)
        self.assertTrue(daemon_result)


class CgiScriptStartThenEventsTest(unittest.TestCase):
    """This tests scripts which also return events and stay running for a long time."""

    def setUp(self):
        # If a Survol agent does not run on this machine with this port, this script starts a local one.
        _supervisor_reset()
        lib_kbase.clear_all_events()
        self._rdf_test_agent, self._agent_url = start_cgiserver(RemoteRdf4TestServerPort)
        print("AgentUrl=", self._agent_url)

        # A shared database is needed because several processes use it simultaneously.
        # When reading the events, this uses the default SQLAlchemy database also used by the CGI scripts.
        lib_common.set_events_credentials()

    def tearDown(self):
        stop_cgiserver(self._rdf_test_agent)
        lib_kbase.clear_all_events()
        lib_kbase.set_storage_style(None,)

    def _agent_box(self):
        return lib_common.OtherAgentBox(self._agent_url + "/survol")

    def _run_script_snapshot_then_events(self, script_suffix, events_delay):
        # The url must not contain the mode
        local_url = "/survol/sources_types/" + script_suffix
        full_url = self._agent_url + local_url

        # This takes the first result as a snapshot. A supervisor deamon process is also styarted,
        # running the same script in a loop, and storing the results in a graph database.
        graph_daemon_result_snapshot = _run_daemon_script_in_snapshot_mode(full_url)

        # The result should not be empty, and contain at least a couple of triples.
        self.assertTrue(graph_daemon_result_snapshot)
        # graph_daemon_result_snapshot= [a rdfg:Graph;rdflib:storage [a rdflib:Store;rdfs:label 'IOMemory']].
        print("Snapshot triples count=", len(graph_daemon_result_snapshot))

        # This gives time to the daemon process, to store events in the graph database.
        print("Waiting", events_delay, "seconds.")
        time.sleep(events_delay)

        # Now, the daemon process must have been started and must still be running.
        is_daemon_running = lib_daemon.is_events_feeder_daemon_running(local_url)
        self.assertTrue(is_daemon_running)

        graph_daemon_result_events = _run_daemon_script_in_snapshot_mode(full_url)

        # This fetches the events stored in the graph database by the daemon process.
        print("Snapshot triples count=", len(graph_daemon_result_events))

        return graph_daemon_result_snapshot, graph_daemon_result_events

    @unittest.skipIf(is_platform_windows and is_travis_machine(), "FIXME: Broken on Windows and Travis")
    def test_events_feeder_psutil_processes_perf(self):
        url_suffix = "events_feeder_psutil_processes_perf.py"
        result_snapshot, result_events = self._run_script_snapshot_then_events(url_suffix, 20)
        _check_events_feeder_psutil_processes_perf(self, "Snapshot before events", result_snapshot)
        _check_events_feeder_psutil_processes_perf(self, "Events", result_events)

    @unittest.skipIf(is_platform_windows and is_travis_machine(), "FIXME: Broken on Windows and Travis")
    def test_events_feeder_psutil_system_counters(self):
        """This script is already tested, as a snapshot."""
        url_suffix = "events_feeder_psutil_system_counters.py"
        result_snapshot, result_events = self._run_script_snapshot_then_events(url_suffix, 20)
        _check_events_feeder_psutil_system_counters(self, "Snapshot before events", result_snapshot)
        _check_events_feeder_psutil_system_counters(self, "Events", result_snapshot)

    #@unittest.skipIf(is_platform_linux or is_travis_machine(), "Windows only")
    @unittest.skipIf(is_platform_linux, "Windows only")
    def test_events_feeder_win32_dir_changes(self):
        """This starts events_feeder_win32_dir_changes, updates a file and checks if this is detected."""
        checked_directory = lib_util.global_temp_directory
        url_suffix = "CIM_Directory/events_feeder_win32_dir_changes.py?xid=CIM_Directory.Name=%s" \
                     % checked_directory

        windows_changed_file = os.path.join(checked_directory, "file_created_%d.tmp" % os.getpid())
        windows_changed_file = windows_changed_file.replace("\\", "/")
        print("windows_changed_file=", windows_changed_file)

        # This creates a subprocess which creates then updates a file several times.
        # It does not write to stdout, so no need of communicate().
        # This processes starts immediately while we are querying the CGI script.
        py_cmd = "import time;[(time.sleep(1),open(r'%s','w'),) for i in range(30)]" % windows_changed_file

        print("test_events_feeder_win32_dir_changes py_cmd=%s" % py_cmd)
        subprocess_command = [
            sys.executable,
            "-c",
            py_cmd]
        print("test_events_feeder_win32_dir_changes supervisor_command=%s" % subprocess_command)

        proc_popen = subprocess.Popen(
            subprocess_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

        result_snapshot, result_events = self._run_script_snapshot_then_events(url_suffix, 5)

        _check_events_feeder_win32_dir_changes(self, "Snapshot before events", result_snapshot, [])
        _check_events_feeder_win32_dir_changes(self, "Events", result_events, [windows_changed_file])

    def test_events_feeder_system_calls_loop(self):
        proc_open = None
        try:
            # This starts a dummy process, whose system calls will be monitored.
            temporary_python_file_name = unique_temporary_path("test_events_feeder_system_calls_loop", ".py")
            script_content = """\
import time
time.sleep(10)
import os
print("cwd=", os.getcwd())
"""
            with open(temporary_python_file_name, "w") as temporary_python_file_fd:
                temporary_python_file_fd.write(script_content)

            subprocess_command = [
                sys.executable,
                temporary_python_file_name]
            print("test_events_feeder_system_calls_loop supervisor_command=%s" % subprocess_command)

            # No Shell, otherwise we cannot know which process is created.
            proc_popen = subprocess.Popen(
                subprocess_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)

            print("proc_popen.pid=%s\n" % proc_popen.pid)

            # This node must be in the result. Dockit is run within a temporary agent,
            # therefore this agent is used as a URL for the created nodes.
            agent_prefix = self._agent_url + "/survol"
            created_process_node = lib_common.OtherAgentBox(agent_prefix).UriMakeFromDict(
                "CIM_Process", {"Handle": proc_popen.pid})
            literal_pid = rdflib.Literal(proc_popen.pid)

            url_suffix = "CIM_Process/events_feeder_system_calls.py?xid=CIM_Process.Handle=%d" % proc_popen.pid
            # This attaches to the subprocess and gets its system calls.
            result_snapshot, result_events = self._run_script_snapshot_then_events(url_suffix, 10)

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

            print("result_events=", result_events)
            for a, b, c in result_events:
                print("    ", a, b, c)

        finally:
            # The subprocess will exit anyway.
            if proc_open:
                proc_popen.kill()
                proc_popen.communicate()
                proc_popen.terminate()


if __name__ == '__main__':
    unittest.main()

