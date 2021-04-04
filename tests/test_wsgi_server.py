#!/usr/bin/env python

from __future__ import print_function

"""This starts a local WSGI server and runs several queries and tests that the results are the same."""

import cgitb
import unittest
import subprocess

from init import *

update_test_path()

# TODO: This should be a parameter.
# It points to the Survol adhoc WSGI server: "http://rchateau-hp:9000"
_remote_wsgi_test_port = RemoteWsgi1TestServerPort
#_remote_wsgi_test_agent = "http://%s:%d" % (CurrentMachine, _remote_wsgi_test_port)
_remote_wsgi_test_agent = None

# If the Survol agent does not exist, this script starts a local one.
_remote_wsgi_agent_process = None

def setUpModule():
    global _remote_wsgi_agent_process
    global _remote_wsgi_test_agent
    _remote_wsgi_agent_process, _remote_wsgi_test_agent = start_wsgiserver(_remote_wsgi_test_port)


def tearDownModule():
    global _remote_wsgi_agent_process
    stop_wsgiserver(_remote_wsgi_agent_process)


import lib_client

# Otherwise, Python callstack would be displayed in HTML.
cgitb.enable(format="txt")


class WsgiLocalTest(unittest.TestCase):
    """Just runs locally without any network connection. This does not start the server by importing
    it as a module, but instead starts it from the Shell or as a DOS command."""
    def test_wsgiserver_help(self):
        """Check content of help command"""
        wsgi_help_command = [sys.executable, "survol/scripts/wsgiserver.py", "--help"]
        command_result = subprocess.check_output(wsgi_help_command)
        print("WSGI help:", command_result)
        self.assertTrue(command_result.startswith(b"Survol WSGI server"))


class WsgiRemoteTest(unittest.TestCase):
    """Test involving remote Survol agents: The scripts executes scripts on remote machines
    and examines the result. It might merge the output with local scripts or scripts on different machines."""

    def test_wsgi_file_stat_json(self):
        # http://the_host:8000/survol/sources_types/CIM_DataFile/file_stat.py?xid=CIM_DataFile.Name%3DC%3A%2FWindows%2Fexplorer.exe
        my_source_file_stat_remote = lib_client.SourceRemote(
            _remote_wsgi_test_agent + "/survol/sources_types/CIM_DataFile/file_stat.py",
            "CIM_DataFile",
            Name=always_present_file)
        print("URL=", my_source_file_stat_remote.Url())
        print("Query=", my_source_file_stat_remote.create_url_query())
        json_content = my_source_file_stat_remote.content_json()

        dir_file_always_there = os.path.basename(always_present_dir)
        base_file_always_there = os.path.basename(always_present_file)

        # "No doc explorer.exe"
        # "File stat information..."
        json_title = json_content['page_title']
        print("json_title=", json_title)

        self.assertTrue(json_title.startswith("File stat information"), "Incorrect title:" + json_title)

        found_file = False
        found_dir = False
        json_nodes = json_content['nodes']
        for one_node in json_nodes:
            print("test_wsgi_file_stat_json one_node=",one_node)
            node_entity_class = one_node['entity_class']
            node_name = one_node['name']
            if not found_file:
                # {u'entity_class': u'CIM_DataFile', u'name': u'explorer.exe' }
                found_file = node_entity_class == 'CIM_DataFile' and node_name == base_file_always_there
            if not found_dir:
                # {u'entity_class': u'CIM_Directory', u'name': u'Windows/'}
                found_dir = node_entity_class == 'CIM_Directory' and node_name == dir_file_always_there + "/"

        self.assertTrue(found_file, "Could not find file:" + always_present_file)
        self.assertTrue(found_dir, "Could not find directory:" + dir_file_always_there)


        # json_links= [
        # {
        # u'survol_link_prop': u'directory',
        # u'source': u'http://rchateau-hp:9000/survol/entity.py?xid=CIM_Directory.Name=C%3A%2FWindows',
        # u'target': u'http://rchateau-hp:9000/survol/entity.py?xid=CIM_DataFile.Name=C%3A%2FWindows%2Fexplorer.exe'},
        json_links = json_content['links']
        link_found = False
        for one_link in json_links:
            if one_link['survol_link_prop'] == 'directory' \
                    and one_link['source'].endswith(dir_file_always_there) \
                    and one_link['target'].endswith(base_file_always_there):
                link_found = True
                break
        self.assertTrue(link_found, "Could not find edge between file and directory")

    def test_wsgi_file_stat_rdf(self):
        # http://rchateau-hp:8000/survol/sources_types/CIM_DataFile/file_stat.py?xid=CIM_DataFile.Name%3DC%3A%2FWindows%2Fexplorer.exe
        my_source_file_stat_remote = lib_client.SourceRemote(
            _remote_wsgi_test_agent + "/survol/sources_types/CIM_DataFile/file_stat.py",
            "CIM_DataFile",
            Name=always_present_file)

        clean_file_always_there = lib_util.standardized_file_path(always_present_file)
        dir_file_always_there = lib_util.standardized_file_path(always_present_dir)

        print("URL=", my_source_file_stat_remote.Url())
        print("Query=", my_source_file_stat_remote.create_url_query())
        data_triplestore = my_source_file_stat_remote.get_triplestore()

        # CIM_Directory.Name=C:/Windows
        # CIM_DataFile.Name=C:/Windows/explorer.exe
        # Win32_Group.Name=TrustedInstaller,Domain=NT SERVICE
        # CIM_Directory.Name=C:/
        list_instances = data_triplestore.get_instances()

        found_file = False
        found_dir = False
        for one_instance in list_instances:
            print("test_wsgi_file_stat_rdf one_instance=", one_instance)
            if not found_dir:
                found_dir = str(one_instance) == "CIM_Directory.Name=" + dir_file_always_there
            if not found_file:
                found_file = str(one_instance) == "CIM_DataFile.Name=" + clean_file_always_there

        self.assertTrue(found_dir, "Cannot find directory:" + dir_file_always_there)
        self.assertTrue(found_file, "Cannot find file:" + always_present_file)

    def test_wsgi_file_directory(self):
        my_source_file_stat_remote = lib_client.SourceRemote(
            _remote_wsgi_test_agent + "/survol/sources_types/CIM_Directory/file_directory.py",
            "CIM_Directory",
            Name=always_present_dir)
        triple_file_stat_remote = my_source_file_stat_remote.get_triplestore()
        print("Len triple_file_stat_remote=", len(triple_file_stat_remote))
        # This should not be empty.
        self.assertTrue(len(triple_file_stat_remote) >= 1)


@unittest.skipIf(not is_platform_linux, "Linux only.")
class WsgiLinuxRemoteTest(unittest.TestCase):
    def test_etc_group(self):
        my_source_file_stat_remote = lib_client.SourceRemote(
            _remote_wsgi_test_agent + "/survol/sources_types/Linux/etc_group.py")
        triple_file_stat_remote = my_source_file_stat_remote.get_triplestore()
        print("Len triple_file_stat_remote=", len(triple_file_stat_remote))
        # This should not be empty.
        self.assertTrue(len(triple_file_stat_remote) >= 1)

    def test_enumerate_user(self):
        my_source_file_stat_remote = lib_client.SourceRemote(
            _remote_wsgi_test_agent + "/survol/sources_types/Linux/enumerate_user.py")
        triple_file_stat_remote = my_source_file_stat_remote.get_triplestore()
        print("Len triple_file_stat_remote=", len(triple_file_stat_remote))
        # This should not be empty.
        self.assertTrue(len(triple_file_stat_remote) >= 1)

    def test_etc_mtab(self):
        my_source_file_stat_remote = lib_client.SourceRemote(
            _remote_wsgi_test_agent + "/survol/sources_types/Linux/etc_mtab.py")
        triple_file_stat_remote = my_source_file_stat_remote.get_triplestore()
        print("Len triple_file_stat_remote=", len(triple_file_stat_remote))
        # This should not be empty.
        self.assertTrue(len(triple_file_stat_remote) >= 1)

    def test_etc_passwd(self):
        my_source_file_stat_remote = lib_client.SourceRemote(
            _remote_wsgi_test_agent + "/survol/sources_types/Linux/etc_passwd.py")
        triple_file_stat_remote = my_source_file_stat_remote.get_triplestore()
        print("Len triple_file_stat_remote=", len(triple_file_stat_remote))
        # This should not be empty.
        self.assertTrue(len(triple_file_stat_remote) >= 1)

    @unittest.skipIf(not pkgutil.find_loader('rpm'), "test_rpm_packages needs rpm package.")
    def test_rpm_packages(self):
        my_source_file_stat_remote = lib_client.SourceRemote(
            _remote_wsgi_test_agent + "/survol/sources_types/Linux/installed_rpm_packages.py")
        triple_file_stat_remote = my_source_file_stat_remote.get_triplestore()
        print("Len triple_file_stat_remote=", len(triple_file_stat_remote))
        # This should not be empty.
        self.assertTrue(len(triple_file_stat_remote) >= 1)

    def test_modules_dependencies(self):
        my_source_file_stat_remote = lib_client.SourceRemote(
            _remote_wsgi_test_agent + "/survol/sources_types/Linux/modules_dependencies.py")
        triple_file_stat_remote = my_source_file_stat_remote.get_triplestore()
        print("Len triple_file_stat_remote=", len(triple_file_stat_remote))
        # This should not be empty.
        self.assertTrue(len(triple_file_stat_remote) >= 1)

    def test_proc_cgroup(self):
        my_source_file_stat_remote = lib_client.SourceRemote(
            _remote_wsgi_test_agent + "/survol/sources_types/Linux/proc_cgroup.py")
        triple_file_stat_remote = my_source_file_stat_remote.get_triplestore()
        print("Len triple_file_stat_remote=", len(triple_file_stat_remote))
        # This should not be empty.
        self.assertTrue(len(triple_file_stat_remote) >= 1)

    def test_tcp_sockets(self):
        my_source_file_stat_remote = lib_client.SourceRemote(
            _remote_wsgi_test_agent + "/survol/sources_types/Linux/tcp_sockets.py")
        triple_file_stat_remote = my_source_file_stat_remote.get_triplestore()
        print("Len triple_file_stat_remote=", len(triple_file_stat_remote))
        # This should not be empty.
        self.assertTrue(len(triple_file_stat_remote) >= 1)

    def test_unix_domain_sockets(self):
        my_source_file_stat_remote = lib_client.SourceRemote(
            _remote_wsgi_test_agent + "/survol/sources_types/Linux/unix_domain_sockets.py")
        triple_file_stat_remote = my_source_file_stat_remote.get_triplestore()
        print("Len triple_file_stat_remote=", len(triple_file_stat_remote))
        # This should not be empty.
        self.assertTrue(len(triple_file_stat_remote) >= 1)


if __name__ == '__main__':
    unittest.main()

# TODO: Test calls to <Any class>.AddInfo()
# TODO: When double-clicking any Python script, it should do something visible.
