#!/usr/bin/env python

from __future__ import print_function

import cgitb
import unittest
import sys
import os
import re
import time
import socket
import json
import atexit

# This starts a local WSGI server and runs several queries and tests that the results are the same.

from init import *

update_test_path()

# TODO: This should be a parameter.
# It points to the Survol adhoc WSGI server: "http://rchateau-hp:9000"
RemoteWsgiTestPort = 9000
RemoteWsgiTestAgent = "http://%s:%d" % (CurrentMachine, RemoteWsgiTestPort)

# If the Survol agent does not exist, this script starts a local one.
RemoteWsgiAgentProcess = None

def setUpModule():
    global RemoteWsgiAgentProcess
    RemoteWsgiAgentProcess = WsgiAgentStart(RemoteWsgiTestAgent, RemoteWsgiTestPort)


def tearDownModule():
    global RemoteWsgiAgentProcess
    WsgiAgentStop(RemoteWsgiAgentProcess)


isVerbose = ('-v' in sys.argv) or ('--verbose' in sys.argv)

import lib_client

ClientObjectInstancesFromScript = lib_client.SourceLocal.GetObjectInstancesFromScript

# Otherwise, Python callstack would be displayed in HTML.
cgitb.enable(format="txt")

# Many tests start a subprocess: Its termination must be checked.
def CheckSubprocessEnd(procOpen):
    ( child_stdout_content, child_stderr_content ) = procOpen.communicate()

    if sys.platform.startswith("win"):
        # This ensures that the suprocess is correctly started.
        assert(child_stdout_content.startswith(b"Starting subprocess"))

        print("procOpen.returncode=",procOpen.returncode)
        assert(procOpen.returncode == 123)


# TODO: Prefix of url samples should be a parameter.

class WsgiRemoteTest(unittest.TestCase):
    """Test involving remote Survol agents: The scripts executes scripts on remote machines
    and examines the result. It might merge the output with local scripts or
    scripts on different machines."""

    def test_wsgi_file_stat_json(self):
        # http://rchateau-hp:8000/survol/sources_types/CIM_DataFile/file_stat.py?xid=CIM_DataFile.Name%3DC%3A%2FWindows%2Fexplorer.exe
        mySourceFileStatRemote = lib_client.SourceRemote(
            RemoteWsgiTestAgent + "/survol/sources_types/CIM_DataFile/file_stat.py",
            "CIM_DataFile",
            Name=FileAlwaysThere)
        print("urlFileStatRemote=",mySourceFileStatRemote.Url())
        print("qryFileStatRemote=",mySourceFileStatRemote.UrlQuery())
        json_content = mySourceFileStatRemote.content_json()

        dirFileAlwaysThere = os.path.basename(os.path.dirname(FileAlwaysThere))
        baseFileAlwaysThere = os.path.basename(FileAlwaysThere)

        # "No doc explorer.exe"
        # "File stat information..."
        json_title = json_content['page_title']
        print("json_title=",json_title)

        self.assertTrue( json_title.startswith("File stat information"), "Incorrect title:"+json_title)

        found_file = False
        found_dir = False
        json_nodes = json_content['nodes']
        for one_node in json_nodes:
            print("test_wsgi_file_stat_json one_node=",one_node)
            if not found_file:
                # {u'entity_class': u'CIM_DataFile', u'name': u'explorer.exe' }
                found_file = one_node['entity_class'] == 'CIM_DataFile' and one_node['name'] == baseFileAlwaysThere
            if not found_dir:
                # {u'entity_class': u'CIM_Directory', u'name': u'Windows/'}
                found_dir = one_node['entity_class'] == 'CIM_Directory' and one_node['name'] == dirFileAlwaysThere + "/"

        self.assertTrue(found_file, "Could not find file:" + FileAlwaysThere)
        self.assertTrue(found_dir, "Could not find directory:" + dirFileAlwaysThere)


        # json_links= [
        # {
        # u'survol_link_prop': u'directory',
        # u'source': u'http://rchateau-hp:9000/survol/entity.py?xid=CIM_Directory.Name=C%3A%2FWindows',
        # u'target': u'http://rchateau-hp:9000/survol/entity.py?xid=CIM_DataFile.Name=C%3A%2FWindows%2Fexplorer.exe'},
        json_links = json_content['links']
        link_found = False
        for one_link in json_links:
            if one_link['survol_link_prop'] == 'directory' \
                    and one_link['source'].endswith(dirFileAlwaysThere) \
                    and one_link['target'].endswith(baseFileAlwaysThere):
                link_found = True
                break
        self.assertTrue(link_found, "Could not find edge between file and directory")

    def test_wsgi_file_stat_rdf(self):
        # http://rchateau-hp:8000/survol/sources_types/CIM_DataFile/file_stat.py?xid=CIM_DataFile.Name%3DC%3A%2FWindows%2Fexplorer.exe
        mySourceFileStatRemote = lib_client.SourceRemote(
            RemoteWsgiTestAgent + "/survol/sources_types/CIM_DataFile/file_stat.py",
            "CIM_DataFile",
            Name=FileAlwaysThere)

        cleanFileAlwaysThere = FileAlwaysThere.replace("\\","/")
        dirFileAlwaysThere = os.path.dirname(FileAlwaysThere).replace("\\","/")

        print("urlFileStatRemote=",mySourceFileStatRemote.Url())
        print("qryFileStatRemote=",mySourceFileStatRemote.UrlQuery())
        data_triplestore = mySourceFileStatRemote.GetTriplestore()

        # CIM_Directory.Name=C:/Windows
        # CIM_DataFile.Name=C:/Windows/explorer.exe
        # Win32_Group.Name=TrustedInstaller,Domain=NT SERVICE
        # CIM_Directory.Name=C:/
        list_instances = data_triplestore.GetInstances()

        found_file = False
        found_dir = False
        for one_instance in list_instances:
            print("test_wsgi_file_stat_rdf one_instance=", one_instance)
            if not found_dir:
                found_dir = str(one_instance) == "CIM_Directory.Name=" + dirFileAlwaysThere
            if not found_file:
                found_file = str(one_instance) == "CIM_DataFile.Name=" + cleanFileAlwaysThere

        self.assertTrue(found_dir, "Cannot find directory:" + dirFileAlwaysThere)
        self.assertTrue(found_file, "Cannot find file:" + FileAlwaysThere)

    def test_wsgi_file_directory(self):
        mySourceFileStatRemote = lib_client.SourceRemote(
            RemoteWsgiTestAgent + "/survol/sources_types/CIM_Directory/file_directory.py",
            "CIM_Directory",
            Name=DirAlwaysThere)
        tripleFileStatRemote = mySourceFileStatRemote.GetTriplestore()
        print("Len tripleFileStatRemote=",len(tripleFileStatRemote))
        # This should not be empty.
        self.assertTrue(len(tripleFileStatRemote)>=1)

class WsgiLinuxRemoteTest(unittest.TestCase):

    @unittest.skipIf(not is_platform_linux, "test_etc_group for Linux only.")
    def test_etc_group(self):
        mySourceFileStatRemote = lib_client.SourceRemote(
            RemoteWsgiTestAgent + "/survol/sources_types/Linux/etc_group.py")
        tripleFileStatRemote = mySourceFileStatRemote.GetTriplestore()
        print("Len tripleFileStatRemote=",len(tripleFileStatRemote))
        # This should not be empty.
        self.assertTrue(len(tripleFileStatRemote)>=1)

    @unittest.skipIf(not is_platform_linux, "test_enumerate_user for Linux only.")
    def test_enumerate_user(self):
        mySourceFileStatRemote = lib_client.SourceRemote(
            RemoteWsgiTestAgent + "/survol/sources_types/Linux/enumerate_user.py")
        tripleFileStatRemote = mySourceFileStatRemote.GetTriplestore()
        print("Len tripleFileStatRemote=",len(tripleFileStatRemote))
        # This should not be empty.
        self.assertTrue(len(tripleFileStatRemote)>=1)

    @unittest.skipIf(not is_platform_linux, "test_etc_mtab for Linux only.")
    def test_etc_mtab(self):
        mySourceFileStatRemote = lib_client.SourceRemote(
            RemoteWsgiTestAgent + "/survol/sources_types/Linux/etc_mtab.py")
        tripleFileStatRemote = mySourceFileStatRemote.GetTriplestore()
        print("Len tripleFileStatRemote=",len(tripleFileStatRemote))
        # This should not be empty.
        self.assertTrue(len(tripleFileStatRemote)>=1)

    @unittest.skipIf(not is_platform_linux, "test_etc_passwd for Linux only.")
    def test_etc_passwd(self):
        mySourceFileStatRemote = lib_client.SourceRemote(
            RemoteWsgiTestAgent + "/survol/sources_types/Linux/etc_passwd.py")
        tripleFileStatRemote = mySourceFileStatRemote.GetTriplestore()
        print("Len tripleFileStatRemote=",len(tripleFileStatRemote))
        # This should not be empty.
        self.assertTrue(len(tripleFileStatRemote)>=1)

    @unittest.skipIf(not ( is_platform_linux and pkgutil.find_loader('rpm')) , "test_installed_rpm_packages for Linux only.")
    def test_installed_rpm_packages(self):
        mySourceFileStatRemote = lib_client.SourceRemote(
            RemoteWsgiTestAgent + "/survol/sources_types/Linux/installed_rpm_packages.py")
        tripleFileStatRemote = mySourceFileStatRemote.GetTriplestore()
        print("Len tripleFileStatRemote=",len(tripleFileStatRemote))
        # This should not be empty.
        self.assertTrue(len(tripleFileStatRemote)>=1)

    @unittest.skipIf(not is_platform_linux, "test_modules_dependencies for Linux only.")
    def test_modules_dependencies(self):
        mySourceFileStatRemote = lib_client.SourceRemote(
            RemoteWsgiTestAgent + "/survol/sources_types/Linux/modules_dependencies.py")
        tripleFileStatRemote = mySourceFileStatRemote.GetTriplestore()
        print("Len tripleFileStatRemote=",len(tripleFileStatRemote))
        # This should not be empty.
        self.assertTrue(len(tripleFileStatRemote)>=1)

    @unittest.skipIf(not is_platform_linux, "test_proc_cgroup for Linux only.")
    def test_proc_cgroup(self):
        mySourceFileStatRemote = lib_client.SourceRemote(
            RemoteWsgiTestAgent + "/survol/sources_types/Linux/proc_cgroup.py")
        tripleFileStatRemote = mySourceFileStatRemote.GetTriplestore()
        print("Len tripleFileStatRemote=",len(tripleFileStatRemote))
        # This should not be empty.
        self.assertTrue(len(tripleFileStatRemote)>=1)

    @unittest.skipIf(not is_platform_linux, "test_tcp_sockets for Linux only.")
    def test_tcp_sockets(self):
        mySourceFileStatRemote = lib_client.SourceRemote(
            RemoteWsgiTestAgent + "/survol/sources_types/Linux/tcp_sockets.py")
        tripleFileStatRemote = mySourceFileStatRemote.GetTriplestore()
        print("Len tripleFileStatRemote=",len(tripleFileStatRemote))
        # This should not be empty.
        self.assertTrue(len(tripleFileStatRemote)>=1)

    @unittest.skipIf(not is_platform_linux, "test_unix_domain_sockets for Linux only.")
    def test_unix_domain_sockets(self):
        mySourceFileStatRemote = lib_client.SourceRemote(
            RemoteWsgiTestAgent + "/survol/sources_types/Linux/unix_domain_sockets.py")
        tripleFileStatRemote = mySourceFileStatRemote.GetTriplestore()
        print("Len tripleFileStatRemote=",len(tripleFileStatRemote))
        # This should not be empty.
        self.assertTrue(len(tripleFileStatRemote)>=1)


if __name__ == '__main__':
    unittest.main()

# TODO: Test calls to <Any class>.AddInfo()
# TODO: When double-clicking any Python script, it should do something visible.
