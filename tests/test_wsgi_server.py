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

# This loads the module from the source, so no need to install it, and no need of virtualenv.
sys.path.insert(0,"../survol")

from init import *

# TODO: This should be a parameter.
# It points to the Survol adhoc WSGI server: "http://rchateau-hp:9000"
RemoteWsgiTestPort = 9000
RemoteWsgiTestAgent = "http://%s:%d" % (CurrentMachine, RemoteWsgiTestPort)

# If the Survol agent does not exist, this script starts a local one.
RemoteAgentProcess = None

def setUpModule():
    global RemoteAgentProcess
    print("setUpModule")
    try:
        # For Python 3.0 and later
        from urllib.request import urlopen as portable_urlopen
    except ImportError:
        # Fall back to Python 2's urllib2
        from urllib2 import urlopen as portable_urlopen

    try:
        # No SVG because Travis might not have dot/Graphviz. Also, the script must be compatible with WSGI.
        response = portable_urlopen(RemoteWsgiTestAgent + "/survol/entity.py?mode=json", timeout=5)
        print("Using existing Survol agent")
    except:
        import multiprocessing
        print("Starting test survol agent: RemoteWsgiTestAgent=", RemoteWsgiTestAgent, " hostname=", socket.gethostname())

        import scripts.wsgiserver
        # cwd = "PythonStyle/tests", must be "PythonStyle".
        # AgentHost = "127.0.0.1"
        AgentHost = socket.gethostname()
        try:
            # Running the tests scripts from PyCharm is from the current directory.
            os.environ["PYCHARM_HELPERS_DIR"]
            current_dir = ".."
        except KeyError:
            current_dir = ""
        print("current_dir=",current_dir)
        print("sys.path=",sys.path)

        atexit.register(ServerDumpContent,scripts.wsgiserver.WsgiServerLogFileName )

        RemoteAgentProcess = multiprocessing.Process(
            target=scripts.wsgiserver.StartWsgiServer,
            args=(AgentHost, RemoteWsgiTestPort, current_dir))
        RemoteAgentProcess.start()
        print("Waiting until the WSGI server is ready")
        time.sleep(8.0)
        # Check again if the server is started. This can be done only with scripts compatible with WSGI.
        local_agent_url = "http://%s:%s/survol/entity.py?mode=json" % (AgentHost, RemoteWsgiTestPort)
        try:
            response = portable_urlopen( local_agent_url, timeout=5)
        except Exception as exc:
            print("Caught:", exc)
            ServerDumpContent( scripts.wsgiserver.WsgiServerLogFileName )
            raise

    data = response.read().decode("utf-8")
    print("Survol agent OK")


def tearDownModule():
    global RemoteAgentProcess
    print("tearDownModule")
    if RemoteAgentProcess:
        RemoteAgentProcess.terminate()
        RemoteAgentProcess.join()


isVerbose = ('-v' in sys.argv) or ('--verbose' in sys.argv)

import lib_client
import lib_properties

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

# This defines a file which is present on all platforms.
if sys.platform.startswith("linux"):
    FileAlwaysThere = "/etc/hosts"
    DirAlwaysThere = "/etc"
    AnyLogicalDisk = ""
else:
    FileAlwaysThere = "C:\\Windows\\explorer.exe"
    DirAlwaysThere = "C:\\Windows"
    AnyLogicalDisk = "D:"


# This test if an executable is present.
def _linux_check_program_exists(program_name):
    import subprocess
    p = subprocess.Popen(['/usr/bin/which', program_name], stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    p.communicate()
    return p.returncode == 0


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


if __name__ == '__main__':
    lenArgv = len(sys.argv)
    ix = 0
    while ix < lenArgv:
        if sys.argv[ix] in ["-l","--list"]:
            globCopy = globals().copy()
            lstGlobs = [ globCopy[clsNam] for clsNam in sorted(globCopy) ]
            # SurvolLocalTest,SurvolRemoteTest,SurvolSearchTest etc...
            lstClasses = [ oneGlob for oneGlob in lstGlobs if isinstance( oneGlob, type )]

            for cls in lstClasses:
                clsDoc = cls.__doc__
                if not clsDoc:
                    clsDoc = ""
                print("%-44s: %s" % ( cls.__name__,clsDoc ) )
                for fnc in dir(cls):
                    if fnc.startswith("test_"):
                        fnc_code = getattr(cls,fnc)
                        if isinstance(fnc_code,bool):
                            tstDoc = "Cannot run"
                        else:
                            tstDoc = fnc_code.__doc__
                        #tstDoc = str(fnc_code)
                        if not tstDoc:
                            tstDoc = ""
                        print("    %-40s: %s" % (fnc, tstDoc))
                print("")
            exit(0)
        if sys.argv[ix] in ["-l","--debug"]:
            lib_client.SetDebugMode()
            del sys.argv[ix]
            lenArgv -= 1
            continue
        if sys.argv[ix] in ["-h","--help"]:
            print("Extra options:")
            print("  -d, --debug: Set debug mode")
            print("  -l, --list : List of tests")
        ix += 1

    unittest.main()

# TODO: Test calls to <Any class>.AddInfo()
# TODO: When double-clicking any Python script, it should do something visible.

#if __name__ == '__main__':
#    freeze_support()
