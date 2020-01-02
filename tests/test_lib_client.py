#!/usr/bin/env python

from __future__ import print_function

import cgitb
import unittest
import subprocess
import sys
import os
import re
import time
import socket
import platform
import pkgutil

from init import *

# This loads the module from the source, so no need to install it, and no need of virtualenv.
update_test_path()

import lib_client
import lib_common
import lib_properties

# If the Survol agent does not exist, this script starts a local one.
RemoteAgentProcess = None

def setUpModule():
    global RemoteAgentProcess
    RemoteAgentProcess = CgiAgentStart(RemoteTestAgent, RemoteTestPort)

def tearDownModule():
    global RemoteAgentProcess
    CgiAgentStop(RemoteAgentProcess)

isVerbose = ('-v' in sys.argv) or ('--verbose' in sys.argv)

# This deletes the module so we can reload them each time.
# Problem: survol modules are not detectable.
# We could as well delete all modules except sys.
allModules = [ modu for modu in sys.modules if modu.startswith("survol") or modu.startswith("lib_")]

ClientObjectInstancesFromScript = lib_client.SourceLocal.GetObjectInstancesFromScript

# Otherwise, Python callstack would be displayed in HTML.
cgitb.enable(format="txt")

# Many tests start a subprocess: Its termination must be checked.
def CheckSubprocessEnd(procOpen):
    ( child_stdout_content, child_stderr_content ) = procOpen.communicate()

    if is_platform_windows:
        # This ensures that the suprocess is correctly started.
        assert(child_stdout_content.startswith(b"Starting subprocess"))

        print("procOpen.returncode=",procOpen.returncode)
        assert(procOpen.returncode == 123)


# TODO: Prefix of url samples should be a parameter.

class SurvolLocalTest(unittest.TestCase):
    """These tests do not need a Survol agent"""

    def test_create_source_local_json(self):
        mySourceFileStatLocal = lib_client.SourceLocal(
            "sources_types/CIM_DataFile/file_stat.py",
            "CIM_DataFile",
            Name=FileAlwaysThere)
        print("test_create_source_local_json: query==%s" % mySourceFileStatLocal.UrlQuery())
        the_content_json = mySourceFileStatLocal.content_json()
        print("test_create_source_local_json: Json content=%s ..."%str(the_content_json)[:30])

    def test_create_source_local_rdf(self):
        mySourceFileStatLocal = lib_client.SourceLocal(
            "sources_types/CIM_DataFile/file_stat.py",
            "CIM_DataFile",
            Name=FileAlwaysThere)
        print("test_create_source_local_rdf: query=%s" % mySourceFileStatLocal.UrlQuery())
        the_content_rdf = mySourceFileStatLocal.content_rdf()
        print("test_create_source_local_rdf: RDF content=%s ..."%str(the_content_rdf)[:30])

    def test_local_triplestore(self):
        mySourceFileStatLocal = lib_client.SourceLocal(
            "sources_types/CIM_DataFile/file_stat.py",
            "CIM_DataFile",
            Name=FileAlwaysThere)
        tripleFileStatLocal = mySourceFileStatLocal.GetTriplestore()
        print("Len triple store local=",len(tripleFileStatLocal.m_triplestore))

    def test_local_instances(self):
        mySourceFileStatLocal = lib_client.SourceLocal(
            "sources_types/CIM_DataFile/file_stat.py",
            "CIM_DataFile",
            Name=FileAlwaysThere)

        lib_common.globalErrorMessageEnabled = False

        tripleFileStatLocal = mySourceFileStatLocal.GetTriplestore()
        print("Len tripleFileStatLocal=",len(tripleFileStatLocal))

        # Typical output:
        #     Win32_Group.Domain=NT SERVICE,Name=TrustedInstaller
        #     CIM_Directory.Name=C:/
        #     CIM_Directory.Name=C:/Windows
        #     CIM_DataFile.Name=C:/Windows/explorer.exe
        instancesFileStatLocal = tripleFileStatLocal.GetInstances()

        lenInstances = len(instancesFileStatLocal)
        sys.stdout.write("Len tripleFileStatLocal=%s\n"%lenInstances)
        for oneInst in instancesFileStatLocal:
            sys.stdout.write("    %s\n"%str(oneInst))
        # This file should be there on any Windows machine.
        self.assertTrue(lenInstances>=1)

    def test_local_json(self):
        # Test merge of heterogeneous data sources.
        mySource1 = lib_client.SourceLocal(
            "entity.py",
            "CIM_LogicalDisk",
            DeviceID=AnyLogicalDisk)

        content1 = mySource1.content_json()
        print( "content1=",str(content1.keys()))

    def test_merge_add_local(self):
        mySource1 = lib_client.SourceLocal(
            "entity.py",
            "CIM_DataFile",
            Name=FileAlwaysThere)
        # The current process is always available.
        mySource2 = lib_client.SourceLocal(
            "entity.py",
            "CIM_Process",
            Handle=CurrentPid)

        mySrcMergePlus = mySource1 + mySource2
        triplePlus = mySrcMergePlus.GetTriplestore()
        print("Len triplePlus:",len(triplePlus))

        lenSource1 = len(mySource1.GetTriplestore().GetInstances())
        lenSource2 = len(mySource2.GetTriplestore().GetInstances())
        lenPlus = len(triplePlus.GetInstances())
        # In the merged link, there cannot be more instances than in the input sources.
        self.assertTrue(lenPlus <= lenSource1 + lenSource2)

    @unittest.skipIf(not pkgutil.find_loader('win32net'), "Cannot import win32net. test_merge_sub_local not run.")
    def test_merge_sub_local(self):
        mySource1 = lib_client.SourceLocal(
            "entity.py",
            "CIM_LogicalDisk",
            DeviceID=AnyLogicalDisk)
        mySource2 = lib_client.SourceLocal(
            "sources_types/win32/win32_local_groups.py")

        mySrcMergeMinus = mySource1 - mySource2
        print("Merge Minus:",str(mySrcMergeMinus.content_rdf())[:30])
        tripleMinus = mySrcMergeMinus.GetTriplestore()
        print("Len tripleMinus:",len(tripleMinus))

        lenSource1 = len(mySource1.GetTriplestore().GetInstances())
        lenMinus = len(tripleMinus.GetInstances())
        # There cannot be more instances after removal.
        self.assertTrue(lenMinus <= lenSource1 )

    @unittest.skipIf(not pkgutil.find_loader('win32api'), "Cannot import win32api. test_merge_duplicate not run.")
    def test_merge_duplicate(self):
        mySourceDupl = lib_client.SourceLocal(
            "sources_types/Win32_UserAccount/Win32_NetUserGetGroups.py",
            "Win32_UserAccount",
            Domain=CurrentMachine,
            Name=CurrentUsername)
        tripleDupl = mySourceDupl.GetTriplestore()
        print("Len tripleDupl=",len(tripleDupl.GetInstances()))

        mySrcMergePlus = mySourceDupl + mySourceDupl
        triplePlus = mySrcMergePlus.GetTriplestore()
        print("Len triplePlus=",len(triplePlus.GetInstances()))
        # No added node.
        self.assertEqual(len(triplePlus.GetInstances()), len(tripleDupl.GetInstances()))

        mySrcMergeMinus = mySourceDupl - mySourceDupl
        tripleMinus = mySrcMergeMinus.GetTriplestore()
        print("Len tripleMinus=",len(tripleMinus.GetInstances()))
        self.assertEqual(len(tripleMinus.GetInstances()), 0)

    # http://rchateau-hp:8000/survol/sources_types/memmap/memmap_processes.py?xid=memmap.Id%3DC%3A%2FWindows%2FSystem32%2Fen-US%2Fkernel32.dll.mui


    def test_exception_bad_source(self):
        # This tests if errors are properly displayed.
        mySourceBad = lib_client.SourceLocal(
            "xxx/yyy/zzz.py",
            "this-will-raise-an-exception")
        try:
            tripleBad = mySourceBad.GetTriplestore()
        except Exception as exc:
            print("Error detected:",exc)

        mySourceBroken = lib_client.SourceRemote(
            RemoteTestAgent + "/xxx/yyy/zzz/ttt.py",
            "wwwww")
        try:
            tripleBroken = mySourceBroken.GetTriplestore()
            excRaised = False
        except Exception as exc:
            excRaised = True
        self.assertTrue(excRaised)

    def test_instance_filter(self):
        # Filter from a triple store by creating a mask like:
        # inst = lib_client.CMI_DataFile
        print("TODO: test_instance_filter not implemented yet")


    def test_sparql(self):
        # https://en.wikipedia.org/wiki/SPARQL
        # PREFIX foaf: <http://xmlns.com/foaf/0.1/>
        # SELECT ?name
        #        ?email
        # WHERE
        #   {
        #     ?person  a          foaf:Person .
        #     ?person  foaf:name  ?name .
        #     ?person  foaf:mbox  ?email .
        #   }
        #
        # TODO: Use rdflib implementation:
        # https://rdflib.readthedocs.io/en/3.4.0/intro_to_sparql.html
        print("TODO: test_sparql not implemented yet")

    def test_wql(self):
        # SELECT * FROM meta_class WHERE NOT __class < "win32"="" and="" not="" __this="" isa="">
        # "Select * from win32_Process where name like '[H-N]otepad.exe'"
        print("TODO: test_wql not implemented yet")

    @unittest.skipIf(not is_platform_windows, "test_local_scripts_UserAccount for Windows only.")
    def test_local_scripts_UserAccount(self):
        """Returns all scripts accessible from current user account."""

        myInstancesLocal = lib_client.Agent().Win32_UserAccount(
            Domain=CurrentMachine,
            Name=CurrentUsername)

        listScripts = myInstancesLocal.GetScripts()
        if isVerbose:
            sys.stdout.write("Scripts:\n")
            for oneScr in listScripts:
                sys.stdout.write("    %s\n"%oneScr)
        # There should be at least a couple of scripts.
        self.assertTrue(len(listScripts) > 0)

    def test_grep_string(self):
        """Searches for printable strings in a file"""

        sampleFile = os.path.join( os.path.dirname(__file__), "SampleDir", "SampleFile.txt" ).replace("\\","/")

        mySourceGrep = lib_client.SourceLocal(
            "sources_types/CIM_DataFile/grep_text_strings.py",
            "CIM_DataFile",
            Name=sampleFile)

        tripleGrep = mySourceGrep.GetTriplestore()

        matchingTriples = tripleGrep.GetMatchingStringsTriples("[Pp]ellentesque")

        lstStringsOnly = sorted( [ trpObj.value for trpSubj,trpPred,trpObj in matchingTriples ] )

        assert( lstStringsOnly == [u'Pellentesque;14;94', u'Pellentesque;6;36', u'Pellentesque;8;50', u'pellentesque;10;66', u'pellentesque;14;101'])

    @unittest.skipIf(not pkgutil.find_loader('win32net'), "Cannot import win32net. test_local_scripts_from_local_source not run.")
    def test_local_scripts_from_local_source(self):
        """Loads the scripts of instances displayed by an initial script"""

        # This is a top-level script.
        mySourceTopLevelLocal = lib_client.SourceLocal(
            "sources_types/win32/win32_local_groups.py")

        tripleTopLevelLocal = mySourceTopLevelLocal.GetTriplestore()
        instancesTopLevelLocal = tripleTopLevelLocal.GetInstances()

        if isVerbose:
            for oneInst in instancesTopLevelLocal:
                sys.stdout.write("    Scripts: %s\n"%str(oneInst))
                listScripts = oneInst.GetScripts()
                for oneScr in listScripts:
                    sys.stdout.write("        %s\n"%oneScr)

    @unittest.skipIf(not pkgutil.find_loader('win32service'), "Cannot import win32service. test_scripts_of_local_instance not run.")
    def test_scripts_of_local_instance(self):
        """This loads scripts of a local instance"""

        # The service "PlugPlay" should be available on all Windows machines.
        myInstanceLocal = lib_client.Agent().Win32_Service(
            Name="PlugPlay")

        listScripts = myInstanceLocal.GetScripts()

        if isVerbose:
            sys.stdout.write("Scripts:\n")
            for oneScr in listScripts:
                sys.stdout.write("    %s\n"%oneScr)
        # There should be at least a couple of scripts.
        self.assertTrue(len(listScripts) > 0)
        # TODO: Maybe this script will not come first in the future.
        assert(listScripts[0].UrlQuery() == "xid=Win32_Service.Name=PlugPlay")
        assert(listScripts[0].m_script == "sources_types/Win32_Service/service_dependencies.py")

    def test_instances_cache(self):
        instanceA = lib_client.Agent().CIM_Directory( Name="C:/Windows")
        instanceB = lib_client.Agent().CIM_Directory( Name="C:/Windows")
        instanceC = lib_client.CreateCIMClass(None,"CIM_Directory",Name="C:/Windows")
        if isVerbose:
            sys.stdout.write("Class=%s\n"%instanceC.__class__.__name__)
            sys.stdout.write("Module=%s\n"%instanceC.__module__)
            sys.stdout.write("Dir=%s\n\n"%str(dir(lib_client)))
            sys.stdout.write("Dir=%s\n"%str(sorted(globals())))

        assert( instanceA is instanceB )
        assert( instanceA is instanceC )
        assert( instanceC is instanceB )

    # This searches the content of a file which contains SQL queries.
    @unittest.skipIf(not pkgutil.find_loader('sqlparse'), "Cannot import sqlparse. test_regex_sql_query_file not run.")
    def test_regex_sql_query_file(self):
        """Searches for SQL queries in one file only."""

        sqlPathName = os.path.join( os.path.dirname(__file__), "AnotherSampleDir", "SampleSqlFile.py" )

        mySourceSqlQueries = lib_client.SourceLocal(
            "sources_types/CIM_DataFile/grep_sql_queries.py",
            "CIM_DataFile",
            Name=sqlPathName)

        tripleSqlQueries = mySourceSqlQueries.GetTriplestore()
        if isVerbose:
            print("Len tripleSqlQueries=",len(tripleSqlQueries.m_triplestore))

        matchingTriples = tripleSqlQueries.GetAllStringsTriples()

        lstQueriesOnly = sorted( matchingTriples )

        if isVerbose:
            print("lstQueriesOnly:",lstQueriesOnly)

        # TODO: Eliminate the last double-quote.
        lstQriesPresent = [
            u'select * from \'AnyTable\'"',
            u'select A.x,B.y from AnyTable A, OtherTable B"',
            u'select a,b,c from \'AnyTable\'"']
        for oneQry in lstQriesPresent:
            assert( oneQry in lstQueriesOnly )

    # This searches the content of a process memory which contains a SQL memory.
    def test_regex_sql_query_from_batch_process(self):
        print("test_regex_sql_query_from_batch_process: Broken")

        return

        try:
            if 'win' in sys.platform:
                import win32con
        except ImportError:
            print("Module win32con is not available so this test is not applicable")
            return

        sqlPathName = os.path.join( os.path.dirname(__file__), "AnotherSampleDir", "CommandExample.bat" )

        execList = [ sqlPathName ]

        # Runs this process: It allocates a variable containing a SQL query, then it waits.
        procOpen = subprocess.Popen(execList, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        print("Started process:",execList," pid=",procOpen.pid)

        (child_stdin, child_stdout_and_stderr) = (procOpen.stdin, procOpen.stdout)

        #print("child_stdout_and_stderr=",child_stdout_and_stderr.readline())

        mySourceSqlQueries = lib_client.SourceLocal(
            "sources_types/CIM_Process/memory_regex_search/scan_sql_queries.py",
            "CIM_Process",
            Handle=procOpen.pid)

        tripleSqlQueries = mySourceSqlQueries.GetTriplestore()
        print(len(tripleSqlQueries))
        assert(len(tripleSqlQueries.m_triplestore)==190)

        lstMatches = list(tripleSqlQueries.GetInstances("[Pp]ellentesque"))
        print("Matches:",lstMatches)
        assert( len(lstMatches) == 5 )

        # Any string will do.
        child_stdin.write("Stop")
        #procOpen.kill()
        #procOpen.communicate()
        #child_stdin.close()
        #child_stdout_and_stderr.close()

        print(lstMatches)

    # This searches the content of a process memory which contains a SQL memory.
    def test_regex_sql_query_from_python_process(self):
        print("test_regex_sql_query_from_python_process: Broken")
        return

        try:
            if 'win' in sys.platform:
                import win32con
        except ImportError:
            print("Module win32con is not available so this test is not applicable")
            return

        sqlPathName = os.path.join( os.path.dirname(__file__), "AnotherSampleDir", "SampleSqlFile.py" )

        execList = [ sys.executable, sqlPathName ]

        # Runs this process: It allocates a variable containing a SQL query, then it waits.
        procOpen = subprocess.Popen(execList, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)

        print("Started process:",execList," pid=",procOpen.pid)

        # Reading from procOpen.stdout is buffered and one cannot get data until trhe process leaves, or so.
        #print("child_stdout_and_stderr=",child_stdout_and_stderr.readline())

        mySourceSqlQueries = lib_client.SourceLocal(
            "sources_types/CIM_Process/memory_regex_search/scan_sql_queries.py",
            "CIM_Process",
            Handle=procOpen.pid)

        tripleSqlQueries = mySourceSqlQueries.GetTriplestore()
        print("len(tripleSqlQueries)=",len(tripleSqlQueries))

        matchingTriples = list(tripleSqlQueries.GetAllStringsTriples())
        print("mmm=",matchingTriples)

        CheckSubprocessEnd(procOpen)

    # This searches the content of a process memory which contains a SQL memory.
    def test_regex_sql_query_from_perl_process(self):
        print("test_regex_sql_query_from_perl_process: Broken")
        return

        sqlPathName = os.path.join( os.path.dirname(__file__), "AnotherSampleDir", "SamplePerlScript.pl" )

        execList = [ "perl", sqlPathName ]

        # Runs this process: It allocates a variable containing a SQL query, then it waits.
        procOpen = subprocess.Popen(execList, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)

        print("Started process:",execList," pid=",procOpen.pid)

        # Reading from procOpen.stdout is buffered and one cannot get data until trhe process leaves, or so.
        #print("child_stdout_and_stderr=",child_stdout_and_stderr.readline())

        mySourceSqlQueries = lib_client.SourceLocal(
            "sources_types/CIM_Process/memory_regex_search/scan_sql_queries.py",
            "CIM_Process",
            Handle=procOpen.pid)

        tripleSqlQueries = mySourceSqlQueries.GetTriplestore()
        print("len(tripleSqlQueries)=",len(tripleSqlQueries))

        matchingTriples = list(tripleSqlQueries.GetAllStringsTriples())
        print("mmm=",matchingTriples)

        CheckSubprocessEnd(procOpen)

    def test_open_files_from_python_process(self):
        """Files open by a Python process"""
        sqlPathName = os.path.join( os.path.dirname(__file__), "AnotherSampleDir", "SampleSqlFile.py" )

        execList = [ sys.executable, sqlPathName ]

        procOpen = subprocess.Popen(execList, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)

        print("Started process:",execList," pid=",procOpen.pid)

        mySourceSqlQueries = lib_client.SourceLocal(
            "sources_types/CIM_Process/process_open_files.py",
            "CIM_Process",
            Handle=procOpen.pid)

        tripleSqlQueries = mySourceSqlQueries.GetTriplestore()

        # Some instances are required.
        lstMandatoryInstances = [
            "CIM_Process.Handle=%d"%procOpen.pid,
            CurrentUserPath ]
        if is_platform_windows:
            lstMandatoryInstances += [
                    "CIM_DataFile.Name=C:/Windows/System32/cmd.exe"]
        else:
            lstMandatoryInstances += [
                    CurrentExecutablePath ]
        for oneStr in lstMandatoryInstances:
            assert( oneStr in lstMandatoryInstances)

        CheckSubprocessEnd(procOpen)

    def test_sub_parent_from_python_process(self):
        """Sub and parent processes a Python process"""
        sqlPathName = os.path.join( os.path.dirname(__file__), "AnotherSampleDir", "SampleSqlFile.py" )

        execList = [ sys.executable, sqlPathName ]

        procOpen = subprocess.Popen(execList, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)

        print("Started process:",execList," pid=",procOpen.pid)

        mySourceProcesses = lib_client.SourceLocal(
            "sources_types/CIM_Process/single_pidstree.py",
            "CIM_Process",
            Handle=procOpen.pid)

        tripleProcesses = mySourceProcesses.GetTriplestore()

        lstInstances = tripleProcesses.GetInstances()
        strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

        # Some instances are required.
        lstMandatoryInstances = [
            CurrentProcessPath, # This is the parent process.
            "CIM_Process.Handle=%d"%procOpen.pid,
            CurrentUserPath ]
        if is_platform_windows:
            lstMandatoryInstances += [
                    "CIM_DataFile.Name=C:/Windows/System32/cmd.exe"]
        else:
            lstMandatoryInstances += [
                    CurrentExecutablePath ]
        for oneStr in lstMandatoryInstances:
            assert( oneStr in strInstancesSet)

        CheckSubprocessEnd(procOpen)

    def test_memory_maps_from_python_process(self):
        """Sub and parent processes a Python process"""
        sqlPathName = os.path.join( os.path.dirname(__file__), "AnotherSampleDir", "SampleSqlFile.py" )

        execList = [ sys.executable, sqlPathName ]

        procOpen = subprocess.Popen(execList, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)

        print("Started process:",execList," pid=",procOpen.pid)

        # Give a bit of time so the process is fully init.
        time.sleep(1)

        mySourceMemMaps = lib_client.SourceLocal(
            "sources_types/CIM_Process/process_memmaps.py",
            "CIM_Process",
            Handle=procOpen.pid)

        tripleMemMaps = mySourceMemMaps.GetTriplestore()

        lstInstances = tripleMemMaps.GetInstances()
        strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

        print("Instances=",strInstancesSet)

        # Some instances are required.
        lstMandatoryInstances = [
            'CIM_Process.Handle=%s'%procOpen.pid ]
        lstMandatoryRegex = []

        if is_platform_windows:
            # This is common to Windows 7 and Windows 8.
            lstMandatoryInstances += [
                'memmap.Id=C:/Windows/Globalization/Sorting/SortDefault.nls',
                'memmap.Id=C:/Windows/System32/kernel32.dll',
                'memmap.Id=C:/Windows/System32/locale.nls',
                'memmap.Id=C:/Windows/System32/ntdll.dll',
                'memmap.Id=C:/Windows/System32/KernelBase.dll',
                'memmap.Id=C:/Windows/System32/msvcrt.dll',
                'memmap.Id=C:/Windows/System32/cmd.exe',
                ]
        else:
            # Typical situation of symbolic links:
            # /usr/bin/python => /usr/bin/python2 => /usr/bin/python2.7
            execPath = os.path.realpath( sys.executable )
            lstMandatoryInstances += [
                        'memmap.Id=[heap]',
                        'memmap.Id=[vdso]',
                        'memmap.Id=[vsyscall]',
                        'memmap.Id=[anon]',
                        'memmap.Id=[vvar]',
                        'memmap.Id=[stack]',
                        # Not on Travis
                        # 'memmap.Id=%s' % execPath,
                        # 'memmap.Id=/usr/lib/locale/locale-archive',
                ]

            # Depending on the machine, the root can be "/usr/lib64" or "/lib/x86_64-linux-gnu"
            lstMandatoryRegex += [
                # 'memmap.Id=/usr/lib64/libpython*.',
                r'memmap.Id=.*/ld-.*\.so.*',
                r'memmap.Id=.*/libc-.*\.so.*',
                # 'memmap.Id=/usr/lib64/python*./lib-dynload/_localemodule.so'
            ]


            # On Travis:
            # strInstancesSet = set(['memmap.Id=[heap]', 'memmap.Id=[stack]', 'memmap.Id=/lib/x86_64-linux-gnu/ld-2.23.so',
            # 'memmap.Id=[vdso]', 'CIM_Process.Handle=3331', 'memmap.Id=[vsyscall]', 'memmap.Id=[anon]',
            # 'memmap.Id=/bin/dash', 'memmap.Id=[vvar]', 'memmap.Id=/lib/x86_64-linux-gnu/libc-2.23.so'])



            for oneStr in lstMandatoryInstances:
                if oneStr not in strInstancesSet:
                    WARNING("Cannot find %s in %s", oneStr, str(strInstancesSet))
                assert( oneStr in strInstancesSet)

            # This is much slower, beware.
            for oneRegex in lstMandatoryRegex:
                re_prog = re.compile(oneRegex)
                for oneStr in strInstancesSet:
                    result = re_prog.match(oneStr)
                    if result:
                        break
                if not result:
                    WARNING("Cannot find regex %s in %s", oneRegex, str(strInstancesSet))
                assert result is not None

        CheckSubprocessEnd(procOpen)

    @staticmethod
    def check_environment_variables(process_id):
        mySourceEnvVars = lib_client.SourceLocal(
            "sources_types/CIM_Process/environment_variables.py",
            "CIM_Process",
            Handle=process_id)

        tripleEnvVars = mySourceEnvVars.GetTriplestore()

        print("tripleEnvVars:",tripleEnvVars)

        # The environment variables are returned in various ways,
        # but it is guaranteed that some of them are always present.
        setEnvVars = set( tripleEnvVars.GetAllStringsTriples() )

        print("setEnvVars:",setEnvVars)

        if 'win' in sys.platform:
            mandatoryEnvVars = ['COMPUTERNAME','OS','PATH']
        else:
            mandatoryEnvVars = ['HOME','PATH']

        print("setEnvVars:",setEnvVars)

        for oneVar in mandatoryEnvVars:
            assert( oneVar in setEnvVars )

    @unittest.skipIf(not pkgutil.find_loader('psutil'), "Cannot import psutil. test_environment_from_batch_process not run.")
    def test_environment_from_batch_process(self):
        """Tests that we can read a process'environment variables"""

        if is_platform_windows:
            command_example = "CommandExample.bat"
        else:
            command_example = "CommandExample.sh"
        script_path_name = os.path.join( os.path.dirname(__file__), "AnotherSampleDir", command_example )

        execList = [ script_path_name ]

        # Runs this process: It allocates a variable containing a SQL query, then it waits.
        procOpen = subprocess.Popen(execList, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        print("Started process:",execList," pid=",procOpen.pid)

        (child_stdin, child_stdout_and_stderr) = (procOpen.stdin, procOpen.stdout)

        self.check_environment_variables(procOpen.pid)

        if is_platform_windows:
            # Any string will do: This stops the subprocess which is waiting for an input.
            child_stdin.write("Stop".encode())

    @unittest.skipIf(not pkgutil.find_loader('psutil'), "Cannot import psutil. test_environment_from_current_process not run.")
    def test_environment_from_current_process(self):
        """Tests that we can read current process'environment variables"""

        self.check_environment_variables(CurrentPid)


    def test_python_package_information(self):
        """Tests Python package information"""

        mySourcePythonPackage = lib_client.SourceLocal(
            "entity.py",
            "python/package",
            Id="rdflib")

        triplePythonPackage = mySourcePythonPackage.GetTriplestore()

        lstInstances = triplePythonPackage.GetInstances()
        strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

        DEBUG("strInstancesSet=%s",strInstancesSet)

        # Checks the presence of some Python dependencies, true for all Python versions and OS platforms.
        for oneStr in [
            'CIM_ComputerSystem.Name=%s' % CurrentMachine,
            'python/package.Id=isodate',
            'python/package.Id=pyparsing',
            'python/package.Id=rdflib',
            CurrentUserPath ]:
            DEBUG("oneStr=%s",oneStr)
            assert( oneStr in strInstancesSet)

    def test_python_current_script(self):
        """Examines a running Python process"""

        # This creates a process running in Python, because it does not work with the current process.
        sqlPathName = os.path.join( os.path.dirname(__file__), "AnotherSampleDir", "SampleSqlFile.py" )

        execList = [ sys.executable, sqlPathName ]

        # On Windows, psutil.Process.cmdline() is not very reliable, if the process is started with cmd.exe and Shell=True:
        #Python 2, psutil.__version__=5.2.2
        # Shell=1 argvArray=['C:\\windows\\system32\\cmd.exe', '/c', 'C:\\Python27\\python.exe AnotherSampleDir\\SampleSqlFile.py']
        # Shell=0 argvArray=['C:\\Python27\\python.exe', 'AnotherSampleDir\\SampleSqlFile.py']
        #
        #Python 3, psutil.__version__=5.4.7
        # Shell=1 argvArray=['C:\\windows\\system32\\cmd.exe', '/c', 'C:\\Program', 'Files', '(x86)\\Microsoft', 'Visual', 'Studio\\Shared\\Python36_64\\python.exe AnotherSampleDir\\SampleSqlFile.py']
        # Shell=0 argvArray=['C:\\Program Files (x86)\\Microsoft Visual Studio\\Shared\\Python36_64\\python.exe', 'AnotherSampleDir\\SampleSqlFile.py']
        #
        #Python 2, psutil.__version__=5.4.3
        # argvArray=['python', 'toto space.py']
        procOpen = subprocess.Popen(execList, shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)

        print("Started process:",execList," pid=",procOpen.pid)

        # Give a bit of time so the process is fully init.
        time.sleep(1)

        mySourcePyScript = lib_client.SourceLocal(
            "sources_types/CIM_Process/languages/python/current_script.py",
            "CIM_Process",
            Handle=procOpen.pid)

        triplePyScript = mySourcePyScript.GetTriplestore()

        lstInstances = triplePyScript.GetInstances()
        strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])
        DEBUG("strInstancesSet=%s",str(strInstancesSet))

        sqlPathNameAbsolute = os.path.abspath(sqlPathName)
        sqlPathNameClean = sqlPathNameAbsolute.replace("\\","/")

        # This checks the presence of the current process and the Python file being executed.
        listRequired = [
            'CIM_Process.Handle=%s' % procOpen.pid,
            'CIM_DataFile.Name=%s' % sqlPathNameClean,
        ]

        for oneStr in listRequired:
            assert( oneStr in strInstancesSet )

        CheckSubprocessEnd(procOpen)

    @unittest.skipIf(is_travis_machine() and is_platform_windows, "Cannot get users on Travis and Windows.")
    def test_enumerate_users(self):
        """List detectable users. Security might hide some of them"""

        # http://rchateau-hp:8000/survol/sources_types/enumerate_user.py?xid=.
        mySourceUsers = lib_client.SourceLocal(
            "sources_types/enumerate_user.py")

        tripleUsers = mySourceUsers.GetTriplestore()
        instancesUsers = tripleUsers.GetInstances()
        strInstancesSet = set([str(oneInst) for oneInst in instancesUsers ])

        # At least the current user must be found.
        for oneStr in [ CurrentUserPath ]:
            assert( oneStr in strInstancesSet)

    @unittest.skipIf(not pkgutil.find_loader('cx_Oracle'), "pyodbc cannot be imported. SurvolPyODBCTest not executed.")
    def test_oracle_process_dbs(self):
        """oracle_process_dbs Information about current process"""

        mySource = lib_client.SourceLocal(
            "sources_types/CIM_Process/oracle_process_dbs.py",
            "CIM_Process",
            Handle=CurrentPid)

        strInstancesSet = set([str(oneInst) for oneInst in mySource.GetTriplestore().GetInstances() ])

        # The result is empty but the script worked.
        print(strInstancesSet)
        assert(strInstancesSet == set())

    def test_process_connections(self):
        """process_connections Information about current process"""

        mySource = lib_client.SourceLocal(
            "sources_types/CIM_Process/process_connections.py",
            "CIM_Process",
            Handle=CurrentPid)

        strInstancesSet = set([str(oneInst) for oneInst in mySource.GetTriplestore().GetInstances() ])

        # The result is empty but the script worked.
        print("Connections=",strInstancesSet)
        # assert(strInstancesSet == set())

    def test_process_cwd(self):
        """process_cwd Information about current process"""

        mySource = lib_client.SourceLocal(
            "sources_types/CIM_Process/process_cwd.py",
            "CIM_Process",
            Handle=CurrentPid)

        strInstancesSet = set( [str(oneInst) for oneInst in mySource.GetTriplestore().GetInstances() ])
        print("test_process_cwd: strInstancesSet:", strInstancesSet)

        print("test_process_cwd: CurrentExecutablePath:", CurrentExecutablePath)
        for oneStr in [
            'CIM_DataFile.Name=%s' % os.getcwd().replace("\\","/"),
            CurrentExecutablePath,
            CurrentProcessPath,
            CurrentUserPath,
        ]:
            if oneStr not in strInstancesSet:
                WARNING("oneStr=%s strInstancesSet=%s", oneStr, str(strInstancesSet) )
                # assert 'CIM_DataFile.Name=c:/python27/python.exe' in set(['CIM_DataFile.Name=C:/Python27/python.exe'
                assert(oneStr in strInstancesSet)

class SurvolLocalWbemTest(unittest.TestCase):
    """These tests do not need a Survol agent"""

    @unittest.skipIf(not is_linux_wbem(), "WBEM not available. test_wbem_process_info not executed.")
    def test_wbem_process_info(self):
        """wbem_process_info Information about current process"""

        mySource = lib_client.SourceLocal(
            "sources_types/CIM_Process/wbem_process_info.py",
            "CIM_Process",
            Handle=CurrentPid)

        triple_store = mySource.GetTriplestore()
        instances_list = triple_store.GetInstances()
        strInstancesSet = set( [str(oneInst) for oneInst in instances_list ])
        print("test_wbem_process_info: strInstancesSet:", strInstancesSet)

    @unittest.skipIf(not is_linux_wbem(), "WBEM not available. test_wbem_hostname_processes_local not executed.")
    def test_wbem_hostname_processes_local(self):
        """Get processes on current machine"""

        mySource = lib_client.SourceLocal(
            "sources_types/CIM_ComputerSystem/wbem_hostname_processes.py",
            "CIM_ComputerSystem",
            Name=CurrentMachine)

        triple_store = mySource.GetTriplestore()
        instances_list = triple_store.GetInstances()
        strInstancesSet = set( [str(oneInst) for oneInst in instances_list ])
        print("test_wbem_hostname_processes_local: strInstancesSet:", strInstancesSet)

class SurvolRemoteWbemTest(unittest.TestCase):
    """These tests do not need a Survol agent"""

    @unittest.skipIf(not has_wbem(), "pywbem cannot be imported. test_wbem_hostname_processes_remote not executed.")
    def test_wbem_hostname_processes_remote(self):
        """Get processes on remote machine"""

        mySource = lib_client.SourceLocal(
            "sources_types/CIM_ComputerSystem/wbem_hostname_processes.py",
            "CIM_ComputerSystem",
            Name=SurvolServerHostname)

        mySource.GetTriplestore()


    @unittest.skipIf(not has_wbem(), "pywbem cannot be imported. test_wbem_hostname_processes_remote not executed.")
    def test_wbem_info_processes_remote(self):
        """Display information about one process on a remote machine"""

        computer_source = lib_client.SourceLocal(
            "sources_types/CIM_ComputerSystem/wbem_hostname_processes.py",
            "CIM_ComputerSystem",
            Name=SurvolServerHostname)

        computer_triple_store = computer_source.GetTriplestore()
        instances_list = computer_triple_store.GetInstances()
        strInstancesSet = set( [str(oneInst) for oneInst in instances_list ])

        # ['CIM_Process.Handle=10', 'CIM_Process.Handle=816', 'CIM_Process.Handle=12' etc...
        print("test_wbem_hostname_processes_remote: strInstancesSet:", strInstancesSet)
        for one_str in strInstancesSet:
            self.assertTrue( one_str.startswith('CIM_Process.Handle=') )

        pids_list = [oneInst.Handle for oneInst in instances_list ]
        print("test_wbem_hostname_processes_remote: pids_list:", pids_list)

        remote_url = SurvolServerAgent + "/survol/sources_types/CIM_ComputerSystem/wbem_hostname_processes.py"
        print("remote_url=", remote_url)

        # Do not check all processes, it would be too slow.
        max_num_processes = 20

        # Some processes might have left, this is a rule-of-thumb.
        num_exit_processes = 0
        for remote_pid in pids_list:
            if max_num_processes == 0:
                break
            max_num_processes -= 1

            print("remote_pid=", remote_pid)
            process_source = lib_client.SourceRemote(
                SurvolServerAgent + "/survol/sources_types/CIM_Process/wbem_process_info.py",
                "CIM_Process",
                Handle=remote_pid)
            try:
                process_triple_store = process_source.GetTriplestore()
            except Exception as exc:
                print("pid=", remote_pid, " exc=", exc)
                continue

            # FIXME: If the process has left, this list is empty, and the test fails.
            instances_list = process_triple_store.GetInstances()
            if instances_list == []:
                WARNING("test_wbem_info_processes_remote: Process %s exit." % remote_pid)
                num_exit_processes += 1
                continue
            instances_str = [str(oneInst) for oneInst in instances_list ]
            print("instances_str=", instances_str)
            self.assertTrue(instances_str[0] == 'CIM_Process.Handle=%s' % remote_pid)
        # Rule of thumb: Not too many processes should have left in such a short time.
        self.assertTrue(num_exit_processes < 10)

    # This test is very slow and should not fail Travis.
    @unittest.skipIf(not has_wbem() or is_travis_machine(), "pywbem cannot be imported. test_remote_ontology_wbem not executed.")
    def test_remote_ontology_wbem(self):
        missing_triples = lib_client.CheckOntologyGraph("wbem", SurvolServerAgent)
        self.assertTrue(missing_triples == [], "Missing triples:%s" % str(missing_triples))


class SurvolLocalJavaTest(unittest.TestCase):

    @unittest.skipIf(not pkgutil.find_loader('jpype'), "jpype cannot be imported. test_java_mbeans not executed.")
    def test_java_mbeans(self):
        """Java MBeans"""

        mySource = lib_client.SourceLocal(
            "sources_types/CIM_Process/languages/java/java_mbeans.py",
            "CIM_Process",
            Handle=CurrentPid)

        listRequired = [
            CurrentProcessPath
        ]

        instPrefix = 'java/mbean.Handle=%d,Name=' % CurrentPid

        for instJavaName in [
            'java.lang:type-Memory',
            'java.lang:type-MemoryManager*name-CodeCacheManager',
            'java.lang:type-MemoryManager*name-Metaspace Manager',
            'java.lang:type-MemoryPool*name-Metaspace',
            'java.lang:type-Runtime',
            'java.lang:type-MemoryPool*name-PS Survivor Space',
            'java.lang:type-GarbageCollector*name-PS Scavenge',
            'java.lang:type-MemoryPool*name-PS Old Gen',
            'java.lang:type-Compilation',
            'java.lang:type-MemoryPool*name-Code Cache',
            'java.lang:type-Threading',
            'JMImplementation:type-MBeanServerDelegate',
            'java.lang:type-ClassLoading',
            'com.sun.management:type-HotSpotDiagnostic',
            'java.lang:type-MemoryPool*name-PS Eden Space',
            'java.lang:type-OperatingSystem',
            'java.nio:type-BufferPool*name-mapped',
            'com.sun.management:type-DiagnosticCommand',
            'java.lang:type-GarbageCollector*name-PS MarkSweep',
            'java.lang:type-MemoryPool*name-Compressed Class Space',
            'java.nio:type-BufferPool*name-direct',
            'java.util.logging:type-Logging'
        ]:
            listRequired.append( instPrefix + instJavaName )

        strInstancesSet = set([str(oneInst) for oneInst in mySource.GetTriplestore().GetInstances() ])
        print("test_java_mbeans strInstancesSet=", strInstancesSet)

        for oneStr in listRequired:
            assert( oneStr in strInstancesSet )

    @unittest.skipIf(not pkgutil.find_loader('jpype'), "jpype cannot be imported. test_java_system_properties not executed.")
    def test_java_system_properties(self):
        """Java system properties"""

        mySource = lib_client.SourceLocal(
            "sources_types/CIM_Process/languages/java/java_system_properties.py",
            "CIM_Process",
            Handle=CurrentPid)

        listRequired = [
            CurrentUserPath,
            'CIM_Directory.Name=C:/windows/system32',
            'CIM_Directory.Name=C:/Program Files/Java/jre1.8.0_121/lib/charsets.jar',
            'CIM_Directory.Name=C:/Program Files/nodejs',
            'CIM_Directory.Name=C:/Program Files/Java/jre1.8.0_121',
            'CIM_Directory.Name=C:/windows',
            'CIM_Directory.Name=C:/windows/Sun/Java/lib/ext',
            'CIM_Directory.Name=C:/Program Files/Java/jre1.8.0_121/classes',
            'CIM_Directory.Name=C:/Program Files/Java/jre1.8.0_121/lib/jsse.jar',
            'CIM_Directory.Name=C:/Program Files/Java/jre1.8.0_121/lib/resources.jar',
            'CIM_Directory.Name=C:/Program Files/Java/jre1.8.0_121/lib/jce.jar',
            'CIM_Directory.Name=C:/Program Files/Java/jdk1.8.0_121/lib/tools.jar',
            'CIM_Directory.Name=.',
            'CIM_Directory.Name=C:/Program Files/Java/jre1.8.0_121/lib/sunrsasign.jar',
            'CIM_Directory.Name=C:/Program Files/Java/jre1.8.0_121/lib/endorsed',
            'CIM_Directory.Name=C:/Program Files/Java/jre1.8.0_121/bin',
            'CIM_Directory.Name=C:/Program Files/Java/jre1.8.0_121/lib/ext',
            'CIM_Directory.Name=C:/windows/System32/WindowsPowerShell/v1.0',
            'CIM_Directory.Name=C:/Program Files/Java/jdk1.8.0_121/jre/bin',
            'CIM_Directory.Name=C:/Program Files/Java/jre1.8.0_121/lib/rt.jar',
            'CIM_Directory.Name=C:/Program Files/Java/jdk1.8.0_121/bin',
            'CIM_Directory.Name=C:/windows/Sun/Java/bin',
            'CIM_Directory.Name=C:/Python27',
        ]

        listRequired.append( CurrentProcessPath )

        strInstancesSet = set([str(oneInst) for oneInst in mySource.GetTriplestore().GetInstances() ])
        print("test_java_system_properties strInstancesSet=", strInstancesSet)

        print("listRequired=",listRequired)
        for oneStr in listRequired:
            if oneStr not in strInstancesSet:
                print("Not there:",oneStr)
            self.assertTrue(oneStr in strInstancesSet, "test_java_system_properties: Not there:%s" % str(oneStr))
            # assert( oneStr in strInstancesSet )

    @unittest.skipIf(not pkgutil.find_loader('jpype'), "jpype cannot be imported. test_java_jdk_jstack not executed.")
    def test_java_jdk_jstack(self):
        """Information about JDK stack"""

        mySource = lib_client.SourceLocal(
            "sources_types/CIM_Process/languages/java/jdk_jstack.py",
            "CIM_Process",
            Handle=CurrentPid)

        # Start a Java process.

        strInstancesSet = set([str(oneInst) for oneInst in mySource.GetTriplestore().GetInstances() ])

        assert(strInstancesSet == set())

class SurvolLocalUtf8Test(unittest.TestCase):

    # Traiter ce nom de fichier: Yana e-trema lle et Constantin a-accent-grave Boulogne-sur-Mer.IMG-20190806-WA0000.jpg
    def test_accented_filename(self):
        # Create directory and file name with accents, depending on the platform: Windows/Linux.

        # Access the directory: file_directory.py

        # Check that the returned file matches the original one.

        # Properties: CIM_DataFile.file_stat.py
        pass

    # Traiter ce nom de fichier: Yana e-trema lle et Constantin a-accent-grave Boulogne-sur-Mer.IMG-20190806-WA0000.jpg
    def test_accented_dirname(self):
        pass
        # Create directory and file name with accents, depending on the platform: Windows/Linux.

        # Properties: CIM_DataFile.dir_stat.py
        # Properties: CIM_Directory.file_directory



class SurvolLocalOntologiesTest(unittest.TestCase):
    """This tests the creation of RDFS or OWL-DL ontologies"""

    def test_ontology_survol(self):
        missing_triples = lib_client.CheckOntologyGraph("survol")
        self.assertTrue(missing_triples == [], "Missing triples:%s" % str(missing_triples))

    @unittest.skipIf(not pkgutil.find_loader('wmi'), "wmi cannot be imported. test_ontology_wmi not executed.")
    def test_ontology_wmi(self):
        missing_triples = lib_client.CheckOntologyGraph("wmi")
        self.assertTrue(missing_triples == [], "Missing triples:%s" % str(missing_triples))

    @unittest.skipIf(not is_linux_wbem(), "pywbem cannot be imported. test_ontology_wbem not executed.")
    def test_ontology_wbem(self):
        missing_triples = lib_client.CheckOntologyGraph("wbem")
        self.assertTrue(missing_triples == [], "Missing triples:%s" % str(missing_triples))

# TODO: Test namespaces etc... etc classes wmi etc...

class SurvolLocalLinuxTest(unittest.TestCase):
    """These tests do not need a Survol agent and apply to Linux machines only"""

    def decorator_linux_platform(test_func):
        if is_platform_linux:
            return test_func
        else:
            return None

    @decorator_linux_platform
    def test_process_cgroups(self):
        """CGroups about current process"""

        mySource = lib_client.SourceLocal(
            "sources_types/CIM_Process/Linux/process_cgroups.py",
            "CIM_Process",
            Handle=CurrentPid)

        listRequired = [
            CurrentExecutablePath,
            CurrentProcessPath,
            CurrentUserPath,
            # 'CIM_Directory.Name=/user.slice/user-1001.slice/session-371.scope',
            # 'CIM_Directory.Name=/user.slice/user-1001.slice',
            'CIM_Directory.Name=/',
            'Linux/cgroup.Name=name=systemd',
            'Linux/cgroup.Name=cpuacct',
            'Linux/cgroup.Name=net_cls',
            'Linux/cgroup.Name=hugetlb',
            'Linux/cgroup.Name=blkio',
            'Linux/cgroup.Name=net_prio',
            'Linux/cgroup.Name=devices',
            'Linux/cgroup.Name=perf_event',
            'Linux/cgroup.Name=freezer',
            'Linux/cgroup.Name=cpu',
            'Linux/cgroup.Name=pids',
            'Linux/cgroup.Name=memory',
            'Linux/cgroup.Name=cpuset',
        ]

        strInstancesSet = set([str(oneInst) for oneInst in mySource.GetTriplestore().GetInstances() ])

        for oneStr in listRequired:
            assert( oneStr in strInstancesSet )

class SurvolLocalGdbTest(unittest.TestCase):
    """These tests do not need a Survol agent, and run on Linux with GDB debugger"""

    def decorator_gdb_platform(test_func):
        if is_platform_linux and linux_check_program_exists("gdb"):
            return test_func
        else:
            return None

    @decorator_gdb_platform
    def test_process_gdbstack(self):
        """process_gdbstack Information about current process"""

        mySource = lib_client.SourceLocal(
            "sources_types/CIM_Process/process_gdbstack.py",
            "CIM_Process",
            Handle=CurrentPid)

        listRequired = [
            'linker_symbol.Name=X19wb2xsX25vY2FuY2Vs,File=/lib64/libc.so.6',
            'CIM_DataFile.Name=/lib64/libc.so.6',
            CurrentUserPath,
            CurrentProcessPath
        ]
        if sys.version_info >= (3,):
            listRequired += [
                'CIM_DataFile.Name=/usr/bin/python3.6',
                'linker_symbol.Name=cG9sbF9wb2xs,File=/usr/bin/python3.6',
        ]
        else:
            listRequired += [
                'CIM_DataFile.Name=/usr/bin/python2.7',
                'CIM_DataFile.Name=/lib64/libc.so.6',
        ]


        strInstancesSet = set([str(oneInst) for oneInst in mySource.GetTriplestore().GetInstances() ])

        for oneStr in listRequired:
            assert( oneStr in strInstancesSet )

    @unittest.skipIf(sys.version_info >= (3,), "Python stack for Python 2 only.")
    @decorator_gdb_platform
    def test_display_python_stack(self):
        """Displays the stack of a Python process"""

        # This creates a process running in Python, because it does not work with the current process.
        pyPathName = os.path.join( os.path.dirname(__file__), "AnotherSampleDir", "SampleSqlFile.py" )
        pyPathName = os.path.abspath(pyPathName)

        execList = [ sys.executable, pyPathName ]

        procOpen = subprocess.Popen(execList, shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)

        print("Started process:",execList," pid=",procOpen.pid)

        # Give a bit of time so the process is fully init.
        time.sleep(1)

        mySourcePyStack = lib_client.SourceLocal(
            "sources_types/CIM_Process/languages/python/display_python_stack.py",
            "CIM_Process",
            Handle=procOpen.pid)

        triplePyStack = mySourcePyStack.GetTriplestore()

        lstInstances = triplePyStack.GetInstances()
        strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])
        print("strInstancesSet=",strInstancesSet)

        # Typical output: [
        #     'linker_symbol.Name=X19tYWluX18=,File=/tmp/tmpfxxzh0.py',
        #     'CIM_DataFile.Name=/tmp/tmpfxxzh0.py',
        #     'linker_symbol.Name=X19tYWluX18=,File=/home/rchateau/survol/tests/AnotherSampleDir/SampleSqlFile.py',
        #     'CIM_DataFile.Name=/home/rchateau/survol/tests/AnotherSampleDir/SampleSqlFile.py'
        # ]

        pyPathNameAbsolute = os.path.abspath(pyPathName)
        pyPathNameClean = pyPathNameAbsolute.replace("\\","/")

        # This checks the presence of the current process and the Python file being executed.
        listRequired = [
            'CIM_DataFile.Name=%s' % pyPathNameClean,
            'linker_symbol.Name=X19tYWluX18=,File=%s' % pyPathName,
        ]

        for oneStr in listRequired:
            print(oneStr)
            assert( oneStr in strInstancesSet )

        CheckSubprocessEnd(procOpen)

@unittest.skipIf(not is_platform_windows, "SurvolLocalWindowsTest runs on Windows only")
class SurvolLocalWindowsTest(unittest.TestCase):
    """These tests do not need a Survol agent. They apply to Windows machines only"""

    @unittest.skipIf(not pkgutil.find_loader('win32service'), "test_win32_services needs win32service to run.")
    def test_win32_services(self):
        """List of Win32 services"""

        lstInstances = ClientObjectInstancesFromScript(
            "sources_types/win32/enumerate_Win32_Service.py")

        strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

        # print(strInstancesSet)
        # Some services must be on any Windpws machine.
        assert('Win32_Service.Name=nsi' in strInstancesSet)
        assert('Win32_Service.Name=LanmanWorkstation' in strInstancesSet)

    @unittest.skipIf(not pkgutil.find_loader('wmi'), "test_wmi_process_info needs wmi to run.")
    def test_wmi_process_info(self):
        """WMI information about current process"""

        lstInstances = ClientObjectInstancesFromScript(
            "sources_types/CIM_Process/wmi_process_info.py",
            "CIM_Process",
            Handle=CurrentPid)

        strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

        # This checks the presence of the current process and its parent.
        assert('CIM_Process.Handle=%s' % CurrentPid in strInstancesSet)
        if sys.version_info >= (3,):
            # Checks the parent's presence also. Not for 2.7.10
            assert(CurrentProcessPath in strInstancesSet)

    @unittest.skipIf(not pkgutil.find_loader('wmi'), "test_win_process_modules needs wmi to run.")
    def test_win_process_modules(self):
        """Windows process modules"""

        lstInstances = ClientObjectInstancesFromScript(
            "sources_types/CIM_Process/win_process_modules.py",
            "CIM_Process",
            Handle=CurrentPid)

        strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

        # This checks the presence of the current process and its parent.
        listRequired = [
            CurrentProcessPath,
            CurrentUserPath,
            'CIM_DataFile.Name=%s' % sys.executable.replace("\\","/"),
        ]

        # Some nodes are in Py2 or Py3.
        if sys.version_info >= (3,):
            if platform.release() == '7':
                listOption = [
                'CIM_DataFile.Name=C:/windows/system32/kernel32.dll',
                ]
            elif platform.release() == '10':
                # 'C:\\Users\\rchat\\AppData\\Local\\Programs\\Python\\Python36\\python.exe'
                # 'C:/Users/rchat/AppData/Local/Programs/Python/Python36/DLLs/_ctypes.pyd'
                filCTypes = os.path.dirname(sys.executable).replace("\\","/") + '/DLLs/_ctypes.pyd'
                listOption = [
                    'CIM_DataFile.Name=%s' % sys.executable.replace("\\","/"),
                    'CIM_DataFile.Name=%s' % filCTypes,
                ]
        else:
            listOption = [
            'CIM_DataFile.Name=C:/windows/SYSTEM32/ntdll.dll',
            ]

        for oneStr in listRequired + listOption:
            assert( oneStr in strInstancesSet )

        # Detection if a specific bug is fixed.
        assert(not 'CIM_DataFile.Name=' in strInstancesSet)

    def test_win32_products(self):
        lstInstances = ClientObjectInstancesFromScript(
            "sources_types/win32/enumerate_Win32_Product.py")

        strInstancesLst = [str(oneInst) for oneInst in lstInstances ]
        print("lstInstances=",strInstancesLst[:3])

    def test_win_cdb_callstack(self):
        """win_cdb_callstack Information about current process"""

        mySource = lib_client.SourceLocal(
            "sources_types/CIM_Process/CDB/win_cdb_callstack.py",
            "CIM_Process",
            Handle=CurrentPid)

        try:
            # Should throw "Exception: ErrorMessageHtml raised:Cannot debug current process"
            mySource.GetTriplestore()
        except Exception as exc:
            print("Success: Exception received, because cannot debug current process")
            return

        assert(False)

    def test_win_cdb_modules(self):
        """win_cdb_modules about current process"""

        mySource = lib_client.SourceLocal(
            "sources_types/CIM_Process/CDB/win_cdb_modules.py",
            "CIM_Process",
            Handle=CurrentPid)

        try:
            # Should throw "Exception: ErrorMessageHtml raised:Cannot debug current process"
            mySource.GetTriplestore()
        except Exception as exc:
            print("Success: Exception received, because cannot debug current process")
            return

        assert(False)

    @unittest.skipIf(is_pytest(), "This msdos test cannot run in pytest.")
    def test_msdos_current_batch(self):
        """Displays information a MSDOS current batch"""

        # This cannot display specific information about the current MSDOS batch because there is none,
        # as it is a Python process. Still, this tests checks that the script runs properly.
        list_instances = ClientObjectInstancesFromScript(
            "sources_types/CIM_Process/languages/msdos/current_batch.py",
            "CIM_Process",
            Handle=CurrentPid)

        # If running in pytest:
        # ['CIM_DataFile.Name=C:/Python27/Scripts/pytest.exe', 'CIM_Process.Handle=74620']
        strInstancesSet = set([str(oneInst) for oneInst in list_instances ])

        listRequired =  [
            CurrentProcessPath,
        ]
        print("listRequired=", listRequired)

        for oneStr in listRequired:
            assert( oneStr in strInstancesSet )

    @unittest.skipIf(not pkgutil.find_loader('win32net'), "test_win32_host_local_groups needs win32net.")
    def test_win32_host_local_groups(self):
        mySourceHostLocalGroups = lib_client.SourceLocal(
            "sources_types/CIM_ComputerSystem/Win32/win32_host_local_groups.py",
            "CIM_ComputerSystem",
            Name = CurrentMachine)

        sys.stderr.write("CurrentMachine=%s before GetTriplestore\n" % CurrentMachine)
        tripleHostLocalGroups = mySourceHostLocalGroups.GetTriplestore()
        sys.stderr.write("CurrentMachine=%s before GetInstances\n" % CurrentMachine)
        instancesHostLocalGroups = tripleHostLocalGroups.GetInstances()

        print("Host local groups=", instancesHostLocalGroups)
        for one_instance in instancesHostLocalGroups:
            print("one_instance=", one_instance)


try:
    import pyodbc
except ImportError as exc:
    pyodbc = None
    print("Detected ImportError:",exc)

# https://stackoverflow.com/questions/23741133/if-condition-in-setup-ignore-test
# This decorator at the class level does not work on Travis.
# @unittest.skipIf( not pyodbc, "pyodbc cannot be imported. SurvolPyODBCTest not executed.")
class SurvolPyODBCTest(unittest.TestCase):

    @unittest.skipIf(not pyodbc, "pyodbc cannot be imported. SurvolPyODBCTest not executed.")
    def test_local_scripts_odbc_dsn(self):
        """This instantiates an instance of a subclass"""

        # The url is "http://rchateau-hp:8000/survol/entity.py?xid=odbc/dsn.Dsn=DSN~MS%20Access%20Database"
        instanceLocalODBC = lib_client.Agent().odbc.dsn(
            Dsn="DSN~MS%20Access%20Database")

        listScripts = instanceLocalODBC.GetScripts()
        if isVerbose:
            sys.stdout.write("Scripts:\n")
            for oneScr in listScripts:
                sys.stdout.write("    %s\n"%oneScr)
        # There should be at least a couple of scripts.
        self.assertTrue(len(listScripts) > 0)

    @unittest.skipIf(not pyodbc, "pyodbc cannot be imported. SurvolPyODBCTest not executed.")
    def test_pyodbc_sqldatasources(self):
        """Tests ODBC data sources"""

        lstInstances = ClientObjectInstancesFromScript(
            "sources_types/Databases/win32_sqldatasources_pyodbc.py")

        strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

        # At least these instances must be present.
        for oneStr in [
            'CIM_ComputerSystem.Name=%s' % CurrentMachine,
            'odbc/dsn.Dsn=DSN~Excel Files',
            'odbc/dsn.Dsn=DSN~MS Access Database',
            'odbc/dsn.Dsn=DSN~MyNativeSqlServerDataSrc',
            'odbc/dsn.Dsn=DSN~MyOracleDataSource',
            'odbc/dsn.Dsn=DSN~OraSysDataSrc',
            'odbc/dsn.Dsn=DSN~SysDataSourceSQLServer',
            'odbc/dsn.Dsn=DSN~dBASE Files',
            'odbc/dsn.Dsn=DSN~mySqlServerDataSource',
            'odbc/dsn.Dsn=DSN~SqlSrvNativeDataSource']:
            assert( oneStr in strInstancesSet)


    @unittest.skipIf(not pyodbc, "pyodbc cannot be imported. SurvolPyODBCTest not executed.")
    def test_pyodbc_dsn_tables(self):
        """Tests ODBC data sources"""

        lstInstances = ClientObjectInstancesFromScript(
            "sources_types/odbc/dsn/odbc_dsn_tables.py",
            "odbc/dsn",
            Dsn="DSN~SysDataSourceSQLServer")

        strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])
        #print("Instances:",strInstancesSet)

        # Checks the presence of some Python dependencies, true for all Python versions and OS platforms.
        for oneStr in [
            'odbc/table.Dsn=DSN~SysDataSourceSQLServer,Table=all_columns',
            'odbc/table.Dsn=DSN~SysDataSourceSQLServer,Table=assembly_files',
            'odbc/table.Dsn=DSN~SysDataSourceSQLServer,Table=change_tracking_tables',
            'odbc/table.Dsn=DSN~SysDataSourceSQLServer,Table=dm_broker_queue_monitors',
            'odbc/table.Dsn=DSN~SysDataSourceSQLServer,Table=dm_hadr_availability_group_states',
            'odbc/table.Dsn=DSN~SysDataSourceSQLServer,Table=dm_hadr_database_replica_cluster_states',
            'odbc/table.Dsn=DSN~SysDataSourceSQLServer,Table=dm_hadr_instance_node_map',
            'odbc/table.Dsn=DSN~SysDataSourceSQLServer,Table=server_audit_specifications',
            'odbc/table.Dsn=DSN~SysDataSourceSQLServer,Table=server_audits',
            'odbc/table.Dsn=DSN~SysDataSourceSQLServer,Table=sysusers',
            ]:
            assert( oneStr in strInstancesSet)


    @unittest.skipIf(not pyodbc, "pyodbc cannot be imported. SurvolPyODBCTest not executed.")
    def test_pyodbc_dsn_one_table_columns(self):
        """Tests ODBC table columns"""

        lstInstances = ClientObjectInstancesFromScript(
            "sources_types/odbc/table/odbc_table_columns.py",
            "odbc/table",
            Dsn="DSN~SysDataSourceSQLServer",
            Table="dm_os_windows_info")

        strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])
        #print("Instances:",strInstancesSet)

        # Checks the presence of some Python dependencies, true for all Python versions and OS platforms.
        for oneStr in [
            'odbc/column.Dsn=DSN~SysDataSourceSQLServer,Table=dm_os_windows_info,Column=windows_service_pack_level',
            'odbc/column.Dsn=DSN~SysDataSourceSQLServer,Table=dm_os_windows_info,Column=os_language_version',
            'odbc/column.Dsn=DSN~SysDataSourceSQLServer,Table=dm_os_windows_info,Column=windows_release',
            'odbc/column.Dsn=DSN~SysDataSourceSQLServer,Table=dm_os_windows_info,Column=windows_sku',
            'odbc/table.Dsn=DSN~SysDataSourceSQLServer,Table=dm_os_windows_info'
        ]:
            assert( oneStr in strInstancesSet)




class SurvolSocketsTest(unittest.TestCase):
    """Test involving remote Survol agents: The scripts executes scripts on remote machines
    and examines the result. It might merge the output with local scripts or
    scripts on different machines."""

    def test_netstat_sockets(self):

        # Not many web sites in HTTP these days. This one is very stable.
        # http://w2.vatican.va/content/vatican/it.html is on port 80=http
        httpHostName = 'w2.vatican.va'

        sockHost = socket.gethostbyname(httpHostName)
        print("gethostbyname(%s)=%s"%(httpHostName,sockHost))

        # This opens a connection to a specific machine, then checks that the socket can be found.
        if sys.version_info >= (3,):
            import http.client
            connHttp = http.client.HTTPConnection(httpHostName, 80, timeout=60)
        else:
            import httplib
            connHttp = httplib.HTTPConnection(httpHostName, 80, timeout=60)
        print("Connection to %s OK"%httpHostName)
        connHttp.request("GET", "/content/vatican/it.html")
        resp = connHttp.getresponse()
        if resp.status != 200 or resp.reason != "OK":
            raise Exception("Hostname %s not ok for test. Status=%d, reason=%s."%(httpHostName, resp.status, resp.reason))
        peerName = connHttp.sock.getpeername()
        peerHost = peerName[0]

        print("Peer name of connection socket:",connHttp.sock.getpeername())

        if is_platform_windows:
            lstInstances = ClientObjectInstancesFromScript("sources_types/win32/tcp_sockets_windows.py")
        else:
            lstInstances = ClientObjectInstancesFromScript("sources_types/Linux/tcp_sockets.py")

        strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

        addrExpected = "addr.Id=%s:80" % (peerHost)
        print("addrExpected=",addrExpected)
        assert( addrExpected in strInstancesSet )

        connHttp.close()

    def test_enumerate_sockets(self):
        """List of sockets opened on the host machine"""

        # httpHostName = 'www.root-servers.org'
        # This site was registered on September the 18th, 1986.
        httpHostName = 'itcorp.com'

        print("")
        sockHost = socket.gethostbyname(httpHostName)
        print("gethostbyname(%s)=%s"%(httpHostName,sockHost))

        # This opens a connection to a specific machine, then checks that the socket can be found.
        if sys.version_info >= (3,):
            import http.client
            connHttp = http.client.HTTPConnection(httpHostName, 80, timeout=60)
        else:
            import httplib
            connHttp = httplib.HTTPConnection(httpHostName, 80, timeout=60)
        print("Connection to %s OK"%httpHostName)

        #connHttp.request(method="GET", url="/", headers={"Connection" : "Keep-alive"})
        print("Requesting content")
        #connHttp.request(method="GET", url="/content/vatican/it.html")
        connHttp.request(method="GET", url="/")
        print("Peer name of connection socket:",connHttp.sock.getpeername())

        resp = connHttp.getresponse()

        if resp.status != 200 or resp.reason != "OK":
            raise Exception("Hostname %s not ok for test. Status=%d, reason=%s."%(httpHostName, resp.status, resp.reason))
        peerName = connHttp.sock.getpeername()
        peerHost = peerName[0]

        lstInstances = ClientObjectInstancesFromScript(
            "sources_types/enumerate_socket.py")

        strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

        addrExpected = "addr.Id=%s:80" % (peerHost)

        #print("Instances:",strInstancesSet)
        print("sockHost=",sockHost)
        print("addrExpected=",addrExpected)
        #assert( addrExpected in strInstancesSet)

        print("test_enumerate_sockets: Does not work yet. Only testing execution.")

        if False:
            # For debugging purpose only.
            def DispIp(oneInst):
                if oneInst.startswith("addr") and oneInst.find("127.0.0.1") < 0:
                    # addr.Id=iwc2-31.catholica.va:http
                    addrOnly = oneInst[ oneInst.find("=") +1: oneInst.find(":") ]
                    try:
                        addrHost = socket.gethostbyname(addrOnly)
                        print(oneInst,addrHost)
                    except:
                        print(oneInst,"===",addrOnly)

            for oneInst in sorted(strInstancesSet):
                DispIp(oneInst)
                if oneInst.find(addrExpected)>= 0:
                    print("OK. Found %s in %s "%(addrExpected,oneInst))
                    break

        connHttp.close()


    def test_socket_connected_processes(self):
        """List of processes connected to a given socket"""

        # This test connect to an external server and checks that sockets are properly listed.
        # It needs a HTTP web server because it is simpler for debugging.
        # https://stackoverflow.com/questions/50068127/http-only-site-to-test-rest-requests
        # This URL doesn't redirect http to https.
        httpHostName = 'eu.httpbin.org'

        print("")
        sockHost = socket.gethostbyname(httpHostName)
        print("gethostbyname(%s)=%s"%(httpHostName,sockHost))

        # This opens a connection to a specific machine, then checks that the socket can be found.
        if sys.version_info >= (3,):
            import http.client
            connHttp = http.client.HTTPConnection(httpHostName, 80, timeout=60)
        else:
            import httplib
            connHttp = httplib.HTTPConnection(httpHostName, 80, timeout=60)
        print("Connection to %s OK"%httpHostName)
        connHttp.request("GET", "")
        resp = connHttp.getresponse()
        if resp.status != 200 or resp.reason != "OK":
            raise Exception("Hostname %s not ok for test. Status=%d, reason=%s."%(httpHostName, resp.status, resp.reason))
        peerName = connHttp.sock.getpeername()
        peerHost = peerName[0]

        print("Peer name of connection socket:",connHttp.sock.getpeername())

        lstInstances = ClientObjectInstancesFromScript(
            "sources_types/addr/socket_connected_processes.py",
            "addr",
            Id="%s:80"%peerHost)

        strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

        # Because the current process has created this socket,
        # it must be found in the socket's connected processes.

        addrExpected = "addr.Id=%s:80" % peerHost
        procExpected =  CurrentProcessPath

        print("addrExpected=",addrExpected)
        print("procExpected=",procExpected)

        assert( addrExpected in strInstancesSet)
        assert( procExpected in strInstancesSet)

        connHttp.close()

    @unittest.skipIf(not is_platform_windows, "test_net_use for Windows only.")
    def test_net_use(self):
        """Just test that the command NET USE runs"""

        # This does not really test the content, because nothing is sure.
        # However, at least it tests that the script can be called.
        lstInstances = ClientObjectInstancesFromScript(
            "sources_types/SMB/net_use.py")

        strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])
        print(strInstancesSet)
        # Typical content:
        # 'CIM_DataFile.Name=//192.168.0.15/public:',
        # 'CIM_DataFile.Name=//192.168.0.15/rchateau:',
        # 'smbshr.Id=\\\\192.168.0.15\\public',
        # 'CIM_DataFile.Name=//localhost/IPC$:',
        # 'smbshr.Id=\\\\192.168.0.15\\rchateau',
        # 'smbshr.Id=\\\\localhost\\IPC$'

        # TODO: localhost should be replaced by the IP address.

        # These elements are nto there after booting a machine.
        #assert( 'CIM_DataFile.Name=//localhost/IPC$:' in strInstancesSet )
        #assert( 'smbshr.Id=\\\\localhost\\IPC$' in strInstancesSet )

    @unittest.skipIf(not is_platform_windows, "test_windows_network_devices for Windows only.")
    def test_windows_network_devices(self):
        """Loads network devices on a Windows network"""

        lstInstances = ClientObjectInstancesFromScript(
            "sources_types/win32/windows_network_devices.py")

        strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])
        print(strInstancesSet)

        # Typical content:
        #   'CIM_ComputerSystem.Name=192.168.0.15',
        #   'smbshr.Id=//192.168.0.15/rchateau',
        #   'CIM_DataFile.Name=Y:',
        #   'CIM_DataFile.Name=Z:',
        #   'smbshr.Id=//192.168.0.15/public'
        #
        # Some sanity checks of the result.
        set_ip_addresses = set()
        smbshr_disk = set()
        for oneInst in strInstancesSet:
            ( the_class,dummy_dot, the_entity_id) = oneInst.partition(".")
            if the_class == "CIM_ComputerSystem":
                (pred_Name,dummy_equal,ip_address) = the_entity_id.partition("=")
                set_ip_addresses.add(ip_address)
            elif  the_class == "smbshr":
                (pred_Name,dummy_equal,disk_name) = the_entity_id.partition("=")
                smbshr_disk.add(disk_name)

        # Check that all machines hosting a disk have their
        for disk_name in smbshr_disk:
            # For example, "//192.168.0.15/public"
            host_name = disk_name.split("/")[2]
            assert( host_name in set_ip_addresses )

class SurvolRemoteTest(unittest.TestCase):
    """Test involving remote Survol agents: The scripts executes scripts on remote machines
    and examines the result. It might merge the output with local scripts or
    scripts on different machines."""

    # This is executed after each test. No special reason for a delay, except perf measures, possibly.
    # https://stackoverflow.com/questions/2648329/python-unit-test-how-to-add-some-sleeping-time-between-test-cases
    #def tearDown(self):
    #    time.sleep(0.01)  # sleep time in seconds

    def test_InstanceUrlToAgentUrl(selfself):
        assert( lib_client.InstanceUrlToAgentUrl("http://LOCALHOST:80/NotRunningAsCgi/entity.py?xid=addr.Id=127.0.0.1:427") == None )
        assert( lib_client.InstanceUrlToAgentUrl(RemoteTestAgent + "/survol/sources_types/java/java_processes.py") == RemoteTestAgent )

    def test_create_source_url(self):
        # http://rchateau-hp:8000/survol/sources_types/CIM_DataFile/file_stat.py?xid=CIM_DataFile.Name%3DC%3A%2FWindows%2Fexplorer.exe
        mySourceFileStatRemote = lib_client.SourceRemote(
            RemoteTestAgent + "/survol/sources_types/CIM_DataFile/file_stat.py",
            "CIM_DataFile",
            Name=FileAlwaysThere)
        print("urlFileStatRemote=",mySourceFileStatRemote.Url())
        print("qryFileStatRemote=",mySourceFileStatRemote.UrlQuery())
        print("jsonFileStatRemote=%s  ..." % str(mySourceFileStatRemote.content_json())[:30])
        print("rdfFileStatRemote=%s ..." % str(mySourceFileStatRemote.content_rdf())[:30])

        # https://stackoverflow.com/questions/46978624/python-multiprocessing-process-to-use-virtualenv
        # print(__file__ + " sys.path=%s" % str(sys.path))
        print(__file__ + " sys.executable=%s" % sys.executable)
        print(__file__ + " sys.exec_prefix=%s" % sys.exec_prefix)

    def test_remote_triplestore(self):
        mySourceFileStatRemote = lib_client.SourceRemote(
            RemoteTestAgent + "/survol/sources_types/CIM_Directory/file_directory.py",
            "CIM_Directory",
            Name=DirAlwaysThere)
        tripleFileStatRemote = mySourceFileStatRemote.GetTriplestore()
        print("Len tripleFileStatRemote=",len(tripleFileStatRemote))
        # This should not be empty.
        self.assertTrue(len(tripleFileStatRemote)>=1)

    # This does not work yet.
    def test_remote_scripts_exception(self):
        myAgent = lib_client.Agent(RemoteTestAgent)

        try:
            mySourceInvalid = myAgent.CIM_LogicalDisk(WrongProperty=AnyLogicalDisk)
            scriptsInvalid = mySourceInvalid.GetScripts()
            excRaised = False
            print("No exception is raised (This is a problem)")
        except Exception as exc:
            # Should print: "No JSON object could be decoded"
            print("An exception is raised (As expected):",exc)
            excRaised = True
        self.assertTrue(excRaised)

    def test_remote_instances_python_package(self):
        """This loads a specific Python package"""
        mySourcePythonPackageRemote = lib_client.SourceRemote(
            RemoteTestAgent + "/survol/entity.py",
            "python/package",
            Id="rdflib")
        triplePythonPackageRemote = mySourcePythonPackageRemote.GetTriplestore()

        instancesPythonPackageRemote = triplePythonPackageRemote.GetInstances()
        lenInstances = len(instancesPythonPackageRemote)
        # This Python module must be there because it is needed by Survol.
        self.assertTrue(lenInstances>=1)

    @unittest.skipIf(not pkgutil.find_loader('jpype'), "jpype cannot be imported. test_remote_instances_java not executed.")
    def test_remote_instances_java(self):
        """Loads Java processes. There is at least one Java process, the one doing the test"""
        mySourceJavaRemote = lib_client.SourceRemote(
            RemoteTestAgent + "/survol/sources_types/java/java_processes.py")
        tripleJavaRemote = mySourceJavaRemote.GetTriplestore()
        print("Len tripleJavaRemote=",len(tripleJavaRemote))

        instancesJavaRemote = tripleJavaRemote.GetInstances()
        numJavaProcesses = 0
        for oneInstance in instancesJavaRemote:
            if oneInstance.__class__.__name__ == "CIM_Process":
                print("Found one Java process:",oneInstance)
                numJavaProcesses += 1
        print("Remote Java processes=",numJavaProcesses)
        self.assertTrue(numJavaProcesses>=1)

    # Cannot run /sbin/arp -an
    @unittest.skipIf(is_travis_machine(), "Cannot run this test on TravisCI because arp is not available.")
    def test_remote_instances_arp(self):
        """Loads machines visible with ARP. There must be at least one CIM_ComputerSystem"""

        mySourceArpRemote = lib_client.SourceRemote(
            RemoteTestAgent + "/survol/sources_types/neighborhood/cgi_arp_async.py")
        tripleArpRemote = mySourceArpRemote.GetTriplestore()
        print("Len tripleArpRemote=",len(tripleArpRemote))

        instancesArpRemote = tripleArpRemote.GetInstances()
        numComputers = 0
        for oneInstance in instancesArpRemote:
            if oneInstance.__class__.__name__ == "CIM_ComputerSystem":
                print("Test remote ARP: Found one machine:",oneInstance)
                numComputers += 1
        print("Remote hosts number=",numComputers)
        self.assertTrue(numComputers>=1)

    def test_merge_add_mixed(self):
        """Merges local data triples and remote Survol agent's"""
        mySource1 = lib_client.SourceLocal(
            "entity.py",
            "CIM_LogicalDisk",
            DeviceID=AnyLogicalDisk)
        if is_platform_windows:
            mySource2 = lib_client.SourceRemote(RemoteTestAgent + "/survol/sources_types/win32/tcp_sockets_windows.py")
        else:
            mySource2 = lib_client.SourceRemote(RemoteTestAgent + "/survol/sources_types/Linux/tcp_sockets.py")

        mySrcMergePlus = mySource1 + mySource2
        print("Merge plus:",str(mySrcMergePlus.content_rdf())[:30])
        triplePlus = mySrcMergePlus.GetTriplestore()
        print("Len triplePlus:",len(triplePlus))

        lenSource1 = len(mySource1.GetTriplestore().GetInstances())
        lenSource2 = len(mySource2.GetTriplestore().GetInstances())
        lenPlus = len(triplePlus.GetInstances())
        # There is a margin because some instances could be created in the mean time.
        errorMargin = 20
        # In the merged link, there cannot be more instances than in the input sources.
        self.assertTrue(lenPlus <= lenSource1 + lenSource2 + errorMargin)

    def test_merge_sub_mixed(self):
        mySource1 = lib_client.SourceLocal(
            "entity.py",
            "CIM_LogicalDisk",
            DeviceID=AnyLogicalDisk)
        if is_platform_windows:
            mySource2 = lib_client.SourceRemote(RemoteTestAgent + "/survol/sources_types/win32/win32_local_groups.py")
        else:
            mySource2 = lib_client.SourceRemote(RemoteTestAgent + "/survol/sources_types/Linux/etc_group.py")

        mySrcMergeMinus = mySource1 - mySource2
        print("Merge Minus:",str(mySrcMergeMinus.content_rdf())[:30])
        tripleMinus = mySrcMergeMinus.GetTriplestore()
        print("Len tripleMinus:",len(tripleMinus))

        lenSource1 = len(mySource1.GetTriplestore().GetInstances())
        lenMinus = len(tripleMinus.GetInstances())
        # There cannot be more instances after removal.
        self.assertTrue(lenMinus <= lenSource1 )

    def test_remote_scripts_CIM_LogicalDisk(self):
        myAgent = lib_client.Agent(RemoteTestAgent)

        myInstancesRemoteDisk = myAgent.CIM_LogicalDisk(DeviceID=AnyLogicalDisk)
        listScriptsDisk = myInstancesRemoteDisk.GetScripts()
        # No scripts yet.
        self.assertTrue(len(listScriptsDisk) == 0)

    def test_remote_scripts_CIM_Directory(self):
        myAgent = lib_client.Agent(RemoteTestAgent)

        myInstancesRemoteDir = myAgent.CIM_Directory(Name=AnyLogicalDisk)
        listScriptsDir = myInstancesRemoteDir.GetScripts()

        if isVerbose:
            for keyScript in listScriptsDir:
                sys.stdout.write("    %s\n"%keyScript)
        # There should be at least a couple of scripts.
        self.assertTrue(len(listScriptsDir) > 0)

    def test_remote_agents(self):
        """Gets agents accessible of remote host, then accesses them one by one"""
        print("TODO: test_remote_agents not implemented yet")

class SurvolAzureTest(unittest.TestCase):
    """Testing Azure discovery"""

    def decorator_azure_subscription(test_func):
        """Returns first available Azure subscription from Credentials file"""

        try:
            import azure
        except ImportError:
            print("Module azure is not available so this test is not applicable")
            return None

        instancesAzureSubscriptions = ClientObjectInstancesFromScript(
            "sources_types/Azure/enumerate_subscription.py")

        # ['Azure/subscription.Subscription=Visual Studio Professional', 'CIM_ComputerSystem.Name=localhost']
        for oneInst in instancesAzureSubscriptions:
            # This returns the first subscription found.
            if oneInst.__class__.__name__ == "Azure/subscription":
                def wrapper(self):
                    test_func(self,oneInst.Subscription)
                return wrapper

        print("No Azure subscription available")
        return None

    @decorator_azure_subscription
    def test_azure_subscriptions(self,azureSubscription):
        print("Azure subscription:",azureSubscription)

    @decorator_azure_subscription
    def test_azure_locations(self,azureSubscription):
        """This checks Azure locations."""

        print("decorator_azure_subscription DISABLED")
        return

        lstInstances = ClientObjectInstancesFromScript(
            "sources_types/Azure/subscription/subscription_locations.py",
            "Azure/subscription",
            Subscription=azureSubscription)

        strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

        # Some locations are very common.
        for locationName in [
                'UK South',
                'West Central US',
                'West Europe' ]:
            entitySubscription = 'Azure/location.Subscription=%s,Location=%s' % ( azureSubscription, locationName )
            assert( entitySubscription in strInstancesSet)

    @decorator_azure_subscription
    def test_azure_subscription_disk(self,azureSubscription):
        """This checks Azure disks."""

        print("test_azure_subscription_disk DISABLED")
        return

        lstInstances = ClientObjectInstancesFromScript(
            "sources_types/Azure/subscription/subscription_disk.py",
            "Azure/subscription",
            Subscription=azureSubscription)

        strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

        print(strInstancesSet)

        # There should be at least one disk.
        assert( len(strInstancesSet) > 0)


class SurvolRabbitMQTest(unittest.TestCase):
    """Testing RabbitMQ discovery"""

    # Beware that it is called anyway for each function it is applied to,
    # even if the function is not called.
    def decorator_rabbitmq_subscription(test_func):
        """Returns first RabbitMQ subscription from Credentials file"""

        try:
            import pyrabbit
        except ImportError:
            print("Module pyrabbit is not available so this test is not applicable")
            return None

        instancesConfigurationsRabbitMQ = ClientObjectInstancesFromScript(
            "sources_types/rabbitmq/list_configurations.py")

        # ['Azure/subscription.Subscription=Visual Studio Professional', 'CIM_ComputerSystem.Name=localhost']
        for oneInst in instancesConfigurationsRabbitMQ:
            # This returns the first subscription found.
            if oneInst.__class__.__name__ == "rabbitmq/manager":
                def wrapper(self):
                    test_func(self,oneInst.Url)
                return wrapper

        print("No Azure subscription available")
        return None

    @decorator_rabbitmq_subscription
    def test_rabbitmq_subscriptions(self,rabbitmqManager):
        print("RabbitMQ:",rabbitmqManager)

    @decorator_rabbitmq_subscription
    def test_rabbitmq_connections(self,rabbitmqManager):
        print("RabbitMQ:",rabbitmqManager)

        lstInstances = ClientObjectInstancesFromScript(
            "sources_types/rabbitmq/manager/list_connections.py",
            "rabbitmq/manager",
            Url=rabbitmqManager)

        strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])
        print(strInstancesSet)

        # Typical content:
        # 'rabbitmq/manager.Url=localhost:12345',\
        # 'rabbitmq/user.Url=localhost:12345,User=guest',\
        # 'rabbitmq/connection.Url=localhost:12345,Connection=127.0.0.1:51752 -&gt; 127.0.0.1:5672',\
        # 'rabbitmq/connection.Url=localhost:12345,Connection=127.0.0.1:51641 -&gt; 127.0.0.1:5672'])

        # Typical content
        for oneStr in [
            'rabbitmq/manager.Url=%s' % rabbitmqManager,
            'rabbitmq/user.Url=%s,User=guest' % rabbitmqManager,
        ]:
            assert( oneStr in strInstancesSet)

    @decorator_rabbitmq_subscription
    def test_rabbitmq_exchanges(self,rabbitmqManager):
        print("RabbitMQ:",rabbitmqManager)

        lstInstances = ClientObjectInstancesFromScript(
            "sources_types/rabbitmq/manager/list_exchanges.py",
            "rabbitmq/manager",
            Url=rabbitmqManager)

        strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])
        print(strInstancesSet)

        # Typical content
        for oneStr in [
            'rabbitmq/exchange.Url=%s,VHost=/,Exchange=amq.match' % rabbitmqManager,
            'rabbitmq/exchange.Url=%s,VHost=/,Exchange=' % rabbitmqManager,
            'rabbitmq/exchange.Url=%s,VHost=/,Exchange=amq.topic' % rabbitmqManager,
            'rabbitmq/exchange.Url=%s,VHost=/,Exchange=amq.rabbitmq.trace' % rabbitmqManager,
            'rabbitmq/exchange.Url=%s,VHost=/,Exchange=amq.headers' % rabbitmqManager,
            'rabbitmq/exchange.Url=%s,VHost=/,Exchange=amq.rabbitmq.log' % rabbitmqManager,
            'rabbitmq/exchange.Url=%s,VHost=/,Exchange=amq.fanout' % rabbitmqManager,
            'rabbitmq/exchange.Url=%s,VHost=/,Exchange=amq.direct' % rabbitmqManager,
            'rabbitmq/vhost.Url=%s,VHost=/' % rabbitmqManager
        ]:
            assert( oneStr in strInstancesSet)

    @decorator_rabbitmq_subscription
    def test_rabbitmq_queues(self,rabbitmqManager):
        print("RabbitMQ:",rabbitmqManager)

        lstInstances = ClientObjectInstancesFromScript(
            "sources_types/rabbitmq/manager/list_queues.py",
            "rabbitmq/manager",
            Url=rabbitmqManager)

        # FIXME: Which queues should always be present ?
        strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])
        print("test_rabbitmq_queues strInstancesSet=", strInstancesSet)
        self.assertTrue('rabbitmq/vhost.Url=localhost:12345,VHost=/' in strInstancesSet)
        self.assertTrue('rabbitmq/manager.Url=localhost:12345' in strInstancesSet)


    @decorator_rabbitmq_subscription
    def test_rabbitmq_users(self,rabbitmqManager):
        print("RabbitMQ:",rabbitmqManager)

        lstInstances = ClientObjectInstancesFromScript(
            "sources_types/rabbitmq/manager/list_users.py",
            "rabbitmq/manager",
            Url=rabbitmqManager)

        strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])
        print(strInstancesSet)

        # Typical content
        for oneStr in [
            'rabbitmq/user.Url=%s,User=guest' % rabbitmqManager,
        ]:
            print(oneStr)
            assert(oneStr in strInstancesSet)


class SurvolOracleTest(unittest.TestCase):
    """Testing Oracle discovery"""

    def decorator_oracle_db(test_func):
        """Returns first Oracle connection from Credentials file"""
        global cx_Oracle_import_ok
        try:
            # This tests only once if this module can be imported.
            return cx_Oracle_import_ok
        except NameError:
            try:
                import cx_Oracle
                cx_Oracle_import_ok = True
            except ImportError as ex:
                print("Module cx_Oracle is not available so this test is not applicable:",ex    )
                cx_Oracle_import_ok = False
                return None

        instancesOracleDbs = ClientObjectInstancesFromScript(
            "sources_types/Databases/oracle_tnsnames.py")

        # Typical content: 'addr.Id=127.0.0.1:1521', 'oracle/db.Db=XE_WINDOWS',
        # 'oracle/db.Db=XE', 'oracle/db.Db=XE_OVH', 'addr.Id=vps516494.ovh.net:1521',
        # 'addr.Id=192.168.0.17:1521', 'oracle/db.Db=XE_FEDORA'}

        # Sorted in alphabetical order.
        strInstances = sorted([str(oneInst.Db) for oneInst in instancesOracleDbs if oneInst.__class__.__name__ == "oracle/db"])

        if strInstances:
            # This returns the first database found in the credentials file in alphabetical order.
            def wrapper(self):
                test_func(self,strInstances[0])
            wrapper.__doc__ = test_func.__doc__
            return wrapper
            # return strInstances[0]

        print("No Oracle database available")
        return None

    @decorator_oracle_db
    def test_oracle_databases(self,oracleDb):
        """Check there is at least one connection."""
        print("Oracle:",oracleDb)

    @decorator_oracle_db
    def test_oracle_schemas(self,oracleDb):
        print("Oracle:",oracleDb)

        lstInstances = ClientObjectInstancesFromScript(
            "sources_types/oracle/db/oracle_db_schemas.py",
            "oracle/db",
            Db=oracleDb)

        strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

        # Typical content:
        for oneStr in [
            'oracle/schema.Db=%s,Schema=SYSTEM' % oracleDb,
            'oracle/schema.Db=%s,Schema=ANONYMOUS' % oracleDb,
            'oracle/schema.Db=%s,Schema=SYS' % oracleDb,
        ]:
            assert( oneStr in strInstancesSet)

    @decorator_oracle_db
    def test_oracle_connected_processes(self,oracleDb):
        print("Oracle:",oracleDb)

        lstInstances = ClientObjectInstancesFromScript(
            "sources_types/oracle/db/oracle_db_processes.py",
            "oracle/db",
            Db=oracleDb)

        strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

        print(strInstancesSet)

        # Typical content:
        # 'CIM_Process.Handle=11772', 'oracle/db.Db=XE', 'Win32_UserAccount.Name=rchateau,Domain=rchateau-hp',
        # 'oracle/schema.Db=XE,Schema=SYSTEM', 'oracle/session.Db=XE,Session=102'
        for oneStr in [
            CurrentProcessPath,
            'oracle/db.Db=%s' % oracleDb,
            'Win32_UserAccount.Name=%s,Domain=%s' % ( CurrentUsername, CurrentMachine),
        ]:
            assert( oneStr in strInstancesSet)

    @decorator_oracle_db
    def test_oracle_running_queries(self,oracleDb):
        print("Oracle:",oracleDb)

        lstInstances = ClientObjectInstancesFromScript(
            "sources_types/oracle/db/oracle_db_parse_queries.py",
            "oracle/db",
            Db=oracleDb)

        # Typical content:
        # ['oracle/db.Db=XE_OVH', 'oracle/query.Query=ICBTRUxF... base64 ...ZGRyICA=,Db=XE_OVH']

        for oneInst in lstInstances:
            if oneInst.__class__.__name__ == 'oracle/query':
                import sources_types.oracle.query
                print("Decoded query:",sources_types.oracle.query.EntityName( [oneInst.Query,oneInst.Db] ))

                # TODO: This is not very consistent: sources_types.oracle.query.EntityName
                # TODO: produces a nice but truncated message, and the relation between
                # TODO: oracle.query and sql.query is not obvious.
                import sources_types.sql.query
                qryDecodedFull = sources_types.sql.query.EntityName( [oneInst.Query] )
                print("Decoded query:",qryDecodedFull)
                # The query must start with a select.
                assert( qryDecodedFull.strip().upper().startswith("SELECT"))

                # TODO: Parse the query ? Or extracts its dependencies ?


    @decorator_oracle_db
    def test_oracle_schema_tables(self,oracleDb):
        print("Oracle:",oracleDb)

        lstInstances = ClientObjectInstancesFromScript(
            "sources_types/oracle/schema/oracle_schema_tables.py",
            "oracle/db",
            Db=oracleDb,
        Schema='SYSTEM')

        strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

        print(strInstancesSet)

        # Various tables which should always be in 'SYSTEM' namespace:
        for oneStr in [
            'oracle/table.Db=%s,Schema=SYSTEM,Table=HELP' % oracleDb,
            #'oracle/table.Db=%s,Schema=SYSTEM,Table=REPCAT$_COLUMN_GROUP' % oracleDb,
            #'oracle/table.Db=%s,Schema=SYSTEM,Table=MVIEW$_ADV_WORKLOAD' % oracleDb,
        ]:
            assert( oneStr in strInstancesSet)

    @decorator_oracle_db
    def test_oracle_schema_views(self,oracleDb):
        print("Oracle:",oracleDb)

        lstInstances = ClientObjectInstancesFromScript(
            "sources_types/oracle/schema/oracle_schema_views.py",
            "oracle/db",
            Db=oracleDb,
            Schema='SYS')

        strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

        print(sorted(strInstancesSet)[:10])

        # Various tables which should always be in 'SYSTEM' namespace:
        for oneStr in [
            'oracle/view.Db=%s,Schema=SYS,View=ALL_ALL_TABLES' % oracleDb,
            #'oracle/table.Db=%s,Schema=SYSTEM,Table=REPCAT$_COLUMN_GROUP' % oracleDb,
            #'oracle/table.Db=%s,Schema=SYSTEM,Table=MVIEW$_ADV_WORKLOAD' % oracleDb,
        ]:
            assert( oneStr in strInstancesSet)

    @decorator_oracle_db
    def test_oracle_view_dependencies(self,oracleDb):
        """Dsplays dependencies of a very common view"""

        lstInstances = ClientObjectInstancesFromScript(
            "sources_types/oracle/view/oracle_view_dependencies.py",
            "oracle/db",
            Db=oracleDb,
            Schema='SYS',
            View='ALL_ALL_TABLES')

        strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

        print(sorted(strInstancesSet)[:10])

        # The dependencies of this view should always be the same,as it does not change often.
        for oneStr in [
            'oracle/schema.Db=%s,Schema=SYS' % oracleDb,
            'oracle/synonym.Db=%s,Schema=PUBLIC,Synonym=ALL_ALL_TABLES' % oracleDb,
            'oracle/view.Db=%s,Schema=SYS,View=ALL_ALL_TABLES' % oracleDb,
            'oracle/view.Db=%s,Schema=SYS,View=ALL_OBJECT_TABLES' % oracleDb,
            'oracle/view.Db=%s,Schema=SYS,View=ALL_TABLES' % oracleDb,
        ]:
            assert( oneStr in strInstancesSet)

class SurvolPEFileTest(unittest.TestCase):
    """Testing pefile features"""

    @unittest.skipIf(not pkgutil.find_loader('pefile'), "pefile cannot be imported. test_pefile_exports not run.")
    def test_pefile_exports(self):
        """Tests exported functions of a DLL."""

        # Very common DLL.
        dllFileName = r"C:\Windows\System32\gdi32.dll"

        lstInstances = ClientObjectInstancesFromScript(
            "sources_types/CIM_DataFile/portable_executable/pefile_exports.py",
            "CIM_DataFile",
            Name=dllFileName)

        import sources_types.linker_symbol
        namesInstance = set()

        for oneInst in lstInstances:
            if oneInst.__class__.__name__ == 'linker_symbol':
                instName = sources_types.linker_symbol.EntityName( [oneInst.Name,oneInst.File] )
                namesInstance.add(instName)

        # Some exported functiosn which should be there.
        for oneStr in [
            "CreateBitmapFromDxSurface",
            "DeleteDC",
            "GdiCreateLocalMetaFilePict",
            "ClearBitmapAttributes",
            "GetViewportOrgEx",
            "GdiDescribePixelFormat",
            "OffsetViewportOrgEx",
        ]:
            assert( oneStr in namesInstance)


class SurvolSearchTest(unittest.TestCase):

    # TODO: This is broken.
    # TODO: This is broken.
    # TODO: This is broken.
    # TODO: This is broken.
    # TODO: This is broken.
    # TODO: Make a simpler test with a fake class and a single script.

    # TODO: Consider using ldspider which is a much better long-term approach.
    # TODO: Should test the individual scripts, but replace the search algorithm.

    """Testing the search engine"""
    def test_search_local_string_flat(self):
        """Searches for a string in one file only. Two occurrences."""

        sampleFile = os.path.join( os.path.dirname(__file__), "SampleDir", "SampleFile.txt" )
        instanceOrigin = lib_client.Agent().CIM_DataFile(Name=sampleFile)

        searchTripleStore = instanceOrigin.FindStringFromNeighbour(searchString="Maecenas",maxDepth=1,filterInstances=None,filterPredicates=None)

        results = list(searchTripleStore)

        print(results)
        assert( len(results) == 2)
        # The line number and occurrence number are concatenated after the string.
        assert( str(results[0][2]).encode("utf-8").startswith( "Maecenas".encode("utf-8")) )
        assert( str(results[1][2]).encode("utf-8").startswith( "Maecenas".encode("utf-8")) )


    def test_search_local_string_one_level(self):
        """Searches for a string in all files of one directory."""

        # There are not many files in this directory
        sampleDir = os.path.join( os.path.dirname(__file__), "SampleDir" )
        instanceOrigin = lib_client.Agent().CIM_Directory(Name=sampleDir)

        mustFind = "Drivers"

        searchTripleStore = instanceOrigin.FindStringFromNeighbour(searchString="Curabitur",maxDepth=2,filterInstances=None,filterPredicates=None)
        list_triple = list(searchTripleStore)
        print("stl_list=",list_triple)
        for tpl in list_triple:
            # One occurrence is enough for this test.
            print(tpl)
            break
        # tpl # To check if a result was found.

    # TODO: Remove search and instead use a Linked Data crawler such as https://github.com/ldspider/ldspider
    # TODO: ... or simply SparQL.
    def test_search_local_string(self):
        """Loads instances connected to an instance by every available script"""

        instanceOrigin = lib_client.Agent().CIM_Directory(
            Name="C:/Windows")

        # The service "PlugPlay" should be available on all Windows machines.
        listInstances = {
            lib_client.Agent().CIM_Directory(Name="C:/Windows/winxs"),
            lib_client.Agent().CIM_Directory(Name="C:/windows/system32"),
            lib_client.Agent().CIM_DataFile(Name="C:/Windows/epplauncher.mif"),
            lib_client.Agent().CIM_DataFile(Name="C:/Windows/U2v243.exe"),
        }

        listPredicates = {
            lib_properties.pc.property_directory,
        }

        mustFind = "Hello"

        searchTripleStore = instanceOrigin.FindStringFromNeighbour(searchString=mustFind,maxDepth=3,filterInstances=listInstances,filterPredicates=listPredicates)
        for tpl in searchTripleStore:
            print(tpl)

# Tests an internal URL
class SurvolInternalTest(unittest.TestCase):
    def check_internal_values(self,anAgentStr):

        anAgent = lib_client.Agent(anAgentStr)
        mapInternalData = anAgent.GetInternalData()

        # http://192.168.0.14/Survol/survol/print_internal_data_as_json.py
        # http://rchateau-hp:8000/survol/print_internal_data_as_json.py

        # RootUri              http://192.168.0.14:80/Survol/survol/print_internal_data_as_json.py
        # uriRoot              http://192.168.0.14:80/Survol/survol
        # HttpPrefix           http://192.168.0.14:80
        # RequestUri           /Survol/survol/print_internal_data_as_json.py
        #
        # RootUri              http://rchateau-HP:8000/survol/print_internal_data_as_json.py
        # uriRoot              http://rchateau-HP:8000/survol
        # HttpPrefix           http://rchateau-HP:8000
        # RequestUri           /survol/print_internal_data_as_json.py

        # RootUri              http://192.168.0.14:80/Survol/survol/Survol/survol/print_internal_data_as_json.py
        # uriRoot              http://192.168.0.14:80/Survol/survol
        # HttpPrefix           http://192.168.0.14:80
        # RequestUri           /Survol/survol/print_internal_data_as_json.py
        #
        # RootUri              http://rchateau-HP:8000/survol/survol/print_internal_data_as_json.py
        # uriRoot              http://rchateau-HP:8000/survol
        # HttpPrefix           http://rchateau-HP:8000
        # RequestUri           /survol/print_internal_data_as_json.py

        print("")
        print("CurrentMachine=", CurrentMachine)
        print("anAgentStr=", anAgentStr)
        for key in mapInternalData:
            print("%-20s %20s"%(key, mapInternalData[key]))

        #"uriRoot": lib_util.uriRoot,
        #"HttpPrefix": lib_util.HttpPrefix(),
        #"RootUri": lib_util.RootUri(),
        #"RequestUri": lib_util.RequestUri()

        # This breaks on Linux Python 3:
        # "http://localhost:8000/survol"
        # "http://travis-job-051017ff-a582-4258-a817-d9cd836533a6:8000/survol"
        print("RootUri=",mapInternalData["RootUri"])
        print("anAgentStr=",anAgentStr)

        self.assertTrue(mapInternalData["uriRoot"] == anAgentStr + "/survol")

        # When the agent is started automatically, "?xid=" is added at the end of the URL.
        # http://rchateau-hp:8000/survol/print_internal_data_as_json.py?xid=
        # This adds lib_util.xidCgiDelimiter at the end.
        assert(mapInternalData["RootUri"] == anAgentStr + "/survol/print_internal_data_as_json.py" + "?xid=")

    def test_internal_remote(self):
        self.check_internal_values(RemoteTestAgent)

    @unittest.skipIf(is_travis_machine(), "Cannot run Apache test on TravisCI.")
    def test_internal_apache(self):
        # http://192.168.0.14/Survol/survol/entity.py

        # TODO: This should be a parameter. This is an Apache server pointing on the current directory.
        # This should behave exactly like the CGI server. It needs the default HTTP port.
        # The key is the return value of socket.gethostname().lower()
        try:
            RemoteTestApacheAgent = {
                "rchateau-hp": "http://192.168.1.10:80/Survol",
                "vps516494.localdomain": SurvolServerAgent}[CurrentMachine]
            self.check_internal_values(RemoteTestApacheAgent)
        except KeyError:
            print("test_internal_apache cannot be run on machine:",CurrentMachine)
            return True


if __name__ == '__main__':
    unittest.main()

# TODO: Test calls to <Any class>.AddInfo()
# TODO: When double-clicking any Python script, it should do something visible.

