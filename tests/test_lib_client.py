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
import pkgutil

from init import *

# This loads the module from the source, so no need to install it, and no need of virtualenv.
update_test_path()

import lib_client
import lib_common
import lib_properties

# If the Survol agent does not exist, this script starts a local one.
RemoteAgentProcess = None
_remote_general_test_agent = "http://%s:%d" % (CurrentMachine, RemoteGeneralTestServerPort)

is_platform_windows_and_wmi = is_platform_windows and pkgutil.find_loader('wmi')

mandatory_cmd_exe = "C:/Windows/SysWOW64/cmd.exe" if is_32_bits else r'C:/Windows/System32/cmd.exe'

def setUpModule():
    global RemoteAgentProcess
    RemoteAgentProcess, _agent_url = start_cgiserver(RemoteGeneralTestServerPort)


def tearDownModule():
    global RemoteAgentProcess
    stop_cgiserver(RemoteAgentProcess)


_is_verbose = ('-v' in sys.argv) or ('--verbose' in sys.argv)

# This deletes the module so we can reload them each time.
# Problem: survol modules are not detectable.
# We could as well delete all modules except sys.
## allModules = [modu for modu in sys.modules if modu.startswith(("survol","lib_"))]

ClientObjectInstancesFromScript = lib_client.SourceLocal.get_object_instances_from_script

# Otherwise, Python callstack would be displayed in HTML.
cgitb.enable(format="txt")

# TODO: Prefix of url samples should be a parameter.


class SurvolLocalTest(unittest.TestCase):
    """These tests do not need a Survol agent"""

    def test_create_source_local_json(self):
        my_source_file_stat_local = lib_client.SourceLocal(
            "sources_types/CIM_DataFile/file_stat.py",
            "CIM_DataFile",
            Name=always_present_file)
        print("test_create_source_local_json: query==%s" % my_source_file_stat_local.create_url_query())
        the_content_json = my_source_file_stat_local.content_json()
        print("test_create_source_local_json: Json content=%s ..."%str(the_content_json)[:100])
        self.assertTrue(the_content_json['page_title'].startswith("File stat information"))

    def test_create_source_local_rdf(self):
        my_source_file_stat_local = lib_client.SourceLocal(
            "sources_types/CIM_DataFile/file_stat.py",
            "CIM_DataFile",
            Name=always_present_file)
        print("test_create_source_local_rdf: query=%s" % my_source_file_stat_local.create_url_query())
        the_content_rdf = my_source_file_stat_local.content_rdf()
        print("test_create_source_local_rdf: RDF content=%s ..."%str(the_content_rdf)[:30])

    def test_local_triplestore(self):
        my_source_file_stat_local = lib_client.SourceLocal(
            "sources_types/CIM_DataFile/file_stat.py",
            "CIM_DataFile",
            Name=always_present_file)
        triple_file_stat_local = my_source_file_stat_local.get_triplestore()
        print("Len triple store local=", len(triple_file_stat_local.m_triplestore))
        # A lot of element.
        self.assertTrue(len(triple_file_stat_local.m_triplestore) > 10)

    def test_local_instances(self):
        my_source_file_stat_local = lib_client.SourceLocal(
            "sources_types/CIM_DataFile/file_stat.py",
            "CIM_DataFile",
            Name=always_present_file)

        lib_common.globalErrorMessageEnabled = False

        triple_file_stat_local = my_source_file_stat_local.get_triplestore()
        print("Len triple_file_stat_local=",len(triple_file_stat_local))

        # Typical output:
        #     Win32_Group.Domain=NT SERVICE,Name=TrustedInstaller
        #     CIM_Directory.Name=C:/
        #     CIM_Directory.Name=C:/Windows
        #     CIM_DataFile.Name=C:/Windows/explorer.exe
        instances_file_stat_local = triple_file_stat_local.get_instances()

        len_instances = len(instances_file_stat_local)
        sys.stdout.write("Len triple_file_stat_local=%s\n"%len_instances)
        for one_inst in instances_file_stat_local:
            sys.stdout.write("    %s\n"%str(one_inst))
        # This file should be there on any Windows machine.
        self.assertTrue(len_instances >= 1)

    def test_local_json(self):
        # Test merge of heterogeneous data sources.
        my_source1 = lib_client.SourceLocal(
            "entity.py",
            "CIM_LogicalDisk",
            DeviceID=AnyLogicalDisk)

        content1 = my_source1.content_json()
        print( "content1=", str(content1.keys()))
        self.assertEqual(sorted(content1.keys()), ['links', 'nodes', 'page_title'])

    def test_merge_add_local(self):
        my_source1 = lib_client.SourceLocal(
            "entity.py",
            "CIM_DataFile",
            Name=always_present_file)
        # The current process is always available.
        mySource2 = lib_client.SourceLocal(
            "entity.py",
            "CIM_Process",
            Handle=CurrentPid)

        my_src_merge_plus = my_source1 + mySource2
        triple_plus = my_src_merge_plus.get_triplestore()
        print("Len triple_plus:",len(triple_plus))

        len_source1 = len(my_source1.get_triplestore().get_instances())
        len_source2 = len(mySource2.get_triplestore().get_instances())
        len_plus = len(triple_plus.get_instances())
        # In the merged link, there cannot be more instances than in the input sources.
        self.assertTrue(len_plus <= len_source1 + len_source2)

    @unittest.skipIf(not pkgutil.find_loader('win32net'), "Cannot import win32net. test_merge_sub_local not run.")
    def test_merge_sub_local(self):
        my_source1 = lib_client.SourceLocal(
            "entity.py",
            "CIM_LogicalDisk",
            DeviceID=AnyLogicalDisk)
        my_source2 = lib_client.SourceLocal(
            "sources_types/win32/win32_local_groups.py")

        my_src_merge_minus = my_source1 - my_source2
        print("Merge Minus:",str(my_src_merge_minus.content_rdf())[:30])
        triple_minus = my_src_merge_minus.get_triplestore()
        print("Len triple_minus:",len(triple_minus))

        len_source1 = len(my_source1.get_triplestore().get_instances())
        len_minus = len(triple_minus.get_instances())
        # There cannot be more instances after removal.
        self.assertTrue(len_minus <= len_source1 )

    @unittest.skipIf(not pkgutil.find_loader('win32api'), "Cannot import win32api. test_merge_duplicate not run.")
    def test_merge_duplicate(self):
        my_source_dupl = lib_client.SourceLocal(
            "sources_types/Win32_UserAccount/Win32_NetUserGetGroups.py",
            "Win32_UserAccount",
            Domain=CurrentMachine,
            Name=CurrentUsername)
        triple_dupl = my_source_dupl.get_triplestore()
        print("Len triple_dupl=",len(triple_dupl.get_instances()))

        my_src_merge_plus = my_source_dupl + my_source_dupl
        triple_plus = my_src_merge_plus.get_triplestore()
        print("Len triple_plus=",len(triple_plus.get_instances()))
        # No added node.
        self.assertEqual(len(triple_plus.get_instances()), len(triple_dupl.get_instances()))

        my_src_merge_minus = my_source_dupl - my_source_dupl
        triple_minus = my_src_merge_minus.get_triplestore()
        print("Len triple_minus=",len(triple_minus.get_instances()))
        self.assertEqual(len(triple_minus.get_instances()), 0)

    def test_exception_bad_source(self):
        """This tests if errors are properly displayed and an exception is raised."""
        my_source_bad = lib_client.SourceLocal(
            "xxx/yyy/zzz.py",
            "this-will-raise-an-exception")
        try:
            my_source_bad.get_triplestore()
        except Exception as exc:
            print("Error detected:",exc)

        my_source_broken = lib_client.SourceRemote(
            _remote_general_test_agent + "/xxx/yyy/zzz/ttt.py",
            "wwwww")
        with self.assertRaises(Exception):
            my_source_broken.get_triplestore()

    @unittest.skipIf(not is_platform_windows, "test_local_scripts_UserAccount for Windows only.")
    def test_local_scripts_UserAccount(self):
        """Returns all scripts accessible from current user account."""

        my_instances_local = lib_client.Agent().Win32_UserAccount(
            Domain=CurrentMachine,
            Name=CurrentUsername)

        list_scripts = my_instances_local.get_scripts()
        if _is_verbose:
            sys.stdout.write("Scripts:\n")
            for one_scr in list_scripts:
                sys.stdout.write("    %s\n"%one_scr)
        # There should be at least a couple of scripts.
        self.assertTrue(len(list_scripts) > 0)

    def test_grep_string(self):
        """Searches for printable strings in a file"""

        sample_file = os.path.join(os.path.dirname(__file__), "SampleDir", "SampleFile.txt")
        sample_file = lib_util.standardized_file_path(sample_file)

        my_source_grep = lib_client.SourceLocal(
            "sources_types/CIM_DataFile/grep_text_strings.py",
            "CIM_DataFile",
            Name=sample_file)

        triple_grep = my_source_grep.get_triplestore()

        matching_triples = triple_grep.get_matching_strings_triples("[Pp]ellentesque")

        lst_strings_only = sorted([trp_obj.value for trp_subj, trp_pred, trp_obj in matching_triples])

        assert(lst_strings_only == [
            u'Pellentesque;14;94',
            u'Pellentesque;6;36',
            u'Pellentesque;8;50',
            u'pellentesque;10;66',
            u'pellentesque;14;101'])

    @unittest.skipIf(not pkgutil.find_loader('win32net'), "test_local_groups_local_scripts needs win32net.")
    def test_local_groups_local_scripts(self):
        """Loads the scripts of instances displayed by an initial script"""

        # This is a top-level script.
        my_source_top_level_local = lib_client.SourceLocal(
            "sources_types/win32/win32_local_groups.py")

        triple_top_level_local = my_source_top_level_local.get_triplestore()
        instances_top_level_local = triple_top_level_local.get_instances()
        print("Instances number:", len(instances_top_level_local))

        class_names_set = {'CIM_ComputerSystem', 'Win32_Group', 'Win32_UserAccount'}
        for one_instance in instances_top_level_local:
            print("    Instance: %s" % str(one_instance))
            print("    Instance Name: %s" % one_instance.__class__.__name__)
            self.assertTrue(one_instance.__class__.__name__ in class_names_set)
            list_scripts = one_instance.get_scripts()
            for one_script in list_scripts:
                print("        %s" % one_script)

    @unittest.skipIf(not pkgutil.find_loader('win32service'), "test_scripts_of_local_instance needs win32service.")
    def test_scripts_of_local_instance(self):
        """This loads scripts of a local instance"""

        # The service "PlugPlay" should be available on all Windows machines.
        my_instance_local = lib_client.Agent().Win32_Service(
            Name="PlugPlay")

        list_scripts = my_instance_local.get_scripts()

        if _is_verbose:
            sys.stdout.write("Scripts:\n")
            for one_scr in list_scripts:
                sys.stdout.write("    %s\n"%one_scr)
        # There should be at least a couple of scripts.
        self.assertTrue(len(list_scripts) > 0)
        # TODO: Maybe this script will not come first in the future.
        self.assertEqual(list_scripts[0].create_url_query(), "xid=Win32_Service.Name=PlugPlay")
        self.assertEqual(list_scripts[0].m_script, "sources_types/Win32_Service/service_dependencies.py")

    def test_instances_cache(self):
        instance_a = lib_client.Agent().CIM_Directory(Name="C:/Windows")
        instance_b = lib_client.Agent().CIM_Directory(Name="C:/Windows")
        instance_c = lib_client.create_CIM_class(None, "CIM_Directory", Name="C:/Windows")
        if _is_verbose:
            sys.stdout.write("Class=%s\n" % instance_c.__class__.__name__)
            sys.stdout.write("Module=%s\n" % instance_c.__module__)
            sys.stdout.write("Dir=%s\n\n" % str(dir(lib_client)))
            sys.stdout.write("Dir=%s\n" % str(sorted(globals())))

        self.assertTrue(instance_a is instance_b)
        self.assertTrue(instance_a is instance_c)
        self.assertTrue(instance_c is instance_b)

    # This searches the content of a file which contains SQL queries.
    @unittest.skipIf(not pkgutil.find_loader('sqlparse'), "Cannot import sqlparse. test_regex_sql_query_file not run.")
    def test_regex_sql_query_file(self):
        """Searches for SQL queries in one file only."""

        sql_path_name = os.path.join(os.path.dirname(__file__), "SampleDirScripts", "SamplePythonFile.py")

        mySourceSqlQueries = lib_client.SourceLocal(
            "sources_types/CIM_DataFile/grep_sql_queries.py",
            "CIM_DataFile",
            Name=sql_path_name)

        triple_sql_queries = mySourceSqlQueries.get_triplestore()
        if _is_verbose:
            print("Len triple_sql_queries=",len(triple_sql_queries.m_triplestore))

        matching_triples = triple_sql_queries.get_all_strings_triples()

        lst_queries_only = sorted(matching_triples)

        if _is_verbose:
            print("lst_queries_only:",lst_queries_only)

        # TODO: Eliminate the last double-quote.
        lst_qries_present = [
            u'select * from \'AnyTable\'"',
            u'select A.x,B.y from AnyTable A, OtherTable B"',
            u'select a,b,c from \'AnyTable\'"']
        for one_qry in lst_qries_present:
            self.assertTrue(one_qry in lst_queries_only)

    def test_open_files_from_python_with_shell(self):
        """Files open by a Python process started in a shell"""
        sql_path_name = os.path.join(os.path.dirname(__file__), "SampleDirScripts", "SamplePythonFile.py")

        exec_list = [sys.executable, sql_path_name]

        proc_open = subprocess.Popen(
            exec_list,
            shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0)

        print("Started process:", exec_list, " pid=", proc_open.pid)

        my_source_sql_queries = lib_client.SourceLocal(
            "sources_types/CIM_Process/process_open_files.py",
            "CIM_Process",
            Handle=proc_open.pid)

        triple_open_files = my_source_sql_queries.get_triplestore()
        lst_instances = triple_open_files.get_instances()
        str_instances_set = set([str(oneInst) for oneInst in lst_instances])
        print("str_instances_set=", str_instances_set)

        # Some instances are required.
        # TODO: Add the Python file.
        lst_mandatory_instances = [
            "CIM_Process.Handle=%d"%proc_open.pid,
            CurrentUserPath]
        if is_platform_windows:
            lst_mandatory_instances += [
                    # Slashes instead of backslashes, as is always the case in Survol.
                    "CIM_DataFile.Name=%s" % mandatory_cmd_exe]
        # On Linux, we do not know which Shell is used to start the command.

        print("lst_mandatory_instances=", lst_mandatory_instances)
        for one_str in lst_mandatory_instances:
            print("    ", one_str)
            self.assertTrue(one_str in str_instances_set)

        proc_open.communicate()

    def test_open_files_from_python_without_shell(self):
        """Files open by a Python process started in a shell"""
        sql_path_name = os.path.join(os.path.dirname(__file__), "SampleDirScripts", "SamplePythonFile.py")

        exec_list = [sys.executable, sql_path_name]

        proc_open = subprocess.Popen(
            exec_list,
            shell=False,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0)

        print("Started process:", exec_list, " pid=", proc_open.pid)

        my_source_sql_queries = lib_client.SourceLocal(
            "sources_types/CIM_Process/process_open_files.py",
            "CIM_Process",
            Handle=proc_open.pid)

        triple_open_files = my_source_sql_queries.get_triplestore()
        lst_instances = triple_open_files.get_instances()
        str_instances_set = set([str(oneInst) for oneInst in lst_instances])
        print("str_instances_set=", str_instances_set)

        # Some instances are required.
        # TODO: Add the Python file.
        lst_mandatory_instances = [
            "CIM_Process.Handle=%d"%proc_open.pid,
            CurrentUserPath,
            CurrentExecutablePath]
        #if is_platform_windows:
        #    lst_mandatory_instances += [
        #            # Slashes instead of backslashes, as is always the case in Survol.
        #            "CIM_DataFile.Name=%s" % sys.executable]
        # On Linux, we do not know which Shell is used to start the command.

        print("lst_mandatory_instances=", lst_mandatory_instances)
        for one_str in lst_mandatory_instances:
            self.assertTrue(one_str in str_instances_set)

        proc_open.communicate()

    def test_sub_parent_from_python_process(self):
        """Sub and parent processes a Python process"""
        sql_path_name = os.path.join( os.path.dirname(__file__), "SampleDirScripts", "SamplePythonFile.py")

        exec_list = [sys.executable, sql_path_name]

        proc_open = subprocess.Popen(
            exec_list,
            shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0)

        print("Started process:", exec_list, " pid=", proc_open.pid)

        my_source_processes = lib_client.SourceLocal(
            "sources_types/CIM_Process/single_pidstree.py",
            "CIM_Process",
            Handle=proc_open.pid)

        triple_processes = my_source_processes.get_triplestore()

        lst_instances = triple_processes.get_instances()
        str_instances_set = set([str(oneInst) for oneInst in lst_instances])

        # Some instances are required.
        lst_mandatory_instances = [
            CurrentProcessPath, # This is the parent process.
            "CIM_Process.Handle=%d"%proc_open.pid,
            CurrentUserPath ]
        if is_platform_windows:
            lst_mandatory_instances += [
                    "CIM_DataFile.Name=%s" % mandatory_cmd_exe]
        else:
            lst_mandatory_instances += [
                    CurrentExecutablePath]
        for one_str in lst_mandatory_instances:
            self.assertTrue(one_str in str_instances_set)

        proc_open.communicate()

    def test_memory_maps_from_python_process(self):
        """Sub and parent processes a Python process"""
        sql_path_name = os.path.join(os.path.dirname(__file__), "SampleDirScripts", "SamplePythonFile.py")

        exec_list = [sys.executable, sql_path_name]

        proc_open = subprocess.Popen(
            exec_list,
            shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0)

        print("Started process:",exec_list," pid=",proc_open.pid)

        # Give a bit of time so the process is fully init.
        time.sleep(1)

        my_source_mem_maps = lib_client.SourceLocal(
            "sources_types/CIM_Process/process_memmaps.py",
            "CIM_Process",
            Handle=proc_open.pid)

        triple_mem_maps = my_source_mem_maps.get_triplestore()

        lst_instances = triple_mem_maps.get_instances()
        str_instances_set = set([str(oneInst) for oneInst in lst_instances])

        print("Instances=",str_instances_set)

        # Some instances are required.
        lst_mandatory_instances = [
            'CIM_Process.Handle=%s'%proc_open.pid]
        lst_mandatory_regex = []

        if is_platform_windows:
            # This is common to Windows 7 and Windows 8.
            lst_mandatory_instances += [
                'memmap.Id=C:/Windows/Globalization/Sorting/SortDefault.nls',
                'memmap.Id=C:/Windows/System32/kernel32.dll',
                'memmap.Id=C:/Windows/System32/locale.nls',
                'memmap.Id=C:/Windows/System32/ntdll.dll',
                'memmap.Id=C:/Windows/System32/KernelBase.dll',
                'memmap.Id=C:/Windows/System32/msvcrt.dll',
                'memmap.Id=C:/Windows/System32/cmd.exe',
                ]
        else:
            lst_mandatory_instances += [
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
            lst_mandatory_regex += [
                r'memmap.Id=.*/ld-.*\.so.*',
                r'memmap.Id=.*/libc-.*\.so.*',
            ]

            for one_str in lst_mandatory_instances:
                if one_str not in str_instances_set:
                    WARNING("Cannot find %s in %s", one_str, str(str_instances_set))
                self.assertTrue(one_str in str_instances_set)

            # This is much slower, beware.
            for oneRegex in lst_mandatory_regex:
                re_prog = re.compile(oneRegex)
                for one_str in str_instances_set:
                    result = re_prog.match(one_str)
                    if result:
                        break
                if not result:
                    WARNING("Cannot find regex %s in %s", oneRegex, str(str_instances_set))
                self.assertTrue(result is not None)

        proc_open.communicate()

    def _check_environment_variables(self, process_id):
        my_source_env_vars = lib_client.SourceLocal(
            "sources_types/CIM_Process/environment_variables.py",
            "CIM_Process",
            Handle=process_id)

        triple_env_vars = my_source_env_vars.get_triplestore()

        print("triple_env_vars:",triple_env_vars)

        # The environment variables are returned in various ways,
        # but it is guaranteed that some of them are always present.
        set_env_vars = set(triple_env_vars.get_all_strings_triples())

        print("set_env_vars:", set_env_vars)

        if is_platform_windows:
            mandatory_env_vars = ['COMPUTERNAME','OS','PATH']
        else:
            mandatory_env_vars = ['HOME','PATH']

        print("set_env_vars:",set_env_vars)

        for one_var in mandatory_env_vars:
            self.assertTrue(one_var in set_env_vars)

    @unittest.skipIf(not pkgutil.find_loader('psutil'), "test_environment_from_batch_process needs psutil.")
    def test_environment_from_batch_process(self):
        """Tests that we can read a process'environment variables"""

        if is_platform_windows:
            command_example = "CommandExample.bat"
        else:
            command_example = "CommandExample.sh"
        script_path_name = os.path.join( os.path.dirname(__file__), "SampleDirScripts", command_example)

        exec_list = [script_path_name]

        # Runs this process: It allocates a variable containing a SQL query, then it waits.
        proc_open = subprocess.Popen(
            exec_list,
            shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)

        print("Started process:",exec_list," pid=",proc_open.pid)

        (child_stdin, child_stdout_and_stderr) = (proc_open.stdin, proc_open.stdout)

        self._check_environment_variables(proc_open.pid)

        if is_platform_windows:
            # Any string will do: This stops the subprocess which is waiting for an input.
            child_stdin.write("Stop".encode())

    @unittest.skipIf(not pkgutil.find_loader('psutil'), "test_environment_from_current_process needs psutil.")
    def test_environment_from_current_process(self):
        """Tests that we can read current process'environment variables"""

        self._check_environment_variables(CurrentPid)

    def test_python_package_information(self):
        """Tests Python package information"""

        my_source_python_package = lib_client.SourceLocal(
            "entity.py",
            "python/package",
            Id="rdflib")

        triple_python_package = my_source_python_package.get_triplestore()

        lst_instances = triple_python_package.get_instances()
        str_instances_set = set([str(oneInst) for oneInst in lst_instances ])

        DEBUG("str_instances_set=%s", str_instances_set)

        # Checks the presence of some Python dependencies, true for all Python versions and OS platforms.
        for one_str in [
            'CIM_ComputerSystem.Name=%s' % CurrentMachine,
            'python/package.Id=isodate',
            'python/package.Id=pyparsing',
            'python/package.Id=rdflib',
            CurrentUserPath ]:
            DEBUG("one_str=%s", one_str)
            self.assertTrue(one_str in str_instances_set)

    def test_python_current_script(self):
        """Examines a running Python process"""

        # This creates a process running in Python, because it does not work with the current process.
        sql_path_name = os.path.join(os.path.dirname(__file__), "SampleDirScripts", "SamplePythonFile.py")

        exec_list = [sys.executable, sql_path_name]

        proc_open = subprocess.Popen(
            exec_list,
            shell=False,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0)

        print("Started process:", exec_list," pid=", proc_open.pid)

        # Give a bit of time so the process is fully init.
        time.sleep(1)

        my_source_py_script = lib_client.SourceLocal(
            "sources_types/CIM_Process/languages/python/current_script.py",
            "CIM_Process",
            Handle=proc_open.pid)

        triple_py_script = my_source_py_script.get_triplestore()

        lst_instances = triple_py_script.get_instances()
        str_instances_set = set([str(one_inst) for one_inst in lst_instances])
        DEBUG("str_instances_set=%s", str(str_instances_set))

        sql_path_name_absolute = os.path.abspath(sql_path_name)
        sql_path_name_clean = lib_util.standardized_file_path(sql_path_name_absolute)

        # This checks the presence of the current process and the Python file being executed.
        list_required = [
            'CIM_Process.Handle=%s' % proc_open.pid,
            'CIM_DataFile.Name=%s' % sql_path_name_clean,
        ]

        for one_str in list_required:
            self.assertTrue(one_str in str_instances_set)

        proc_open.communicate()

    @unittest.skipIf(is_travis_machine() and is_platform_windows, "Cannot get users on Travis and Windows.")
    def test_enumerate_users(self):
        """List detectable users. Security might hide some of them"""

        # http://rchateau-hp:8000/survol/sources_types/enumerate_user.py?xid=.
        mySourceUsers = lib_client.SourceLocal(
            "sources_types/enumerate_user.py")

        tripleUsers = mySourceUsers.get_triplestore()
        instancesUsers = tripleUsers.get_instances()
        strInstancesSet = set([str(oneInst) for oneInst in instancesUsers ])

        # At least the current user must be found.
        for oneStr in [ CurrentUserPath ]:
            self.assertTrue(oneStr in strInstancesSet)

    def test_enumerate_CIM_Process(self):
        """List detectable processes."""

        my_source_processes = lib_client.SourceLocal(
            "sources_types/enumerate_CIM_Process.py")

        triple_processes = my_source_processes.get_triplestore()
        instances_processes = triple_processes.get_instances()
        str_instances_set = set([str(oneInst) for oneInst in instances_processes])

        # At least the current process must be found.
        for one_str in [CurrentProcessPath]:
            self.assertTrue(one_str in str_instances_set)

    def test_objtypes(self):
        my_source_objtypes = lib_client.SourceLocal(
            "objtypes.py")

        triple_objtypes = my_source_objtypes.get_triplestore()
        self.assertTrue(len(triple_objtypes) > 0)

    @unittest.skipIf(not is_platform_windows_and_wmi, "WMI on Windows only.")
    def test_objtypes_wmi(self):
        my_source_objtypes = lib_client.SourceLocal(
            "objtypes_wmi.py")

        triple_objtypes = my_source_objtypes.get_triplestore()
        self.assertTrue(len(triple_objtypes) > 0)

    @unittest.skipIf(not is_platform_windows_and_wmi, "WMI on Windows only.")
    def test_class_wmi(self):
        my_source_objtypes = lib_client.SourceLocal(
            "class_wmi.py",
            "CIM_LogicalElement")

        triple_objtypes = my_source_objtypes.get_triplestore()
        self.assertTrue(len(triple_objtypes) > 0)

    def test_class_type_all(self):
        my_source_class_type_all = lib_client.SourceLocal(
            "class_type_all.py",
            "CIM_DataFile")

        triple_class_type_all = my_source_class_type_all.get_triplestore()
        self.assertTrue(len(triple_class_type_all) > 0)

    @unittest.skipIf(not pkgutil.find_loader('cx_Oracle'), "pyodbc cannot be imported. SurvolPyODBCTest not executed.")
    def test_oracle_process_dbs(self):
        """oracle_process_dbs Information about current process"""

        my_source = lib_client.SourceLocal(
            "sources_types/CIM_Process/oracle_process_dbs.py",
            "CIM_Process",
            Handle=CurrentPid)

        str_instances_set = set([str(oneInst) for oneInst in my_source.get_triplestore().get_instances() ])

        # The result is empty but the script worked.
        print(str_instances_set)
        self.assertEqual(str_instances_set, set())

    def test_process_connections(self):
        """This returns the socket connections of the current process."""

        my_source = lib_client.SourceLocal(
            "sources_types/CIM_Process/process_connections.py",
            "CIM_Process",
            Handle=CurrentPid)

        str_instances_set = set([str(oneInst) for oneInst in my_source.get_triplestore().get_instances()])

        # The result is empty but the script worked.
        print("Connections=", str_instances_set)
        self.assertEqual(str_instances_set, set())

    def test_process_cwd(self):
        """process_cwd Information about current process"""

        my_source = lib_client.SourceLocal(
            "sources_types/CIM_Process/process_cwd.py",
            "CIM_Process",
            Handle=CurrentPid)

        str_instances_set = set([str(oneInst) for oneInst in my_source.get_triplestore().get_instances()])
        print("test_process_cwd: str_instances_set:", str_instances_set)

        print("test_process_cwd: CurrentExecutablePath:", CurrentExecutablePath)
        for one_str in [
            'CIM_DataFile.Name=%s' % lib_util.standardized_file_path(os.getcwd()),
            CurrentExecutablePath,
            CurrentProcessPath,
            CurrentUserPath,
        ]:
            if one_str not in str_instances_set:
                WARNING("one_str=%s str_instances_set=%s", one_str, str(str_instances_set) )
                # assert 'CIM_DataFile.Name=c:/python27/python.exe' in set(['CIM_DataFile.Name=C:/Python27/python.exe'
                self.assertTrue(one_str in str_instances_set)


class SurvolLocalWbemTest(unittest.TestCase):
    """These tests do not need a Survol agent"""

    @unittest.skipIf(not is_linux_wbem(), "WBEM not available. test_wbem_process_info not executed.")
    def test_wbem_process_info(self):
        """wbem_process_info Information about current process"""

        my_source = lib_client.SourceLocal(
            "sources_types/CIM_Process/wbem_process_info.py",
            "CIM_Process",
            Handle=CurrentPid)

        triple_store = my_source.get_triplestore()
        instances_list = triple_store.get_instances()
        str_instances_set = set([str(one_inst) for one_inst in instances_list])
        print("test_wbem_process_info: str_instances_set:", str_instances_set)
        # TODO: Check output

    @unittest.skipIf(not is_linux_wbem(), "WBEM not available. test_wbem_hostname_processes_local not executed.")
    def test_wbem_hostname_processes_local(self):
        """Get processes on current machine"""

        my_source = lib_client.SourceLocal(
            "sources_types/CIM_ComputerSystem/wbem_hostname_processes.py",
            "CIM_ComputerSystem",
            Name=CurrentMachine)

        triple_store = my_source.get_triplestore()
        instances_list = triple_store.get_instances()
        str_instances_set = set([str(one_inst) for one_inst in instances_list])
        print("test_wbem_hostname_processes_local: str_instances_set:", str_instances_set)
        # TODO: Check output


class SurvolRemoteWbemTest(unittest.TestCase):
    """These tests do not need a Survol agent"""

    @unittest.skipIf(not has_wbem(), "pywbem cannot be imported. test_wbem_hostname_processes_remote not executed.")
    def test_wbem_hostname_processes_remote(self):
        """Get processes on remote machine"""

        my_source = lib_client.SourceLocal(
            "sources_types/CIM_ComputerSystem/wbem_hostname_processes.py",
            "CIM_ComputerSystem",
            Name=SurvolServerHostname)

        my_source.get_triplestore()
        # TODO: Check output

    @unittest.skipIf(not has_wbem(), "pywbem cannot be imported. test_wbem_hostname_processes_remote not executed.")
    def test_wbem_info_processes_remote(self):
        """Display information about one process on a remote machine"""

        computer_source = lib_client.SourceLocal(
            "sources_types/CIM_ComputerSystem/wbem_hostname_processes.py",
            "CIM_ComputerSystem",
            Name=SurvolServerHostname)

        computer_triple_store = computer_source.get_triplestore()
        instances_list = computer_triple_store.get_instances()
        str_instances_set = set( [str(oneInst) for oneInst in instances_list ])

        # ['CIM_Process.Handle=10', 'CIM_Process.Handle=816', 'CIM_Process.Handle=12' etc...
        print("test_wbem_hostname_processes_remote: str_instances_set:", str_instances_set)
        for one_str in str_instances_set:
            self.assertTrue(one_str.startswith('CIM_Process.Handle='))

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
                process_triple_store = process_source.get_triplestore()
            except Exception as exc:
                print("pid=", remote_pid, " exc=", exc)
                continue

            # FIXME: If the process has left, this list is empty, and the test fails.
            instances_list = process_triple_store.get_instances()
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
        missing_triples = lib_client.check_ontology_graph("wbem", SurvolServerAgent)
        self.assertTrue(missing_triples == [], "Missing triples:%s" % str(missing_triples))


@unittest.skipIf(not pkgutil.find_loader('jpype'), "jpype cannot be imported.")
class SurvolLocalJavaTest(unittest.TestCase):

    def test_java_mbeans(self):
        """Java MBeans"""

        my_source = lib_client.SourceLocal(
            "sources_types/CIM_Process/languages/java/java_mbeans.py",
            "CIM_Process",
            Handle=CurrentPid)

        list_required = [
            CurrentProcessPath
        ]

        inst_prefix = 'java/mbean.Handle=%d,Name=' % CurrentPid

        for inst_java_name in [
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
            list_required.append( inst_prefix + inst_java_name )

        str_instances_set = set([str(one_inst) for one_inst in my_source.get_triplestore().get_instances()])
        print("test_java_mbeans str_instances_set=", str_instances_set)

        for one_str in list_required:
            self.assertTrue(one_str in str_instances_set)

    def test_java_system_properties(self):
        """Java system properties"""

        my_source = lib_client.SourceLocal(
            "sources_types/CIM_Process/languages/java/java_system_properties.py",
            "CIM_Process",
            Handle=CurrentPid)

        list_required = [
            CurrentUserPath,
            #'CIM_Directory.Name=C:/windows/system32',
            'CIM_Directory.Name=C:/Program Files/Java/jre1.8.0_121/lib/charsets.jar',
            'CIM_Directory.Name=C:/Program Files/nodejs',
            'CIM_Directory.Name=C:/Program Files/Java/jre1.8.0_121',
            #'CIM_Directory.Name=C:/windows',
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
            #'CIM_Directory.Name=C:/windows/System32/WindowsPowerShell/v1.0',
            'CIM_Directory.Name=C:/Program Files/Java/jdk1.8.0_121/jre/bin',
            'CIM_Directory.Name=C:/Program Files/Java/jre1.8.0_121/lib/rt.jar',
            'CIM_Directory.Name=C:/Program Files/Java/jdk1.8.0_121/bin',
            'CIM_Directory.Name=C:/windows/Sun/Java/bin',
            'CIM_Directory.Name=C:/Python27',
        ]

        list_required.append(CurrentProcessPath)

        str_instances_set = set([str(one_inst) for one_inst in my_source.get_triplestore().get_instances()])
        print("test_java_system_properties str_instances_set=", sorted(str_instances_set))

        print("list_required=", list_required)
        for one_str in list_required:
            if one_str not in str_instances_set:
                print("Not there:",one_str)
            self.assertTrue(one_str in str_instances_set, "test_java_system_properties: Not there:%s" % str(one_str))

    def test_java_jdk_jstack(self):
        """Information about JDK stack"""

        my_source = lib_client.SourceLocal(
            "sources_types/CIM_Process/languages/java/jdk_jstack.py",
            "CIM_Process",
            Handle=CurrentPid)

        # Start a Java process.

        str_instances_set = set([str(one_inst) for one_inst in my_source.get_triplestore().get_instances()])

        self.assertTrue(str_instances_set == set())


class SurvolSpecialCharactersTest(unittest.TestCase):

    def _is_file_found(self, path_name):
        full_path = os.path.join(os.path.dirname(__file__), "SampleDirSpecialCharacters", path_name)

        my_source_file_stat = lib_client.SourceRemote(
            _remote_general_test_agent + "/survol/sources_types/CIM_DataFile/file_stat.py",
            "CIM_DataFile",
            Name=full_path)
        json_content = my_source_file_stat.content_json()

        for one_node in json_content['nodes']:
            try:
                found_file = one_node['entity_class'] == 'CIM_DataFile' and one_node['name'] == path_name
                if found_file:
                    return True
            except:
                pass
        return False

    @unittest.skip("This test is broken.")
    def test_filename_with_accents(self):
        # TODO: Fix by simplifying URL: store predicate values in CGI parameters; Use B64 encoding for special chars.
        filename_char_e_acute = "e_acute_\xc3\xa9.txt"
        self.assertTrue(self._is_file_found(filename_char_e_acute))

    @unittest.skip("This test is broken.")
    def test_filename_with_commas(self):
        # TODO: Fix by simplifying URL: store predicate values in CGI parameters; Use B64 encoding for special chars.
        self.assertTrue(self._is_file_found("with,commas,in,file,name.txt"))

    @unittest.skip("This test is broken.")
    def test_filename_with_equals(self):
        # TODO: Fix by simplifying URL: store predicate values in CGI parameters; Use B64 encoding for special chars.
        self.assertTrue(self._is_file_found("with=equal=in=file=name.txt"))


class SurvolLocalOntologiesTest(unittest.TestCase):
    """This tests the creation of RDFS or OWL-DL ontologies"""

    def test_ontology_survol(self):
        missing_triples = lib_client.check_ontology_graph("survol")
        self.assertEqual(missing_triples, [], "Missing triples:%s" % str(missing_triples))

    @unittest.skipIf(not pkgutil.find_loader('wmi'), "wmi cannot be imported. test_ontology_wmi not executed.")
    def test_ontology_wmi(self):
        missing_triples = lib_client.check_ontology_graph("wmi")
        self.assertTrue(missing_triples == [], "Missing triples:%s" % str(missing_triples))

    @unittest.skipIf(not is_linux_wbem(), "pywbem cannot be imported. test_ontology_wbem not executed.")
    def test_ontology_wbem(self):
        missing_triples = lib_client.check_ontology_graph("wbem")
        self.assertTrue(missing_triples == [], "Missing triples:%s" % str(missing_triples))

# TODO: Test namespaces etc... etc classes wmi etc...

@unittest.skipIf(not is_platform_linux, "Linux tests only.")
class SurvolLocalLinuxTest(unittest.TestCase):
    """These tests do not need a Survol agent and apply to Linux machines only"""

    def test_process_cgroups(self):
        """CGroups about current process"""

        my_source = lib_client.SourceLocal(
            "sources_types/CIM_Process/Linux/process_cgroups.py",
            "CIM_Process",
            Handle=CurrentPid)

        str_instances_set = set([str(one_inst) for one_inst in my_source.get_triplestore().get_instances()])

        list_required = [
            CurrentExecutablePath,
            CurrentProcessPath,
            CurrentUserPath,
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

        for one_str in list_required:
            self.assertTrue(one_str in str_instances_set)


    def test_account_groups(self):
        """Groups of a Linux account"""

        my_source = lib_client.SourceLocal(
            "sources_types/LMI_Account/user_linux_id.py",
            "LMI_Account",
            Name="root",
            Domain=CurrentMachine)

        str_instances_set = set([str(one_inst) for one_inst in my_source.get_triplestore().get_instances()])
        print("str_instances_set=", str_instances_set)

        # Account "root" always belong to group "root"
        # The account must also be returned.
        list_required = [
            'LMI_Account.Name=root,Domain=%s' % CurrentMachine,
            'LMI_Group.Name=root',
        ]

        for one_str in list_required:
            self.assertTrue(one_str in str_instances_set)

    def test_account_processes(self):
        """Processes of a Linux account"""

        my_source = lib_client.SourceLocal(
            "sources_types/LMI_Account/user_processes.py",
            "LMI_Account",
            Name="root",
            Domain=CurrentMachine)

        str_instances_set = set([str(one_inst) for one_inst in my_source.get_triplestore().get_instances()])
        print("str_instances_set=", str_instances_set)

        # It is not possible to know in advance which process ids are used, but there must be at least one.
        self.assertTrue(len(str_instances_set) > 0)

    def test_group_users(self):
        """Users of a Linux group"""

        my_source = lib_client.SourceLocal(
            "sources_types/LMI_Group/linux_user_group.py",
            "LMI_Group",
            Name="root")

        str_instances_set = set([str(one_inst) for one_inst in my_source.get_triplestore().get_instances()])
        print("str_instances_set=", str_instances_set)

        # At least the group itself, is returned.
        list_required = [
            'LMI_Group.Name=root',
        ]

        for one_str in list_required:
            self.assertTrue(one_str in str_instances_set)


class SurvolLocalGdbTest(unittest.TestCase):
    """These tests do not need a Survol agent, and run on Linux with GDB debugger"""

    def decorator_gdb_platform(test_func):
        if is_platform_linux and check_program_exists("gdb"):
            return test_func
        else:
            return None

    @decorator_gdb_platform
    def test_process_gdbstack(self):
        """process_gdbstack Information about current process"""

        my_source = lib_client.SourceLocal(
            "sources_types/CIM_Process/process_gdbstack.py",
            "CIM_Process",
            Handle=CurrentPid)

        list_required = [
            'linker_symbol.Name=X19wb2xsX25vY2FuY2Vs,File=/lib64/libc.so.6',
            'CIM_DataFile.Name=/lib64/libc.so.6',
            CurrentUserPath,
            CurrentProcessPath
        ]
        if is_py3:
            list_required += [
                'CIM_DataFile.Name=/usr/bin/python3.6',
                'linker_symbol.Name=cG9sbF9wb2xs,File=/usr/bin/python3.6',
        ]
        else:
            list_required += [
                'CIM_DataFile.Name=/usr/bin/python2.7',
                'CIM_DataFile.Name=/lib64/libc.so.6',
        ]

        str_instances_set = set([str(oneInst) for oneInst in my_source.get_triplestore().get_instances() ])

        for one_str in list_required:
            self.assertTrue(one_str in str_instances_set)

    @unittest.skipIf(is_py3, "Python stack for Python 2 only.")
    @decorator_gdb_platform
    def test_display_python_stack(self):
        """Displays the stack of a Python process"""

        # This creates a process running in Python, because it does not work with the current process.
        py_path_name = os.path.join(os.path.dirname(__file__), "SampleDir", "SamplePythonFile.py")
        py_path_name = os.path.abspath(py_path_name)

        exec_list = [sys.executable, py_path_name]

        proc_open = subprocess.Popen(
            exec_list,
            shell=False,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0)

        print("Started process:", exec_list, " pid=", proc_open.pid)

        # Give a bit of time so the process is fully init.
        time.sleep(1)

        my_source_py_stack = lib_client.SourceLocal(
            "sources_types/CIM_Process/languages/python/display_python_stack.py",
            "CIM_Process",
            Handle=proc_open.pid)

        triple_py_stack = my_source_py_stack.get_triplestore()

        lst_instances = triple_py_stack.get_instances()
        str_instances_set = set([str(oneInst) for oneInst in lst_instances])
        print("str_instances_set=",str_instances_set)

        py_path_name_absolute = os.path.abspath(py_path_name)
        py_path_name_clean = lib_util.standardized_file_path(py_path_name_absolute)

        # This checks the presence of the current process and the Python file being executed.
        list_required = [
            'CIM_DataFile.Name=%s' % py_path_name_clean,
            'linker_symbol.Name=X19tYWluX18=,File=%s' % py_path_name,
        ]

        for one_str in list_required:
            print(one_str)
            self.assertTrue(one_str in str_instances_set)

        proc_open.communicate()


@unittest.skipIf(not is_platform_windows, "SurvolLocalWindowsTest runs on Windows only")
class SurvolLocalWindowsTest(unittest.TestCase):
    """These tests do not need a Survol agent. They apply to Windows machines only"""

    @unittest.skipIf(not pkgutil.find_loader('win32service'), "test_win32_services needs win32service to run.")
    def test_win32_services(self):
        """List of Win32 services"""

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/win32/enumerate_Win32_Service.py")

        str_instances_set = set([str(oneInst) for oneInst in lst_instances ])

        # print(str_instances_set)
        # Some services must be on any Windpws machine.
        self.assertTrue('Win32_Service.Name=nsi' in str_instances_set)
        self.assertTrue('Win32_Service.Name=LanmanWorkstation' in str_instances_set)

    @unittest.skipIf(not pkgutil.find_loader('wmi'), "test_wmi_process_info needs wmi to run.")
    def test_wmi_process_info(self):
        """WMI information about current process"""

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/CIM_Process/wmi_process_info.py",
            "CIM_Process",
            Handle=CurrentPid)

        str_instances_set = set([str(oneInst) for oneInst in lst_instances])

        # This checks the presence of the current process and its parent.
        self.assertTrue('CIM_Process.Handle=%s' % CurrentPid in str_instances_set)
        if is_py3:
            # Checks the parent's presence also. Not for 2.7.10
            self.assertTrue(CurrentProcessPath in str_instances_set)

    @unittest.skipIf(not pkgutil.find_loader('wmi'), "test_win_process_modules needs wmi to run.")
    def test_win_process_modules(self):
        """Windows process modules"""

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/CIM_Process/win_process_modules.py",
            "CIM_Process",
            Handle=CurrentPid)

        str_instances_set = set([str(one_inst) for one_inst in lst_instances])

        # This checks the presence of the current process and its parent.
        list_required = [
            CurrentProcessPath,
            CurrentUserPath,
            'CIM_DataFile.Name=%s' % CurrentExecutable,
        ]

        # Some nodes are in Py2 or Py3.
        if is_py3:
            if is_windows10:
                # 'C:\\Users\\rchat\\AppData\\Local\\Programs\\Python\\Python36\\python.exe'
                # 'C:/Users/rchat/AppData/Local/Programs/Python/Python36/DLLs/_ctypes.pyd'
                list_option = []
                packages_dir = os.path.dirname(CurrentExecutable)
                #if is_travis_machine():
                #    # FIXME: On Travis, "C:/users" in lowercase. Why ?
                #    packages_dir = packages_dir.lower()
                extra_file = os.path.join(packages_dir, 'lib', 'site-packages', 'win32', 'win32api.pyd')
                extra_file = lib_util.standardized_file_path(extra_file)
                list_option.append('CIM_DataFile.Name=%s' % extra_file)
            else:
                list_option = [
                    'CIM_DataFile.Name=%s' % lib_util.standardized_file_path('C:/windows/system32/kernel32.dll'),
                ]
        else:
            list_option = [
            'CIM_DataFile.Name=%s' % lib_util.standardized_file_path('C:/windows/SYSTEM32/ntdll.dll'),
            ]

        print("Actual=", str_instances_set)
        for one_str in list_required + list_option:
            print("one_str=", one_str)
            self.assertTrue(one_str in str_instances_set)

        # Detection if a specific bug is fixed.
        self.assertTrue(not 'CIM_DataFile.Name=' in str_instances_set)

    def test_win32_products(self):
        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/win32/enumerate_Win32_Product.py")

        str_instances_lst = [str(oneInst) for oneInst in lst_instances ]
        products_count = 0
        for one_instance in str_instances_lst:
            # Ex: 'Win32_Product.IdentifyingNumber={1AC6CC3D-7724-4D84-9270-798A2191AB1C}'
            if one_instance.startswith('Win32_Product.IdentifyingNumber='):
                products_count += 1

        print("lst_instances=",str_instances_lst[:3])

        # Certainly, there a more that five products or any other small number.
        self.assertTrue(products_count > 5)

    def test_win_cdb_callstack(self):
        """win_cdb_callstack Information about current process"""

        my_source = lib_client.SourceLocal(
            "sources_types/CIM_Process/CDB/win_cdb_callstack.py",
            "CIM_Process",
            Handle=CurrentPid)

        with self.assertRaises(Exception):
            # Should throw "Exception: ErrorMessageHtml raised:Cannot debug current process"
            my_source.get_triplestore()

    def test_win_cdb_modules(self):
        """win_cdb_modules about current process"""

        my_source = lib_client.SourceLocal(
            "sources_types/CIM_Process/CDB/win_cdb_modules.py",
            "CIM_Process",
            Handle=CurrentPid)

        with self.assertRaises(Exception):
            # Should throw "Exception: ErrorMessageHtml raised:Cannot debug current process"
            my_source.get_triplestore()

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
        str_instances_set = set([str(oneInst) for oneInst in list_instances ])

        list_required =  [
            CurrentProcessPath,
        ]
        print("list_required=", list_required)

        for one_str in list_required:
            self.assertTrue(one_str in str_instances_set)

    @unittest.skipIf(not pkgutil.find_loader('win32net'), "test_win32_host_local_groups needs win32net.")
    def test_win32_host_local_groups(self):
        my_source_host_local_groups = lib_client.SourceLocal(
            "sources_types/CIM_ComputerSystem/Win32/win32_host_local_groups.py",
            "CIM_ComputerSystem",
            Name = CurrentMachine)

        triple_host_local_groups = my_source_host_local_groups.get_triplestore()
        instances_host_local_groups = triple_host_local_groups.get_instances()

        group_instances = set(str(one_instance) for one_instance in instances_host_local_groups)
        print("group_instances=", group_instances)

        print("Win32_Group.Name=Administrators,Domain=%s" % CurrentMachine)
        self.assertTrue("Win32_Group.Name=Administrators,Domain=%s" % CurrentMachine in group_instances)
        self.assertTrue("Win32_Group.Name=Users,Domain=%s" % CurrentMachine in group_instances)


try:
    import pyodbc
    # This is temporary until ODBC is setup on this machine.
    # FIXME: The correct solution might be to check ODBC credentials.
    if not has_credentials("ODBC"): # CurrentMachine in ["laptop-r89kg6v1", "desktop-ny99v8e"]:
        pyodbc = None
except ImportError as exc:
    pyodbc = None
    print("Detected ImportError:", exc)

# https://stackoverflow.com/questions/23741133/if-condition-in-setup-ignore-test
# This decorator at the class level does not work on Travis.
# @unittest.skipIf( not pyodbc, "pyodbc cannot be imported. SurvolPyODBCTest not executed.")
class SurvolPyODBCTest(unittest.TestCase):

    @unittest.skipIf(not pyodbc, "pyodbc cannot be imported. SurvolPyODBCTest not executed.")
    def test_local_scripts_odbc_dsn(self):
        """This instantiates an instance of a subclass"""

        # The url is "http://rchateau-hp:8000/survol/entity.py?xid=odbc/dsn.Dsn=DSN~MS%20Access%20Database"
        instance_local_odbc = lib_client.Agent().odbc.dsn(
            Dsn="DSN~MS%20Access%20Database")

        list_scripts = instance_local_odbc.get_scripts()
        if _is_verbose:
            sys.stdout.write("Scripts:\n")
            for one_scr in list_scripts:
                sys.stdout.write("    %s\n" % one_scr)
        # There should be at least a couple of scripts.
        self.assertTrue(len(list_scripts) > 0)

    @unittest.skipIf(not pyodbc, "pyodbc cannot be imported. SurvolPyODBCTest not executed.")
    def test_pyodbc_sqldatasources(self):
        """Tests ODBC data sources"""

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/Databases/win32_sqldatasources_pyodbc.py")

        str_instances_set = set([str(oneInst) for oneInst in lst_instances ])

        # At least these instances must be present.
        for one_str in [
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
            self.assertTrue(one_str in str_instances_set)

    @unittest.skipIf(not pyodbc, "pyodbc cannot be imported. SurvolPyODBCTest not executed.")
    def test_pyodbc_dsn_tables(self):
        """Tests ODBC data sources"""

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/odbc/dsn/odbc_dsn_tables.py",
            "odbc/dsn",
            Dsn="DSN~SysDataSourceSQLServer")

        strInstancesSet = set([str(oneInst) for oneInst in lst_instances])
        #print("Instances:",strInstancesSet)

        # Checks the presence of some Python dependencies, true for all Python versions and OS platforms.
        for one_str in [
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
            self.assertTrue(one_str in strInstancesSet)


    @unittest.skipIf(not pyodbc, "pyodbc cannot be imported. SurvolPyODBCTest not executed.")
    def test_pyodbc_dsn_one_table_columns(self):
        """Tests ODBC table columns"""

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/odbc/table/odbc_table_columns.py",
            "odbc/table",
            Dsn="DSN~SysDataSourceSQLServer",
            Table="dm_os_windows_info")

        str_instances_set = set([str(oneInst) for oneInst in lst_instances ])
        #print("Instances:",str_instances_set)

        # Checks the presence of some Python dependencies, true for all Python versions and OS platforms.
        for one_str in [
            'odbc/column.Dsn=DSN~SysDataSourceSQLServer,Table=dm_os_windows_info,Column=windows_service_pack_level',
            'odbc/column.Dsn=DSN~SysDataSourceSQLServer,Table=dm_os_windows_info,Column=os_language_version',
            'odbc/column.Dsn=DSN~SysDataSourceSQLServer,Table=dm_os_windows_info,Column=windows_release',
            'odbc/column.Dsn=DSN~SysDataSourceSQLServer,Table=dm_os_windows_info,Column=windows_sku',
            'odbc/table.Dsn=DSN~SysDataSourceSQLServer,Table=dm_os_windows_info'
        ]:
            self.assertTrue(one_str in str_instances_set)


class SurvolSocketsTest(unittest.TestCase):
    """Test involving remote Survol agents: The scripts executes scripts on remote machines
    and examines the result. It might merge the output with local scripts or
    scripts on different machines."""

    def test_netstat_sockets(self):

        # Not many web sites in HTTP these days. This one is very stable.
        # http://w2.vatican.va/content/vatican/it.html is on port 80=http
        http_host_name = 'w2.vatican.va'

        sock_host = socket.gethostbyname(http_host_name)
        print("gethostbyname(%s)=%s" % (http_host_name, sock_host))

        # This opens a connection to a specific machine, then checks that the socket can be found.
        if is_py3:
            import http.client
            conn_http = http.client.HTTPConnection(http_host_name, 80, timeout=60)
        else:
            import httplib
            conn_http = httplib.HTTPConnection(http_host_name, 80, timeout=60)
        print("Connection to %s OK"%http_host_name)
        # Legacy and backward compatibility.
        conn_http.request("GET", "/latin/latin_index.html")
        resp = conn_http.getresponse()
        if (resp.status, resp.reason) not in [(200, "OK"), (302, "Found")]:
            raise Exception("Hostname %s not ok. Status=%d, reason=%s." % (http_host_name, resp.status, resp.reason))
        peer_name = conn_http.sock.getpeername()
        peer_host = peer_name[0]

        print("Peer name of connection socket:",conn_http.sock.getpeername())

        if is_platform_windows:
            lst_instances = ClientObjectInstancesFromScript("sources_types/win32/tcp_sockets_windows.py")
        else:
            lst_instances = ClientObjectInstancesFromScript("sources_types/Linux/tcp_sockets.py")

        str_instances_set = set([str(oneInst) for oneInst in lst_instances ])

        addr_expected = "addr.Id=%s:80" % peer_host
        print("addr_expected=", addr_expected)
        self.assertTrue(addr_expected in str_instances_set)

        conn_http.close()

    @unittest.skip("THIS WORKS ONLY SOMETIMES")
    def test_enumerate_sockets(self):
        """List of sockets opened on the host machine"""

        # This site was registered on September the 18th, 1986. It is very stable.
        http_host_name = 'www.itcorp.com'

        sock_host = socket.gethostbyname(http_host_name)
        print("gethostbyname(%s)=%s"%(http_host_name,sock_host))

        # This opens a connection to a specific machine, then checks that the socket can be found.
        expected_port = 80
        if is_py3:
            import http.client
            conn_http = http.client.HTTPConnection(http_host_name, expected_port, timeout=60)
        else:
            import httplib
            conn_http = httplib.HTTPConnection(http_host_name, expected_port, timeout=60)
        print("Connection to %s OK"%http_host_name)

        print("Requesting content")
        conn_http.request(method="GET", url="/")
        print("Peer name of connection socket:",conn_http.sock.getpeername())

        resp = conn_http.getresponse()

        if resp.status != 200 or resp.reason != "OK":
            raise Exception("Hostname %s not ok. Status=%d, reason=%s." % (http_host_name, resp.status, resp.reason))
        peer_name = conn_http.sock.getpeername()
        peer_host = peer_name[0]

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/enumerate_socket.py")

        str_instances_list = [str(one_inst) for one_inst in lst_instances]

        print("sock_host=", sock_host)
        print("peer_host=", peer_host)
        print("expected_port=", expected_port)

        found_socket = False
        for one_instance in str_instances_list:
            #print("one_instance=", one_instance)
            match_address = re.match("addr.Id=(.*):([0-9]*)", one_instance)
            if match_address:
                instance_host = match_address.group(1)
                instance_port = match_address.group(2)
                if instance_host == "127.0.0.1":
                    continue
                try:
                    instance_addr = socket.gethostbyname(instance_host)
                    #print("instance_addr=", instance_addr)
                    found_socket = instance_addr == peer_host and instance_port == str(expected_port)
                    if found_socket:
                        break
                except socket.gaierror:
                    pass

        self.assertTrue(found_socket)
        conn_http.close()

    def test_socket_connected_processes(self):
        """List of processes connected to a given socket"""

        # This test connect to an external server and checks that sockets are properly listed.
        # It needs a HTTP web server because it is simpler for debugging.
        # https://stackoverflow.com/questions/50068127/http-only-site-to-test-rest-requests
        # This URL doesn't redirect http to https.
        http_host_name = 'eu.httpbin.org'

        print("")
        sockHost = socket.gethostbyname(http_host_name)
        print("gethostbyname(%s)=%s"%(http_host_name, sockHost))

        # This opens a connection to a specific machine, then checks that the socket can be found.
        if is_py3:
            import http.client
            conn_http = http.client.HTTPConnection(http_host_name, 80, timeout=60)
        else:
            import httplib
            conn_http = httplib.HTTPConnection(http_host_name, 80, timeout=60)
        print("Connection to %s OK"%http_host_name)
        conn_http.request("GET", "")
        resp = conn_http.getresponse()
        if resp.status != 200 or resp.reason != "OK":
            raise Exception("Hostname %s not ok. Status=%d, reason=%s." % (http_host_name, resp.status, resp.reason))
        peer_name = conn_http.sock.getpeername()
        peer_host = peer_name[0]

        print("Peer name of connection socket:",conn_http.sock.getpeername())

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/addr/socket_connected_processes.py",
            "addr",
            Id="%s:80" % peer_host)

        str_instances_set = set([str(oneInst) for oneInst in lst_instances])

        # Because the current process has created this socket,
        # it must be found in the socket's connected processes.

        addr_expected = "addr.Id=%s:80" % peer_host
        proc_expected = CurrentProcessPath

        print("addr_expected=", addr_expected)
        print("proc_expected=", proc_expected)

        self.assertTrue(addr_expected in str_instances_set)
        self.assertTrue(proc_expected in str_instances_set)

        conn_http.close()

    @unittest.skipIf(not is_platform_windows, "test_net_use for Windows only.")
    def test_net_use(self):
        """Just test that the command NET USE runs"""

        # This does not really test the content, because nothing is sure.
        # However, at least it tests that the script can be called.
        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/SMB/net_use.py")

        str_instances_set = set([str(one_inst) for one_inst in lst_instances])
        print(str_instances_set)
        # Typical content:
        # 'CIM_DataFile.Name=//192.168.0.15/public:',
        # 'CIM_DataFile.Name=//192.168.0.15/rchateau:',
        # 'smbshr.Id=\\\\192.168.0.15\\public',
        # 'CIM_DataFile.Name=//localhost/IPC$:',
        # 'smbshr.Id=\\\\192.168.0.15\\rchateau',
        # 'smbshr.Id=\\\\localhost\\IPC$'

        # TODO: This cannot be tested on Travis.


    @unittest.skipIf(not is_platform_windows, "test_windows_network_devices for Windows only.")
    def test_windows_network_devices(self):
        """Loads network devices on a Windows network"""

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/win32/windows_network_devices.py")

        str_instances_set = set([str(one_inst) for one_inst in lst_instances])
        print(str_instances_set)

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
        for one_inst in str_instances_set:
            ( the_class,dummy_dot, the_entity_id) = one_inst.partition(".")
            if the_class == "CIM_ComputerSystem":
                pred_name, dummy_equal, ip_address = the_entity_id.partition("=")
                set_ip_addresses.add(ip_address)
            elif the_class == "smbshr":
                pred_name, dummy_equal, disk_name = the_entity_id.partition("=")
                smbshr_disk.add(disk_name)

        # Check that all machines hosting a disk have their
        for disk_name in smbshr_disk:
            # For example, "//192.168.0.15/public"
            host_name = disk_name.split("/")[2]
            self.assertTrue(host_name in set_ip_addresses)

class SurvolRemoteTest(unittest.TestCase):
    """Test involving remote Survol agents: The scripts executes scripts on remote machines
    and examines the result. It might merge the output with local scripts or
    scripts on different machines."""

    def test_InstanceUrlToAgentUrl(self):
        agent1 = lib_client.instance_url_to_agent_url("http://LOCALHOST:80/LocalExecution/entity.py?xid=addr.Id=127.0.0.1:427")
        print("agent1=", agent1)
        self.assertEqual(agent1, None )
        agent2 = lib_client.instance_url_to_agent_url(_remote_general_test_agent + "/survol/sources_types/java/java_processes.py")
        print("agent2=", agent2)
        self.assertEqual(agent2, _remote_general_test_agent )

    def test_create_source_url(self):
        # http://rchateau-hp:8000/survol/sources_types/CIM_DataFile/file_stat.py?xid=CIM_DataFile.Name%3DC%3A%2FWindows%2Fexplorer.exe
        my_source_file_stat_remote = lib_client.SourceRemote(
            _remote_general_test_agent + "/survol/sources_types/CIM_DataFile/file_stat.py",
            "CIM_DataFile",
            Name=always_present_file)
        print("urlFileStatRemote=",my_source_file_stat_remote.Url())
        print("qryFileStatRemote=",my_source_file_stat_remote.create_url_query())
        json_content = my_source_file_stat_remote.content_json()

        found_file = False
        always_present_basename = os.path.basename(always_present_file)
        for one_node in json_content['nodes']:
            try:
                found_file = one_node['entity_class'] == 'CIM_DataFile' and one_node['name'] == always_present_basename
                if found_file:
                    break
            except:
                pass

        self.assertTrue(found_file)

    def test_remote_triplestore(self):
        my_source_file_stat_remote = lib_client.SourceRemote(
            _remote_general_test_agent + "/survol/sources_types/CIM_Directory/file_directory.py",
            "CIM_Directory",
            Name=always_present_dir)
        triple_file_stat_remote = my_source_file_stat_remote.get_triplestore()
        print("Len triple_file_stat_remote=", len(triple_file_stat_remote))
        # This should not be empty.
        self.assertTrue(len(triple_file_stat_remote) >= 1)

    def test_remote_scripts_exception(self):
        my_agent = lib_client.Agent(_remote_general_test_agent)

        # This raises an exception like "EntityId className=CIM_LogicalDisk. No key DeviceID"
        # because the properties are incorrect,
        with self.assertRaises(Exception):
            my_source_invalid = my_agent.CIM_LogicalDisk(WrongProperty=AnyLogicalDisk)
            scripts_invalid = my_source_invalid.get_scripts()

    def test_remote_instances_python_package(self):
        """This loads a specific Python package"""
        my_source_python_package_remote = lib_client.SourceRemote(
            _remote_general_test_agent + "/survol/entity.py",
            "python/package",
            Id="rdflib")
        triple_python_package_remote = my_source_python_package_remote.get_triplestore()

        instances_python_package_remote = triple_python_package_remote.get_instances()
        len_instances = len(instances_python_package_remote)
        # This Python module must be there because it is needed by Survol.
        self.assertTrue(len_instances>=1)

    @unittest.skipIf(not pkgutil.find_loader('jpype'), "jpype cannot be imported. test_remote_instances_java not executed.")
    def test_remote_instances_java(self):
        """Loads Java processes. There is at least one Java process, the one doing the test"""
        my_source_java_remote = lib_client.SourceRemote(
            _remote_general_test_agent + "/survol/sources_types/java/java_processes.py")
        triple_java_remote = my_source_java_remote.get_triplestore()
        print("Len triple_java_remote=", len(triple_java_remote))

        instances_java_remote = triple_java_remote.get_instances()
        num_java_processes = 0
        for one_instance in instances_java_remote:
            if one_instance.__class__.__name__ == "CIM_Process":
                print("Found one Java process:", one_instance)
                num_java_processes += 1
        print("Remote Java processes=", num_java_processes)
        self.assertTrue(num_java_processes >= 1)

    # Cannot run /sbin/arp -an
    @unittest.skipIf(is_travis_machine(), "Cannot run this test on TravisCI because arp is not available.")
    def test_remote_instances_arp(self):
        """Loads machines visible with ARP. There must be at least one CIM_ComputerSystem"""

        my_source_arp_remote = lib_client.SourceRemote(
            _remote_general_test_agent + "/survol/sources_types/neighborhood/cgi_arp_async.py")
        triple_arp_remote = my_source_arp_remote.get_triplestore()
        print("Len triple_arp_remote=", len(triple_arp_remote))

        instances_arp_remote = triple_arp_remote.get_instances()
        num_computers = 0
        for one_instance in instances_arp_remote:
            if one_instance.__class__.__name__ == "CIM_ComputerSystem":
                print("Test remote ARP: Found one machine:", one_instance)
                num_computers += 1
        print("Remote hosts number=", num_computers)
        self.assertTrue(num_computers >= 1)

    def test_merge_add_mixed(self):
        """Merges local data triples and remote Survol agent's"""
        my_source1 = lib_client.SourceLocal(
            "entity.py",
            "CIM_LogicalDisk",
            DeviceID=AnyLogicalDisk)
        if is_platform_windows:
            my_source2 = lib_client.SourceRemote(_remote_general_test_agent + "/survol/sources_types/win32/tcp_sockets_windows.py")
        else:
            my_source2 = lib_client.SourceRemote(_remote_general_test_agent + "/survol/sources_types/Linux/tcp_sockets.py")

        my_src_merge_plus = my_source1 + my_source2
        print("Merge plus:",str(my_src_merge_plus.content_rdf())[:30])
        triple_plus = my_src_merge_plus.get_triplestore()
        print("Len triple_plus:",len(triple_plus))

        len_source1 = len(my_source1.get_triplestore().get_instances())
        len_source2 = len(my_source2.get_triplestore().get_instances())
        len_plus = len(triple_plus.get_instances())
        # There is a margin because some instances could be created in the mean time.
        error_margin = 20
        # In the merged link, there cannot be more instances than in the input sources.
        self.assertTrue(len_plus <= len_source1 + len_source2 + error_margin)

    @unittest.skipIf(not pkgutil.find_loader('win32net'), "Cannot import win32net. test_merge_sub_mixed not run.")
    def test_merge_sub_mixed(self):
        my_source1 = lib_client.SourceLocal(
            "entity.py",
            "CIM_LogicalDisk",
            DeviceID=AnyLogicalDisk)
        if is_platform_windows:
            my_source2 = lib_client.SourceRemote(_remote_general_test_agent + "/survol/sources_types/win32/win32_local_groups.py")
        else:
            my_source2 = lib_client.SourceRemote(_remote_general_test_agent + "/survol/sources_types/Linux/etc_group.py")

        my_src_merge_minus = my_source1 - my_source2
        print("Merge Minus:",str(my_src_merge_minus.content_rdf())[:30])
        triple_minus = my_src_merge_minus.get_triplestore()
        print("Len triple_minus:", len(triple_minus))

        len_source1 = len(my_source1.get_triplestore().get_instances())
        len_minus = len(triple_minus.get_instances())
        # There cannot be more instances after removal.
        self.assertTrue(len_minus <= len_source1 )

    def test_remote_scripts_CIM_LogicalDisk(self):
        my_agent = lib_client.Agent(_remote_general_test_agent)

        my_instances_remote_disk = my_agent.CIM_LogicalDisk(DeviceID=AnyLogicalDisk)
        list_scripts_disk = my_instances_remote_disk.get_scripts()
        # No scripts yet.
        self.assertTrue(len(list_scripts_disk) == 0)

    def test_remote_scripts_CIM_Directory(self):
        my_agent = lib_client.Agent(_remote_general_test_agent)

        my_instances_remote_dir = my_agent.CIM_Directory(Name=AnyLogicalDisk)
        list_scripts_dir = my_instances_remote_dir.get_scripts()

        if _is_verbose:
            for key_script in list_scripts_dir:
                sys.stdout.write("    %s\n"%key_script)
        # There should be at least a couple of scripts.
        self.assertTrue(len(list_scripts_dir) > 0)


class SurvolAzureTest(unittest.TestCase):
    """Testing Azure discovery"""

    def decorator_azure_subscription(test_func):
        """Returns first available Azure subscription from Credentials file"""

        try:
            import azure
        except ImportError:
            print("Module azure is not available so this test is not applicable")
            return None

        instances_azure_subscriptions = ClientObjectInstancesFromScript(
            "sources_types/Azure/enumerate_subscription.py")

        # ['Azure/subscription.Subscription=Visual Studio Professional', 'CIM_ComputerSystem.Name=localhost']
        for one_inst in instances_azure_subscriptions:
            # This returns the first subscription found.
            if one_inst.__class__.__name__ == "Azure/subscription":
                def wrapper(self):
                    test_func(self,one_inst.Subscription)
                return wrapper

        print("No Azure subscription available")
        return None

    @decorator_azure_subscription
    def test_azure_subscriptions(self, azureSubscription):
        print("Azure subscription:", azureSubscription)

    @decorator_azure_subscription
    @unittest.skip("Azure test disabled")
    def test_azure_locations(self, azureSubscription):
        """This checks Azure locations."""

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/Azure/subscription/subscription_locations.py",
            "Azure/subscription",
            Subscription=azureSubscription)

        str_instances_set = set([str(oneInst) for oneInst in lst_instances ])

        # Some locations are very common.
        for location_name in [
                'UK South',
                'West Central US',
                'West Europe']:
            entity_subscription = 'Azure/location.Subscription=%s,Location=%s' % (azureSubscription, location_name)
            self.assertTrue(entity_subscription in str_instances_set)

    @decorator_azure_subscription
    @unittest.skip("Azure test disabled")
    def test_azure_subscription_disk(self, azureSubscription):
        """This checks Azure disks."""

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/Azure/subscription/subscription_disk.py",
            "Azure/subscription",
            Subscription=azureSubscription)

        str_instances_set = set([str(oneInst) for oneInst in lst_instances ])

        print(str_instances_set)

        # There should be at least one disk.
        self.assertTrue(len(str_instances_set) > 0)


class SurvolRabbitMQTest(unittest.TestCase):
    """Testing RabbitMQ discovery"""

    def setUp(self):
        time.sleep(2)

    def tearDown(self):
        time.sleep(2)

    # Beware that it is called anyway for each function it is applied to,
    # even if the function is not called.
    def decorator_rabbitmq_subscription(test_func):
        """Returns first RabbitMQ subscription from Credentials file"""

        try:
            import pyrabbit

            # NOT RELIABLE.
            return None
        except ImportError:
            print("Module pyrabbit is not available so this test is not applicable")
            return None

        instances_configurations_rabbit_mq = ClientObjectInstancesFromScript(
            "sources_types/rabbitmq/list_configurations.py")

        # ['Azure/subscription.Subscription=Visual Studio Professional', 'CIM_ComputerSystem.Name=localhost']
        for one_inst in instances_configurations_rabbit_mq:
            # This returns the first subscription found.
            if one_inst.__class__.__name__ == "rabbitmq/manager":
                def wrapper(self):
                    test_func(self, one_inst.Url)
                return wrapper

        print("No Azure subscription available")
        return None

    @decorator_rabbitmq_subscription
    def test_rabbitmq_subscriptions(self,rabbitmqManager):
        print("RabbitMQ:", rabbitmqManager)

    @decorator_rabbitmq_subscription
    def test_rabbitmq_connections(self,rabbitmqManager):
        print("RabbitMQ:", rabbitmqManager)

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/rabbitmq/manager/list_connections.py",
            "rabbitmq/manager",
            Url=rabbitmqManager)

        str_instances_set = set([str(oneInst) for oneInst in lst_instances ])
        print(str_instances_set)

        # Typical content:
        # 'rabbitmq/manager.Url=localhost:12345',\
        # 'rabbitmq/user.Url=localhost:12345,User=guest',\
        # 'rabbitmq/connection.Url=localhost:12345,Connection=127.0.0.1:51752 -&gt; 127.0.0.1:5672',\
        # 'rabbitmq/connection.Url=localhost:12345,Connection=127.0.0.1:51641 -&gt; 127.0.0.1:5672'])

        # Typical content
        for one_str in [
            'rabbitmq/manager.Url=%s' % rabbitmqManager,
            'rabbitmq/user.Url=%s,User=guest' % rabbitmqManager,
        ]:
            self.assertTrue(one_str in str_instances_set)

    @decorator_rabbitmq_subscription
    def test_rabbitmq_exchanges(self, rabbitmq_manager):
        print("RabbitMQ:", rabbitmq_manager)

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/rabbitmq/manager/list_exchanges.py",
            "rabbitmq/manager",
            Url=rabbitmq_manager)

        str_instances_set = set([str(oneInst) for oneInst in lst_instances])
        print(str_instances_set)

        # Typical content
        for one_str in [
            'rabbitmq/exchange.Url=%s,VHost=/,Exchange=amq.match' % rabbitmq_manager,
            'rabbitmq/exchange.Url=%s,VHost=/,Exchange=' % rabbitmq_manager,
            'rabbitmq/exchange.Url=%s,VHost=/,Exchange=amq.topic' % rabbitmq_manager,
            'rabbitmq/exchange.Url=%s,VHost=/,Exchange=amq.rabbitmq.trace' % rabbitmq_manager,
            'rabbitmq/exchange.Url=%s,VHost=/,Exchange=amq.headers' % rabbitmq_manager,
            'rabbitmq/exchange.Url=%s,VHost=/,Exchange=amq.rabbitmq.log' % rabbitmq_manager,
            'rabbitmq/exchange.Url=%s,VHost=/,Exchange=amq.fanout' % rabbitmq_manager,
            'rabbitmq/exchange.Url=%s,VHost=/,Exchange=amq.direct' % rabbitmq_manager,
            'rabbitmq/vhost.Url=%s,VHost=/' % rabbitmq_manager
        ]:
            self.assertTrue(one_str in str_instances_set)

    @decorator_rabbitmq_subscription
    def test_rabbitmq_queues(self, rabbitmq_manager):
        print("RabbitMQ:", rabbitmq_manager)

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/rabbitmq/manager/list_queues.py",
            "rabbitmq/manager",
            Url=rabbitmq_manager)

        # FIXME: Which queues should always be present ?
        str_instances_set = set([str(one_inst) for one_inst in lst_instances])
        print("test_rabbitmq_queues str_instances_set=", str_instances_set)
        self.assertTrue('rabbitmq/vhost.Url=localhost:12345,VHost=/' in str_instances_set)
        self.assertTrue('rabbitmq/manager.Url=localhost:12345' in str_instances_set)

    @decorator_rabbitmq_subscription
    def test_rabbitmq_users(self, rabbitmq_manager):
        print("RabbitMQ:", rabbitmq_manager)

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/rabbitmq/manager/list_users.py",
            "rabbitmq/manager",
            Url=rabbitmq_manager)

        str_instances_set = set([str(one_inst) for one_inst in lst_instances])
        print(str_instances_set)

        # Typical content
        for one_str in [
            'rabbitmq/user.Url=%s,User=guest' % rabbitmq_manager,
        ]:
            print(one_str)
            self.assertTrue(one_str in str_instances_set)

def _find_oracle_db():
    """Returns first Oracle connection from Credentials file"""
    try:
        import cx_Oracle
    except ImportError:
        print("Module cx_Oracle is not available so this test is not applicable:")
        return None

    instances_oracle_dbs = ClientObjectInstancesFromScript(
        "sources_types/Databases/oracle_tnsnames.py")

    # Typical content: 'addr.Id=127.0.0.1:1521', 'oracle/db.Db=XE_WINDOWS',
    # 'oracle/db.Db=XE', 'oracle/db.Db=XE_OVH', 'addr.Id=vps516494.ovh.net:1521',
    # 'addr.Id=192.168.0.17:1521', 'oracle/db.Db=XE_FEDORA'}

    # Sorted in alphabetical order.
    str_instances = sorted([
        str(one_inst.Db)
        for one_inst in instances_oracle_dbs
        if one_inst.__class__.__name__ == "oracle/db"])

    if str_instances:
        return str_instances[0]
    else:
        print("No Oracle database available")
        return None


_global_oracle_db = _find_oracle_db()


@unittest.skipIf(_global_oracle_db is None, "Oracle not available")
class SurvolOracleTest(unittest.TestCase):
    """Testing Oracle discovery"""
    
    _oracle_db = _global_oracle_db

    def test_oracle_schemas(self):
        print("Oracle:", self._oracle_db)

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/oracle/db/oracle_db_schemas.py",
            "oracle/db",
            Db=self._oracle_db)

        str_instances_set = set([str(one_inst) for one_inst in lst_instances])

        # Typical content:
        for one_str in [
            'oracle/schema.Db=%s,Schema=SYSTEM' % self._oracle_db,
            'oracle/schema.Db=%s,Schema=ANONYMOUS' % self._oracle_db,
            'oracle/schema.Db=%s,Schema=SYS' % self._oracle_db,
        ]:
            self.assertTrue(one_str in str_instances_set)

    def test_oracle_connected_processes(self):
        print("Oracle:", self._oracle_db)

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/oracle/db/oracle_db_processes.py",
            "oracle/db",
            Db=self._oracle_db)

        str_instances_set = set([str(oneInst) for oneInst in lst_instances])

        print(str_instances_set)

        # Typical content:
        # 'CIM_Process.Handle=11772', 'oracle/db.Db=XE', 'Win32_UserAccount.Name=rchateau,Domain=rchateau-hp',
        # 'oracle/schema.Db=XE,Schema=SYSTEM', 'oracle/session.Db=XE,Session=102'
        for one_str in [
            CurrentProcessPath,
            'oracle/db.Db=%s' % self._oracle_db,
            'Win32_UserAccount.Name=%s,Domain=%s' % ( CurrentUsername, CurrentMachine),
        ]:
            self.assertTrue(one_str in str_instances_set)

    def test_oracle_running_queries(self):
        print("Oracle:", self._oracle_db)

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/oracle/db/oracle_db_parse_queries.py",
            "oracle/db",
            Db=self._oracle_db)

        # Typical content:
        # ['oracle/db.Db=XE_OVH', 'oracle/query.Query=ICBTRUxF... base64 ...ZGRyICA=,Db=XE_OVH']

        for one_inst in lst_instances:
            if one_inst.__class__.__name__ == 'oracle/query':
                import sources_types.oracle.query
                print("Decoded query:", sources_types.oracle.query.EntityName([one_inst.Query, one_inst.Db]))

                # TODO: This is not very consistent: sources_types.oracle.query.EntityName
                # TODO: produces a nice but truncated message, and the relation between
                # TODO: oracle.query and sql.query is not obvious.
                import sources_types.sql.query
                qry_decoded_full = sources_types.sql.query.EntityName([one_inst.Query])
                print("Decoded query:", qry_decoded_full)
                # The query must start with a select.
                self.assertTrue(qry_decoded_full.strip().upper().startswith("SELECT"))

                # TODO: Parse the query ? Or extracts its dependencies ?

    def test_oracle_view_dependencies(self):
        """Dsplays dependencies of a very common view"""

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/oracle/view/oracle_view_dependencies.py",
            "oracle/db",
            Db=self._oracle_db,
            Schema='SYS',
            View='ALL_ALL_TABLES')

        str_instances_set = set([str(one_inst) for one_inst in lst_instances])

        print(sorted(str_instances_set)[:10])

        # The dependencies of this view should always be the same,as it does not change often.
        for one_str in [
            'oracle/schema.Db=%s,Schema=SYS' % self._oracle_db,
            'oracle/synonym.Db=%s,Schema=PUBLIC,Synonym=ALL_ALL_TABLES' % self._oracle_db,
            'oracle/view.Db=%s,Schema=SYS,View=ALL_ALL_TABLES' % self._oracle_db,
            'oracle/view.Db=%s,Schema=SYS,View=ALL_OBJECT_TABLES' % self._oracle_db,
            'oracle/view.Db=%s,Schema=SYS,View=ALL_TABLES' % self._oracle_db,
        ]:
            self.assertTrue(one_str in str_instances_set)

    def test_oracle_schema_functions(self):
        """See functions of schema SYS"""
        print("Oracle:", self._oracle_db)

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/oracle/schema/oracle_schema_functions.py",
            "oracle/db",
            Db=self._oracle_db,
            Schema='SYS')

        str_instances_set = set([str(oneInst) for oneInst in lst_instances])

        print(str_instances_set)

        # Various functions which should always be in 'SYS' namespace:
        for one_str in [
            'oracle/function.Db=%s,Schema=SYS,Function=BLASTN_MATCH' % self._oracle_db,
        ]:
            self.assertTrue(one_str in str_instances_set)

    def test_oracle_schema_libraries(self):
        """See libraries of schema SYS"""
        print("Oracle:", self._oracle_db)

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/oracle/schema/oracle_schema_libraries.py",
            "oracle/db",
            Db=self._oracle_db,
            Schema='SYS')

        str_instances_set = set([str(oneInst) for oneInst in lst_instances])

        print(str_instances_set)

        # Various libraries which should always be in 'SYS' namespace:
        for one_str in [
            'oracle/library.Db=%s,Schema=SYS,Library=COLLECTION_LIB' % self._oracle_db,
        ]:
            self.assertTrue(one_str in str_instances_set)

    def test_oracle_schema_package_bodies(self):
        """See package bodies of schema SYS"""
        print("Oracle:", self._oracle_db)

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/oracle/schema/oracle_schema_package_bodies.py",
            "oracle/db",
            Db=self._oracle_db,
            Schema='SYS')

        str_instances_set = set([str(oneInst) for oneInst in lst_instances])

        print(str_instances_set)

        # Various package bodies which should always be in 'SYS' namespace:
        for one_str in [
            'oracle/package_body.Db=%s,Schema=SYS,PackageBody=DBMS_TRANSFORM' % self._oracle_db,
        ]:
            self.assertTrue(one_str in str_instances_set)

    def test_oracle_schema_packages(self):
        """See packages of schema SYS"""
        print("Oracle:", self._oracle_db)

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/oracle/schema/oracle_schema_packages.py",
            "oracle/db",
            Db=self._oracle_db,
            Schema='SYS')

        str_instances_set = set([str(oneInst) for oneInst in lst_instances])

        print(str_instances_set)

        # Various packages which should always be in 'SYS' namespace:
        for one_str in [
            'oracle/package.Db=%s,Schema=SYS,Package=AS_REPLAY' % self._oracle_db,
        ]:
            self.assertTrue(one_str in str_instances_set)

    def test_oracle_schema_procedures(self):
        """See procedures of schema SYS"""
        print("Oracle:", self._oracle_db)

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/oracle/schema/oracle_schema_procedures.py",
            "oracle/db",
            Db=self._oracle_db,
            Schema='SYS')

        str_instances_set = set([str(oneInst) for oneInst in lst_instances])

        print(str_instances_set)

        # Various procedures which should always be in 'SYS' namespace:
        for one_str in [
            'oracle/procedure.Db=%s,Schema=SYS,Procedure=SET_TABLESPACE' % self._oracle_db,
        ]:
            self.assertTrue(one_str in str_instances_set)

    def test_oracle_schema_sequences(self):
        """See sequences of schema SYS"""
        print("Oracle:", self._oracle_db)

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/oracle/schema/oracle_schema_sequences.py",
            "oracle/db",
            Db=self._oracle_db,
            Schema='SYS')

        str_instances_set = set([str(oneInst) for oneInst in lst_instances])

        print(str_instances_set)

        # Various sequences which should always be in 'SYS' namespace:
        for one_str in [
            'oracle/sequence.Db=%s,Schema=SYS,Sequence=SYSTEM_GRANT' % self._oracle_db,
        ]:
            self.assertTrue(one_str in str_instances_set)

    def test_oracle_schema_synonyms(self):
        """See synonyms of schema SYS"""
        print("Oracle:", self._oracle_db)

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/oracle/schema/oracle_schema_synonyms.py",
            "oracle/db",
            Db=self._oracle_db,
            Schema='SYS')

        str_instances_set = set([str(oneInst) for oneInst in lst_instances])

        print(str_instances_set)

        # Various synonyms which should always be in 'SYS' namespace:
        for one_str in [
            'oracle/synonym.Db=%s,Schema=SYS,Synonym=XMLDOM' % self._oracle_db,
        ]:
            self.assertTrue(one_str in str_instances_set)

    def test_oracle_schema_tables(self):
        """See functions of schema SYS"""
        print("Oracle:", self._oracle_db)

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/oracle/schema/oracle_schema_tables.py",
            "oracle/db",
            Db=self._oracle_db,
            Schema='SYS')

        str_instances_set = set([str(oneInst) for oneInst in lst_instances])

        print(str_instances_set)

        # Various tables which should always be in 'SYS' namespace:
        for one_str in [
            'oracle/table.Db=%s,Schema=SYS,Table=SQLERROR$' % self._oracle_db,
        ]:
            self.assertTrue(one_str in str_instances_set)

    def test_oracle_schema_triggers(self):
        """See triggers of schema SYS"""
        print("Oracle:", self._oracle_db)

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/oracle/schema/oracle_schema_triggers.py",
            "oracle/db",
            Db=self._oracle_db,
            Schema='SYS')

        str_instances_set = set([str(oneInst) for oneInst in lst_instances])

        print(str_instances_set)

        # Various triggers which should always be in 'SYS' namespace:
        for one_str in [
            'oracle/trigger.Db=%s,Schema=SYS,Trigger=AW_DROP_TRG' % self._oracle_db,
        ]:
            self.assertTrue(one_str in str_instances_set)

    def test_oracle_schema_types(self):
        """See types of schema SYS"""
        print("Oracle:", self._oracle_db)

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/oracle/schema/oracle_schema_types.py",
            "oracle/db",
            Db=self._oracle_db,
            Schema='SYS')

        str_instances_set = set([str(oneInst) for oneInst in lst_instances])

        print(str_instances_set)

        # Various types which should always be in 'SYS' namespace:
        for one_str in [
            'oracle/type.Db=%s,Schema=SYS,Type=AQ$_HISTORY' % self._oracle_db,
        ]:
            self.assertTrue(one_str in str_instances_set)

    def test_oracle_schema_views(self):
        print("Oracle:", self._oracle_db)

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/oracle/schema/oracle_schema_views.py",
            "oracle/db",
            Db=self._oracle_db,
            Schema='SYS')

        str_instances_set = set([str(one_inst) for one_inst in lst_instances])

        # Just print some data for information.
        print(sorted(str_instances_set)[:10])

        # Various views which should always be in 'SYS' namespace:
        for one_str in [
            'oracle/view.Db=%s,Schema=SYS,View=ALL_ALL_TABLES' % self._oracle_db,
        ]:
            self.assertTrue(one_str in str_instances_set)


class SurvolPEFileTest(unittest.TestCase):
    """Testing pefile features"""

    @unittest.skipIf(not pkgutil.find_loader('pefile'), "pefile cannot be imported. test_pefile_exports not run.")
    def test_pefile_exports(self):
        """Tests exported functions of a DLL."""

        # Very common DLL on usual Windows machines.
        dll_file_name = r"C:\Windows\System32\gdi32.dll"

        lst_instances = ClientObjectInstancesFromScript(
            "sources_types/CIM_DataFile/portable_executable/pefile_exports.py",
            "CIM_DataFile",
            Name=dll_file_name)

        import sources_types.linker_symbol
        names_instance = set()

        for one_inst in lst_instances:
            if one_inst.__class__.__name__ == 'linker_symbol':
                inst_name = sources_types.linker_symbol.EntityName([one_inst.Name, one_inst.File])
                names_instance.add(inst_name)

        # Some exported functions which should be there.
        for one_str in [
            "CreateBitmapFromDxSurface",
            "DeleteDC",
            "GdiCreateLocalMetaFilePict",
            "ClearBitmapAttributes",
            "GetViewportOrgEx",
            "GdiDescribePixelFormat",
            "OffsetViewportOrgEx",
        ]:
            self.assertTrue(one_str in names_instance)


class SurvolSearchTest(unittest.TestCase):

    # TODO: This feature should probably be removed.
    # TODO: Make a simpler test with a fake class and a single script.
    # TODO: Consider using ldspider which is a much better long-term approach.
    # TODO: Should test the individual scripts, but replace the search algorithm.

    """Testing the search engine"""
    def test_search_local_string_flat(self):
        """Searches for a string in one file only. Two occurrences."""

        sample_file = os.path.join(os.path.dirname(__file__), "SampleDir", "SampleFile.txt")
        instance_origin = lib_client.Agent().CIM_DataFile(Name=sample_file)

        search_triple_store = instance_origin.find_string_from_neighbour(
            search_string="Maecenas",
            max_depth=1,
            filter_instances=None,
            filter_predicates=None)

        results = list(search_triple_store)

        print(results)
        self.assertEqual(len(results), 2)
        # The line number and occurrence number are concatenated after the string.
        self.assertTrue(str(results[0][2]).encode("utf-8").startswith( "Maecenas".encode("utf-8")))
        self.assertTrue(str(results[1][2]).encode("utf-8").startswith( "Maecenas".encode("utf-8")))

    def test_search_local_string_one_level(self):
        """Searches for a string in all files of one directory."""

        # There are not many files in this directory
        sample_dir = os.path.join(os.path.dirname(__file__), "SampleDir")
        instance_origin = lib_client.Agent().CIM_Directory(Name=sample_dir)

        search_triple_store = instance_origin.find_string_from_neighbour(
            search_string="Curabitur",
            max_depth=2,
            filter_instances=None,
            filter_predicates=None)
        list_triple = list(search_triple_store)
        print("stl_list=", list_triple)
        for tpl in list_triple:
            # One occurrence is enough for this test.
            print(tpl)
            break
        # tpl # To check if a result was found.
        # TODO: Check this

    # TODO: Remove search and instead use a Linked Data crawler such as https://github.com/ldspider/ldspider
    # TODO: ... or simply SparQL.
    def test_search_local_string(self):
        """Loads instances connected to an instance by every available script"""

        instance_origin = lib_client.Agent().CIM_Directory(
            Name="C:/Windows")

        # The service "PlugPlay" should be available on all Windows machines.
        list_instances = {
            lib_client.Agent().CIM_Directory(Name="C:/Windows/winxs"),
            lib_client.Agent().CIM_Directory(Name="C:/windows/system32"),
            lib_client.Agent().CIM_DataFile(Name="C:/Windows/epplauncher.mif"),
            lib_client.Agent().CIM_DataFile(Name="C:/Windows/U2v243.exe"),
        }

        list_predicates = {
            lib_properties.pc.property_directory,
        }

        must_find = "Hello"

        search_triple_store = instance_origin.find_string_from_neighbour(
            search_string=must_find,
            max_depth=3,
            filter_instances=list_instances,
            filter_predicates=list_predicates)
        for tpl in search_triple_store:
            print(tpl)
        # TODO: Check this

# Tests an internal URL
class SurvolInternalTest(unittest.TestCase):
    def check_internal_values(self, an_agent_str):

        an_agent = lib_client.Agent(an_agent_str)
        map_internal_data = an_agent.get_internal_data()

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
        print("an_agent_str=", an_agent_str)
        for key in map_internal_data:
            print("%-20s %20s"%(key, map_internal_data[key]))

        #"uriRoot": lib_util.uriRoot,
        #"HttpPrefix": lib_util.HttpPrefix(),
        #"RootUri": lib_util.RootUri(),
        #"RequestUri": lib_util.RequestUri()

        # This breaks on Linux Python 3:
        # "http://localhost:8000/survol"
        # "http://travis-job-051017ff-a582-4258-a817-d9cd836533a6:8000/survol"
        print("RootUri=", map_internal_data["RootUri"])
        print("an_agent_str=", an_agent_str)

        self.assertEqual(map_internal_data["uriRoot"], an_agent_str + "/survol")

        # When the agent is started automatically, "?xid=" is added at the end of the URL.
        # http://rchateau-hp:8000/survol/print_internal_data_as_json.py?xid=
        # This adds lib_util.xidCgiDelimiter at the end.
        self.assertEqual(map_internal_data["RootUri"], an_agent_str + "/survol/print_internal_data_as_json.py" + "?xid=")

    def test_internal_remote(self):
        self.check_internal_values(_remote_general_test_agent)

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
        # TODO: Check this.


if __name__ == '__main__':
    unittest.main()

# TODO: Test calls to <Any class>.AddInfo()
# TODO: When double-clicking any Python script, it should do something visible.

