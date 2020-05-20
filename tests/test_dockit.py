#!/usr/bin/env python

from __future__ import print_function

import os
import re
import sys
from xml.dom import minidom
import json
import tempfile
import unittest
import shutil
import rdflib
import subprocess
import collections

# In pytest, __file__ is abolute, but this is relative with unittest.
_current_file_dirname = os.path.abspath(os.path.dirname(__file__))

from init import *

from survol.scripts import dockit
# FIXME: It should be on Linux only.
from survol.scripts import linux_api_definitions


dock_input_files_path = os.path.join(_current_file_dirname, "dockit_input_test_trace_files")

dockit_output_files_path = os.path.join(_current_file_dirname, "dockit_output_files")

# This is the expected content of some generated files.
dockit_output_files_path_expected = os.path.join(_current_file_dirname, "dockit_output_files_expected")

# This is the directory of the command dockit.py and ised used to run it
# and check where the default ouput files are created.
# __file__ could be 'C:\\Python27\\lib\\site-packages\\survol\\scripts\\dockit.pyc'
dockit_dirname = os.path.abspath(os.path.dirname(dockit.__file__))

# Creates the destination file for result if not there, otherwise cleanup.
# This is needed otherwise pytest would run the Python files in this dir.
if os.path.exists(dockit_output_files_path):
    for file_object in os.listdir(dockit_output_files_path):
        file_object_path = os.path.join(dockit_output_files_path, file_object)
        if os.path.isfile(file_object_path) or os.path.islink(file_object_path):
            os.unlink(file_object_path)
        else:
            shutil.rmtree(file_object_path)
else:
    # Creates the outdir directory, because it is not there.
    os.makedirs(dockit_output_files_path)

def path_prefix_output_result(*file_path):
    return os.path.join(dockit_output_files_path, *file_path)


# Check content of the generated files.
# Depending on the file extension, this tries to load the content of the file.
# it returns the parsed content, depending on the extension,
def check_file_content(*file_path):
    full_file_path = path_prefix_output_result(*file_path)
    fil_descr = open(full_file_path)
    filename, file_extension = os.path.splitext(full_file_path)
    if file_extension == ".json":
        # Checks that this json file can be loaded.
        file_content = json.load(fil_descr)
    elif file_extension == ".xml":
        # Checks that this xml file can be parsed.
        file_content = minidom.parse(full_file_path)
    elif file_extension == ".rdf":
        rdflib_graph = rdflib.Graph()
        rdflib_graph.parse(full_file_path)
        num_triples = len(rdflib_graph)
        # There should be at least one triple.
        assert num_triples > 0
        file_content = rdflib_graph
    elif file_extension == ".ini":
        file_content = dockit.ini_file_check(full_file_path)
    else:
        file_content = None

    fil_descr.close()

    # Now compare this file with the expected one, if it is here.
    expected_file_path = os.path.join(dockit_output_files_path_expected, *file_path)
    try:
        expected_fil_descr = open(expected_file_path)
        expected_content = expected_fil_descr.readlines()
        print("Checking content of:", expected_file_path)

        fil_descr = open(full_file_path)
        actual_content = expected_fil_descr.readlines()

        # Each test has an ini file used by the script dockit.ini, to force a given date.
        # So there is not need to replace the date by the current one.
        for expected_line, actual_line in zip(expected_content, actual_content):
            assert expected_line == actual_line
        print("Comparison OK with ", full_file_path)
        expected_fil_descr.close()
        fil_descr.close()

    except IOError:
        print("INFO: No comparison file:", expected_file_path)
    return file_content


# This checks that a file was NOT created.
def check_file_missing(*file_path):
    full_file_path = path_prefix_output_result(*file_path)
    try:
        open(full_file_path)
        assert False, "File %s should not be there." % full_file_path
    except:
        pass

def path_prefix_input_file(*file_path):
    # Travis and PyCharm do not start this unit tests script from the same directory.
    # The test files are alongside the script.
    return os.path.join( dock_input_files_path, *file_path )


class LowLevelComponentsTest(unittest.TestCase):
    """
    Test parsing of strace output.
    """

    # This is a set of arguments of system function calls as displayed by strace or ltrace.
    # This checks if they are correctly parsed.
    def test_trace_line_parse(self):
        data_tst = [
            ('xyz',
              ["xyz"], 3),
            ('"Abcd"',
              ["Abcd"], 6),
            ('"Ab","cd"',
              ["Ab","cd"], 9),
            ('Ab,"cd"',
              ["Ab","cd"], 7),
            ('"Ab","cd","ef"',
              ["Ab","cd","ef"], 14),
            ('"Ab","cd","ef",gh',
              ["Ab","cd","ef","gh"], 17),
            ('"/usr/bin/grep", ["grep", "earth"]',
              ["/usr/bin/grep", ["grep", "earth"] ], 34),
            ('"/usr/bin/grep", ["grep", "earth", "moon"]',
              ["/usr/bin/grep", ["grep", "earth", "moon"] ], 42),
            ('"/usr/bin/grep", ["grep", "earth", "moon"], "sun"',
              ["/usr/bin/grep", ["grep", "earth", "moon"], "sun" ], 49),
            ('"","cd"',
              ["","cd"], 7),
            ('3 <unfinished ...>',
              ["3"], 2),
            ('<... close resumed>',
              ['<... close resumed>'], 19),
            ('"12345",""',
              ["12345",""], 10),
            ('8, "/\nbid_convert_data.o/\nbid128_noncomp.o/\nbid128_compare.o/\nbid32_to_bid64.o/\nbid32_to_bid128.o/\nbid64_to_bid128.o/\nbid64_to_int32.o/\nbid64_to_int64.o/\nbid64_to_uint32.o/\nbid64_to_uint64.o/\nbid128_to_in"..., 4096',
              ['8', '/\nbid_convert_data.o/\nbid128_noncomp.o/\nbid128_compare.o/\nbid32_to_bid64.o/\nbid32_to_bid128.o/\nbid64_to_bid128.o/\nbid64_to_int32.o/\nbid64_to_int64.o/\nbid64_to_uint32.o/\nbid64_to_uint64.o/\nbid128_to_in...', '4096'], 214),
            ('3</usr/lib64/libpcre.so.1.2.8>',
              ['3</usr/lib64/libpcre.so.1.2.8>'], 30),
            ('NULL, 4000096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3</usr/lib64/libc-2.25.so>, 0',
              ['NULL', '4000096', 'PROT_READ|PROT_EXEC', 'MAP_PRIVATE|MAP_DENYWRITE', '3</usr/lib64/libc-2.25.so>', '0'], 92),
            ('"/usr/bin/grep", ["grep", "Hello", "../Divers/com_type_l"...], 0x7ffd8a76efa8 /* 17 vars */',
              ['/usr/bin/grep', ['grep', 'Hello', '../Divers/com_type_l...'], '0x7ffd8a76efa8 /* 17 vars */'], 91),
            ('3</usr/lib64/libpthread-2.21.so>, "xyz", 832',
              ['3</usr/lib64/libpthread-2.21.so>', 'xyz', '832'], 44),
            ('1<pipe:[7124131]>, TCGETS, 0x7ffe58d35d60',
              ['1<pipe:[7124131]>', 'TCGETS', '0x7ffe58d35d60'], 41),
            ('3<TCP:[127.0.0.1:59100->127.0.0.1:3306]>, SOL_IP, IP_TOS, [8], 4',
              ['3<TCP:[127.0.0.1:59100->127.0.0.1:3306]>', 'SOL_IP', 'IP_TOS', ['8'], '4'], 64),
            ('"/usr/bin/python", ["python", "TestProgs/big_mysql_"...], [/* 37 vars */]',
              ['/usr/bin/python', ['python', 'TestProgs/big_mysql_...'], ['/* 37 vars */']], 73),

            ('3</usr/lib64/libc-2.21.so>, "\x7fELF\x02\x01\x01\x03\\>\x00"..., 832',
                ['3</usr/lib64/libc-2.21.so>', '\x7fELF\x02\x01\x01\x03\\>\x00...', '832'], 49),

            ('29</home/rchateau/.mozilla/firefox/72h59sxe.default/cookies.sqlite>, "SQLite format 3\0\200\0\2\2\0@  \0\0\0\4\0\0\0\4\0\0\0\0\0\0\0\0\0\0\0\2\0\0\0\4\0\0\0\0\0\0\0\0\0\0\0\1\0\0\0\t\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\4\0.\30\310", 100',
              ['29</home/rchateau/.mozilla/firefox/72h59sxe.default/cookies.sqlite>', 'SQLite format 3\x00\x80\x00\x02\x02\x00@  \x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\t\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00.\x18\xc8', '100'], 176),

            ('5</etc/pki/nssdb/key4.db>, "\r\0\0\0\1\0G\0\0G\3\313\0\0\0\0\0\0\2076\1\7\27!!\1\2167tablenssPrivatenssPrivate\2CREATE TABLE nssP\2076\1\7\27!!\1\2167tablenssPrivatenssPrivate\2CREATE TABLE nssPrivate (id PRIMARY KEY UNIQUE ON CONFLICT ABORT, a0, a1, a2, a3, a10, a11, a"..., 1024, 3072',
              ['5</etc/pki/nssdb/key4.db>', '\r\x00\x00\x00\x01\x00G\x00\x00G\x03\xcb\x00\x00\x00\x00\x00\x00\x876\x01\x07\x17!!\x01\x8e7tablenssPrivatenssPrivate\x02CREATE TABLE nssP\x876\x01\x07\x17!!\x01\x8e7tablenssPrivatenssPrivate\x02CREATE TABLE nssPrivate (id PRIMARY KEY UNIQUE ON CONFLICT ABORT, a0, a1, a2, a3, a10, a11, a...', '1024', '3072'], 244),

            ('4</etc/pki/nssdb/cert9.db>, F_SETLK, {l_type=F_RDLCK, l_whence=SEEK_SET, l_start=1073741824, l_len=1}',
                ['4</etc/pki/nssdb/cert9.db>', 'F_SETLK', ['l_type=F_RDLCK', 'l_whence=SEEK_SET', 'l_start=1073741824', 'l_len=1']], 101),

            ('4</etc/pki/nssdb/cert9.db>, "\0\0\0\2\0\0\0\t\0\0\0\0\0\0\0\0", 16, 24',
              ['4</etc/pki/nssdb/cert9.db>', '\x00\x00\x00\x02\x00\x00\x00\t\x00\x00\x00\x00\x00\x00\x00\x00', '16', '24'], 54),

            ('0</dev/pts/2>, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 2)}',
              ['0</dev/pts/2>', ['st_mode=S_IFCHR|0620', 'st_rdev=makedev(136, 2)']], 62),

            ('6, [4<UNIX:[3646855,"/run/proftpd/proftpd.sock"]>], NULL, NULL, {tv_sec=0, tv_usec=500}',
              ['6', ['4<UNIX:[3646855,"/run/proftpd/proftpd.sock"]>'], 'NULL', 'NULL', ['tv_sec=0', 'tv_usec=500']], 87),

            ('13<UNIX:[10579575->10579582]>, SOL_SOCKET, SO_PEERSEC, "system_u:system_r:system_dbusd_t:s0-s0:c0.c1023\0", [64->48]',
              ['13<UNIX:[10579575->10579582]>', 'SOL_SOCKET', 'SO_PEERSEC', 'system_u:system_r:system_dbusd_t:s0-s0:c0.c1023\x00', ['64->48']], 115),

            ('17<TCP:[54.36.162.150:32855]>, {sa_family=AF_INET, sin_port=htons(63705), sin_addr=inet_addr("82.45.12.63")}, [16]',
              ['17<TCP:[54.36.162.150:32855]>', ['sa_family=AF_INET', 'sin_port=htons(63705)', 'sin_addr=inet_addr("82.45.12.63")'], ['16']], 114),

            ('"/usr/bin/gcc", ["gcc", "-O3", "ProgsAndScriptsForUnitTests/HelloWorld.c"], 0x7ffd8b44aab8 /* 30 vars */) = 0 <0.000270>',
              ['/usr/bin/gcc', ['gcc', '-O3', 'ProgsAndScriptsForUnitTests/HelloWorld.c'], '0x7ffd8b44aab8 /* 30 vars */'], 106),

            # TODO: ltrace does not escape double-quotes:
            #  "\001$\001$\001\026\001"\0015\001\n\001\r\001\r\001\f\001(\020",
            # "read@SYS(3, "" + str(row) + "\\n")\n\n", 4096)"
            # This string is broken due to the repeated double-quote.
            # ( '4, "\001\024\001$\001$\001\026\001"\0015\001\n\001\r\001\004\002\r\001\f\001(\020", 4096) = 282 <0.000051>',
            #   ['4', '\x01\x14\x01$\x01$\x01\x16\x01"\x015\x01\n\x01\r\x01\x04\x02\r\x01\x0c\x01(\x10', '4096'], 987979 ),

        ]

        for tupl in data_tst:
            # The input string theoretically starts and ends with parenthesis,
            # but the closing one might not be there.
            # Therefore it should be tested with and without the closing parenthesis.
            resu,idx = linux_api_definitions.parse_call_arguments(tupl[0])
            if resu != tupl[1]:
                raise Exception("\n     Fail:%s\nSHOULD BE:%s" % ( str(resu),str(tupl[1])  ) )

            # This must be the position of the end of the arguments.
            if idx != tupl[2]:
                raise Exception("Fail idx: %d SHOULD BE:%d" % ( idx, tupl[2] ) )

            if idx != len(tupl[0]):
                if not tupl[0][idx:].startswith("<unfinished ...>"):
                    if tupl[0][idx-2] != ')':
                        raise Exception("Fail idx2: len=%d %d SHOULD BE:%d; S=%s / '%s'" % (len(tupl[0]), idx, tupl[2], tupl[0], tupl[0][idx-2:] ) )

    def test_usage(self):
        # Conventional value 999 makes that this function does not exit.
        dockit.print_dockit_usage(999)


# This runs dockit as a command. Its returns the content of stdout.
def _run_dockit_command(one_command):
    if is_platform_linux:
        dockit_command = "cd %s;%s dockit.py %s" % (dockit_dirname, sys.executable, one_command)
    else:
        # The executable could contain spaces like:
        # 'C:\\Program Files (x86)\\Microsoft Visual Studio\\Shared\\Python36_64\\python.exe',
        # therefore it must be enclosed in quotes.
        dockit_command = 'cd %s&"%s" dockit.py %s' % (dockit_dirname, sys.executable, one_command)
    print("dockit_command=", dockit_command)
    output_content = subprocess.check_output(dockit_command, shell=True)
    return output_content


# The script dockit.py can be used as a command line or as an imported module.
# This test checks the script dockit.py from from command lines, and not from the internal function.
class CommandLineTest(unittest.TestCase):

    def test_usage(self):
        """This tests the help message displayed by dockit.py """
        command_result = _run_dockit_command("--help")
        self.assertTrue(command_result.startswith(b"DockIT"))

    @unittest.skipIf(is_platform_windows, "This is not a Linux machine. Test skipped.")
    def test_run_linux_ls(self):

        output_basename_prefix = "test_linux_ls"
        output_prefix = path_prefix_output_result(output_basename_prefix)
        command_result = _run_dockit_command("-D -f JSON -F TXT -l %s ls" % output_prefix)

        # This creates files like ".../test_linux_ls.strace<pid>.ini"
        check_file_content(output_basename_prefix + ".ini")
        check_file_content(output_basename_prefix + ".json")
        check_file_content(output_basename_prefix + ".summary.txt")
        check_file_content(output_basename_prefix + ".docker", "Dockerfile")

        check_file_missing(output_basename_prefix + ".log")

    def test_replay_non_existent_input_file(self):
        try:
            _run_dockit_command("--input does_not_exist")
            self.fail("An exception should be thrown")
        except Exception as exc:
            print("exc=", exc)

    def test_replay_sample_shell_ltrace(self):
        input_log_file = path_prefix_input_file("sample_shell.ltrace.log")
        output_basename_prefix = "sample_shell.ltrace"
        output_prefix = path_prefix_output_result(output_basename_prefix)

        dockit_command = "--input %s --dockerfile --log %s -t ltrace --duplicate" % (
            input_log_file,
            output_prefix)
        command_result = _run_dockit_command(dockit_command)
        self.assertTrue(command_result.startswith(b"Loading ini file:"))

        # No ini file created because this is a replay session from a log file.
        check_file_missing(output_basename_prefix + ".txt")

        # No ini file created because this is a replay session from a log file.
        check_file_missing(output_basename_prefix + ".ini")

        # This file must be created because "--duplicate" options is set.
        check_file_content(output_basename_prefix + ".log")

    def test_replay_oracle_db_data_strace(self):
        input_log_file = path_prefix_input_file("oracle_db_data.strace.5718.log")
        output_basename_prefix = "oracle_db_data.strace.5718"
        output_prefix = path_prefix_output_result(output_basename_prefix)

        dockit_command = "--input %s --dockerfile --log %s -t strace" % (
            input_log_file,
            output_prefix)
        command_result = _run_dockit_command(dockit_command)

        self.assertTrue(command_result.startswith(b"Loading ini file:"))

        # No ini file created because this is a replay session from a log file.
        check_file_content(output_basename_prefix + ".txt")

        # No ini file created because this is a replay session from a log file.
        check_file_missing(output_basename_prefix + ".ini")

        # This file should not be created because "--duplicate" options is not set.
        check_file_missing(output_basename_prefix + ".log")

    # This processes an existing input file by running the script dockit.py.
    def test_replay_sample_shell_strace(self):
        input_log_file = path_prefix_input_file("sample_shell.strace.log")
        output_basename_prefix = "sample_shell.strace"
        output_prefix = path_prefix_output_result(output_basename_prefix)

        dockit_command = "--input %s --dockerfile --log %s -t strace" % (
            input_log_file,
            output_prefix)
        command_result = _run_dockit_command(dockit_command)
        self.assertTrue(command_result.startswith(b"Loading ini file:"))

        # The pid 4401 comes from the input log file.
        output_file_path = output_prefix + ".txt"

        expected_output = [
            "calls_number:29\n",
            "process_id:18198\n",
            "calls_number:84\n",
            "process_id:18196\n",
            "calls_number:2754\n",
            "process_id:18195\n",
            "calls_number:77\n",
            "process_id:18194\n",
            "calls_number:12\n",
            "process_id:18193\n",
            "calls_number:66\n",
            "process_id:4401\n",
        ]

        with open(output_file_path) as output_file_descriptor:
            output_file_content = output_file_descriptor.readlines()
        print("output_file_content=", output_file_content)
        self.assertTrue(output_file_content == expected_output)

    def test_replay_sqlplus_strace(self):
        input_log_file = path_prefix_input_file("sqlplus.strace.4401.log")
        output_basename_prefix = "sqlplus.strace.4401"
        output_prefix = path_prefix_output_result(output_basename_prefix)

        dockit_command = "--input %s --dockerfile --log %s -t strace" % (
            input_log_file,
            output_prefix)
        command_result = _run_dockit_command(dockit_command)

        check_file_content(output_basename_prefix + ".docker", "Dockerfile")
        check_file_missing(output_basename_prefix + ".ini")

    @unittest.skipIf(is_platform_linux, "Windows only.")
    def test_replay_windows_dir(self):
        input_log_file = path_prefix_input_file("windows_dir.pydbg.45884.log")
        output_basename_prefix = "windows_dir.pydbg.45884"
        output_prefix = path_prefix_output_result(output_basename_prefix)

        dockit_command = "--input %s --dockerfile --log %s -t strace" % (
            input_log_file,
            output_prefix)
        command_result = _run_dockit_command(dockit_command)

        check_file_content(output_basename_prefix + ".docker", "Dockerfile")
        check_file_missing(output_basename_prefix + ".ini")


# The script dockit.py can be used as a command line or as an imported module.
# This test checks the script dockit.py from from command lines, and not from the internal function.
@unittest.skipIf(is_platform_linux, "Windows only.")
class CommandLineWin32Test(unittest.TestCase):

    def test_run_windows_ping_nowhere(self):
        """This runs "ping" and the command help must be print."""
        command_result = _run_dockit_command("ping")

        # Now parse the output to ensure that the command ran correctly.

        # C:\Survol>ping
        #
        # Usage: ping [-t] ...

        # [msdos@domain survol]$ ping
        # Usage: ping [-aAbBdDfhLnOqrRUvV64] ...

        self.assertTrue( command_result.find(b"Usage: ping") >= 0)

    def test_run_windows_ping_home(self):
        # This test pings to a domain name.
        output_basename_prefix = "test_run_windows_ping_home_%d" % CurrentPid
        output_prefix = path_prefix_output_result(output_basename_prefix)
        command_result = _run_dockit_command("--log=%s ping primhillcomputers.com" % output_prefix)

        # The ini file is always created and store some parameters to replay the sessiosn.
        check_file_content(output_basename_prefix + ".ini")
        check_file_content(output_basename_prefix + ".txt")

        # The parameter to log the function calls is not given on the command line.
        check_file_missing(output_basename_prefix + ".log")

        # The parameter to create a Dockerfile is not given on the command line.
        check_file_missing(output_basename_prefix + ".docker", "Dockerfile")

    def test_run_windows_ping_github(self):
        output_basename_prefix = "test_run_windows_ping_github_%d" % CurrentPid
        output_prefix = path_prefix_output_result(output_basename_prefix)
        command_result = _run_dockit_command("--log=%s --duplicate ping github.com" % output_prefix)

        check_file_content(output_basename_prefix + ".ini")
        check_file_content(output_basename_prefix + ".txt")
        check_file_content(output_basename_prefix + ".log")

        check_file_missing(output_basename_prefix + ".docker", "Dockerfile")

    def test_run_windows_echo(self):
        output_basename_prefix = "test_run_windows_echo_%d" % CurrentPid
        output_prefix = path_prefix_output_result(output_basename_prefix)

        output_tmpfile = output_prefix + ".tmp.txt"
        dockit_command = "%s /c echo HelloWorld > %s" % (windows_system32_cmd_exe, output_tmpfile)
        command_result = _run_dockit_command(dockit_command)

        self.assertTrue(command_result == b"")

        # The outputs of the command and of dockit.py are redirected to the same file.
        with open(output_tmpfile) as results_file_descriptor:
            result_lines = results_file_descriptor.readlines()
            self.assertTrue(result_lines[0].startswith("HelloWorld"))

        print("output_tmpfile=", output_tmpfile)

        # No other output file is created.
        check_file_missing(output_basename_prefix + ".ini")
        check_file_missing(output_basename_prefix + ".txt")
        check_file_missing(output_basename_prefix + ".log")
        check_file_missing(output_basename_prefix + ".docker", "Dockerfile")

    def test_run_windows_dir(self):
        """This generates a replay filename and reuses it immediately."""
        output_basename_prefix = "test_run_windows_dir"
        output_prefix = path_prefix_output_result(output_basename_prefix)

        dockit_command = "--log=%s --duplicate %s /c DIR" % (output_prefix, windows_system32_cmd_exe)
        command_result = _run_dockit_command(dockit_command)

        check_file_content(output_basename_prefix + ".ini")
        check_file_content(output_basename_prefix + ".log")

    def test_run_windows_mkdir_rdf(self):
        """This generates a replay filename and reuses it immediately."""
        output_basename_prefix = "test_run_windows_mkdir_rdf"
        created_rdf_file = path_prefix_output_result(output_basename_prefix + ".rdf")
        created_directory = path_prefix_output_result(output_basename_prefix + ".dir")

        dockit_command = "--server=%s %s /c mkdir %s" % (created_rdf_file, windows_system32_cmd_exe, created_directory)
        command_result = _run_dockit_command(dockit_command)

        # The ini file is created with a default name.
        # It does not use check_file_content because the output directory is not standard.
        ini_file_default = os.path.join(dockit_dirname, "dockit_output" + ".ini")
        dockit.ini_file_check(ini_file_default)

        # This RDF file contains the raw triples generated from events.
        # It does not contain semantic data necessary for SPARQL quries such as rdflib.namespace.RDF.type.
        rdf_content = check_file_content(created_rdf_file)
        # http://rchateau-hp:80/LocalExecution/entity.py?xid=CIM_NetworkAdapter.Name=192.168.1.10
        # http://www.primhillcomputers.com/survol#Name
        # 192.168.1.10
        # http://rchateau-hp:80/LocalExecution/entity.py?xid=CIM_OperatingSystem.
        # http://www.primhillcomputers.com/survol#OSType
        # win32
        # http://rchateau-hp:80/LocalExecution/entity.py?xid=CIM_ComputerSystem.Name=rchateau-hp
        # http://www.primhillcomputers.com/survol#VirtualMemoryTotal
        # 17099120640
        # http://rchateau-hp:80/LocalExecution/entity.py?xid=CIM_ComputerSystem.Name=rchateau-hp
        # http://www.primhillcomputers.com/survol#VirtualMemoryUsed
        # 14555295744
        # http://rchateau-hp:80/LocalExecution/entity.py?xid=CIM_OperatingSystem.
        # http://www.primhillcomputers.com/survol#Release
        # 7
        # http://rchateau-hp:80/LocalExecution/entity.py?xid=CIM_OperatingSystem.
        # http://www.primhillcomputers.com/survol#Platform
        # Windows-7-6.1.7601-SP1
        # http://rchateau-hp:80/LocalExecution/entity.py?xid=CIM_ComputerSystem.Name=rchateau-hp
        # http://www.primhillcomputers.com/survol#CpuMinimum
        # 0.0
        # http://rchateau-hp:80/LocalExecution/entity.py?xid=CIM_OperatingSystem.
        # http://www.primhillcomputers.com/survol#Name
        # nt
        # http://rchateau-hp:80/LocalExecution/entity.py?xid=CIM_ComputerSystem.Name=rchateau-hp
        # http://www.primhillcomputers.com/survol#VirtualMemoryAvailable
        # 2543824896
        # http://rchateau-hp:80/LocalExecution/entity.py?xid=CIM_ComputerSystem.Name=rchateau-hp
        # http://www.primhillcomputers.com/survol#CpuMaximum
        # 3200.0
        # http://rchateau-hp:80/LocalExecution/entity.py?xid=CIM_OperatingSystem.
        # http://www.primhillcomputers.com/survol#System
        # Windows
        # http://rchateau-hp:80/LocalExecution/entity.py?xid=CIM_ComputerSystem.Name=rchateau-hp
        # http://www.primhillcomputers.com/survol#CpuCurrent
        # 3200.0
        # http://rchateau-hp:80/LocalExecution/entity.py?xid=CIM_ComputerSystem.Name=rchateau-hp
        # http://www.primhillcomputers.com/survol#Name
        # rchateau-hp
        # http://rchateau-hp:80/LocalExecution/entity.py?xid=CIM_ComputerSystem.Name=rchateau-hp
        # http://www.primhillcomputers.com/survol#VirtualMemoryFree
        # 2543824896
        # http://rchateau-hp:80/LocalExecution/entity.py?xid=CIM_NetworkAdapter.Name=192.168.1.10
        # http://www.primhillcomputers.com/survol#PermanentAddress
        # 192.168.1.10
        triples_as_string = [
            (str(rdf_subject), str(rdf_predicate), str(rdf_object))
            for rdf_subject, rdf_predicate, rdf_object in rdf_content.triples((None, None, None))
        ]

        self.assertTrue((
            "http://rchateau-hp:80/LocalExecution/entity.py?xid=CIM_OperatingSystem.",
            "http://www.primhillcomputers.com/survol#System",
            "Windows"
        ) in triples_as_string)

        current_ip_address = socket.gethostbyname(socket.gethostname())
        self.assertTrue((
            "http://rchateau-hp:80/LocalExecution/entity.py?xid=CIM_NetworkAdapter.Name=%s" % current_ip_address,
            "http://www.primhillcomputers.com/survol#PermanentAddress",
            current_ip_address
        ) in triples_as_string)

        check_file_missing(output_basename_prefix + ".log")
        check_file_missing(output_basename_prefix + ".docker", "Dockerfile")


class SummaryXMLTest(unittest.TestCase):
    @staticmethod
    def _rebuild_process_tree_aux(current_node, margin=""):

        summary_process_tree = {}

        submargin = margin + "   "
        for sub_node in current_node.childNodes:
            if sub_node.localName == 'CIM_Process':
                sub_object = SummaryXMLTest._rebuild_process_tree_aux(sub_node, submargin)
                process_id = int(sub_node.attributes['Handle'].value)
                summary_process_tree[process_id] = sub_object

        return summary_process_tree

    @staticmethod
    def rebuild_process_tree(output_summary_file):
        mydoc = minidom.parse(output_summary_file)
        current_node = mydoc.getElementsByTagName('Dockit')

        return SummaryXMLTest._rebuild_process_tree_aux(current_node[0])


    # This loads a log file generated by strace and rebuilds the processes tree.
    def test_summary_XML_strace1(self):
        # For testing the creation of summary XML file from a strace log.
        strace_logfile_content = """
12:43:54.334660 execve("/usr/bin/gcc", ["gcc", "-O3", "ProgsAndScriptsForUnitTests/HelloWorld.c"], 0x7ffd8b44aab8 /* 30 vars */) = 0 <0.000270>
12:43:54.351205 vfork( <unfinished ...>
[pid 19353] 12:43:54.353230 execve("/usr/libexec/gcc/x86_64-redhat-linux/7/cc1", ["/usr/libexec/gcc/x86_64-redhat-linux/7/cc1", "-quiet", "ProgsAndScriptsForUnitTests/HelloWorld.c", "-quiet", "-dumpbase", "HelloWorld.c", "-mtune=generic", "-march=x86-64", "-auxbase", "HelloWorld", "-O3", "-o", "/tmp/ccPlYSs9.s"], 0x175f140 /* 35 vars */ <unfinished ...>
[pid 19351] 12:43:54.353461 <... vfork resumed> ) = 19353 <0.002239>
[pid 19351] 12:43:54.353502 wait4(19353,  <unfinished ...>
[pid 19353] 12:43:54.353866 <... execve resumed> ) = 0 <0.000557>
[pid 19353] 12:43:54.468360 exit_group(0) = ?
12:43:54.469190 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 19353 <0.115666>
12:43:54.469217 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=19353, si_uid=1001, si_status=0, si_utime=2, si_stime=1} ---
12:43:54.469708 vfork( <unfinished ...>
[pid 19354] 12:43:54.470903 execve("/u01/app/oracle/product/11.2.0/xe/bin/as", ["as", "--64", "-o", "/tmp/ccajVp6K.o", "/tmp/ccPlYSs9.s"], 0x175f140 /* 35 vars */) = -1 ENOENT (No such file or directory) <0.000132>
[pid 19354] 12:43:54.471761 execve("/usr/local/bin/as", ["as", "--64", "-o", "/tmp/ccajVp6K.o", "/tmp/ccPlYSs9.s"], 0x175f140 /* 35 vars */) = -1 ENOENT (No such file or directory) <0.000037>
[pid 19354] 12:43:54.471997 execve("/usr/bin/as", ["as", "--64", "-o", "/tmp/ccajVp6K.o", "/tmp/ccPlYSs9.s"], 0x175f140 /* 35 vars */ <unfinished ...>
[pid 19351] 12:43:54.472143 <... vfork resumed> ) = 19354 <0.002423>
[pid 19351] 12:43:54.472159 wait4(19354,  <unfinished ...>
[pid 19354] 12:43:54.472530 <... execve resumed> ) = 0 <0.000492>
[pid 19354] 12:43:54.492949 exit_group(0) = ?
12:43:54.493438 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 19354 <0.021274>
12:43:54.493460 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=19354, si_uid=1001, si_status=0, si_utime=0, si_stime=0} ---
12:43:54.494581 vfork( <unfinished ...>
[pid 19355] 12:43:54.499593 execve("/usr/libexec/gcc/x86_64-redhat-linux/7/collect2", ["/usr/libexec/gcc/x86_64-redhat-linux/7/collect2", "-plugin", "/usr/libexec/gcc/x86_64-redhat-linux/7/liblto_plugin.so", "-plugin-opt=/usr/libexec/gcc/x86_64-redhat-linux/7/lto-wrapper", "-plugin-opt=-fresolution=/tmp/cc3Y2UNm.res", "-plugin-opt=-pass-through=-lgcc", "-plugin-opt=-pass-through=-lgcc_s", "-plugin-opt=-pass-through=-lc", "-plugin-opt=-pass-through=-lgcc", "-plugin-opt=-pass-through=-lgcc_s", "--build-id", "--no-add-needed", "--eh-frame-hdr", "--hash-style=gnu", "-m", "elf_x86_64", "-dynamic-linker", "/lib64/ld-linux-x86-64.so.2", "/usr/lib/gcc/x86_64-redhat-linux/7/../../../../lib64/crt1.o", "/usr/lib/gcc/x86_64-redhat-linux/7/../../../../lib64/crti.o", "/usr/lib/gcc/x86_64-redhat-linux/7/crtbegin.o", "-L/usr/lib/gcc/x86_64-redhat-linux/7", "-L/usr/lib/gcc/x86_64-redhat-linux/7/../../../../lib64", "-L/lib/../lib64", "-L/usr/lib/../lib64", "-L/usr/lib/gcc/x86_64-redhat-linux/7/../../..", "/tmp/ccajVp6K.o", "-lgcc", "--as-needed", "-lgcc_s", "--no-as-needed", "-lc", "-lgcc", "--as-needed", "-lgcc_s", "--no-as-needed", "/usr/lib/gcc/x86_64-redhat-linux/7/crtend.o", "/usr/lib/gcc/x86_64-redhat-linux/7/../../../../lib64/crtn.o"], 0x175eac0 /* 37 vars */ <unfinished ...>
[pid 19351] 12:43:54.499796 <... vfork resumed> ) = 19355 <0.005197>
[pid 19351] 12:43:54.499813 wait4(19355,  <unfinished ...>
[pid 19355] 12:43:54.499922 <... execve resumed> ) = 0 <0.000233>
[pid 19355] 12:43:54.504213 vfork( <unfinished ...>
[pid 19356] 12:43:54.506472 execve("/usr/bin/ld", ["/usr/bin/ld", "-plugin", "/usr/libexec/gcc/x86_64-redhat-linux/7/liblto_plugin.so", "-plugin-opt=/usr/libexec/gcc/x86_64-redhat-linux/7/lto-wrapper", "-plugin-opt=-fresolution=/tmp/cc3Y2UNm.res", "-plugin-opt=-pass-through=-lgcc", "-plugin-opt=-pass-through=-lgcc_s", "-plugin-opt=-pass-through=-lc", "-plugin-opt=-pass-through=-lgcc", "-plugin-opt=-pass-through=-lgcc_s", "--build-id", "--no-add-needed", "--eh-frame-hdr", "--hash-style=gnu", "-m", "elf_x86_64", "-dynamic-linker", "/lib64/ld-linux-x86-64.so.2", "/usr/lib/gcc/x86_64-redhat-linux/7/../../../../lib64/crt1.o", "/usr/lib/gcc/x86_64-redhat-linux/7/../../../../lib64/crti.o", "/usr/lib/gcc/x86_64-redhat-linux/7/crtbegin.o", "-L/usr/lib/gcc/x86_64-redhat-linux/7", "-L/usr/lib/gcc/x86_64-redhat-linux/7/../../../../lib64", "-L/lib/../lib64", "-L/usr/lib/../lib64", "-L/usr/lib/gcc/x86_64-redhat-linux/7/../../..", "/tmp/ccajVp6K.o", "-lgcc", "--as-needed", "-lgcc_s", "--no-as-needed", "-lc", "-lgcc", "--as-needed", "-lgcc_s", "--no-as-needed", "/usr/lib/gcc/x86_64-redhat-linux/7/crtend.o", "/usr/lib/gcc/x86_64-redhat-linux/7/../../../../lib64/crtn.o"], 0x7ffc023b8fd0 /* 37 vars */ <unfinished ...>
[pid 19355] 12:43:54.506621 <... vfork resumed> ) = 19356 <0.002398>
[pid 19355] 12:43:54.506674 wait4(19356,  <unfinished ...>
[pid 19356] 12:43:54.506760 <... execve resumed> ) = 0 <0.000216>
[pid 19356] 12:43:54.606281 exit_group(0) = ?
[pid 19355] 12:43:54.606691 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 19356 <0.100010>
[pid 19355] 12:43:54.606712 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=19356, si_uid=1001, si_status=0, si_utime=0, si_stime=0} ---
[pid 19355] 12:43:54.608051 exit_group(0) = ?
12:43:54.608189 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 19355 <0.108370>
12:43:54.608213 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=19355, si_uid=1001, si_status=0, si_utime=0, si_stime=0} ---
12:43:54.608378 exit_group(0)           = ?
"""

        tempfil_strace= tempfile.NamedTemporaryFile(mode='w+',delete=False)
        tempfil_strace.write(strace_logfile_content)
        tempfil_strace.close()

        output_summary_file = dockit.test_from_file(
            input_log_file=tempfil_strace.name,
            tracer="strace",
            input_process_id=19351,
            output_files_prefix=None,
            output_format=None,
            verbose=False,
            map_params_summary=dockit.full_map_params_summary,
            summary_format="XML",
            with_warning=False,
            with_dockerfile=False,
            update_server=None,
            aggregator=None)

        process_tree = SummaryXMLTest.rebuild_process_tree(output_summary_file)

        print(process_tree)

        # This tests the existence of some processes and subprocesses.
        process_tree[19351]
        process_tree[19351][19353]
        process_tree[19351][19354]
        process_tree[19351][19355]
        process_tree[19351][19355][19356]


    # This loads a log file generated by strace and rebuilds the processes tree.
    def test_summary_XML_strace2(self):
        # For testing the creation of summary XML file from a strace log.
        strace_logfile_content = """
19:37:50.321491 execve("/usr/bin/gcc", ["gcc", "-O3", "ProgsAndScriptsForUnitTests/HelloWorld.c"], 0x7ffdf59908e8 /* 30 vars */) = 0 <0.000170>
19:37:50.331960 vfork( <unfinished ...>
[pid 22034] 19:37:50.334013 execve("/usr/libexec/gcc/x86_64-redhat-linux/7/cc1", ["/usr/libexec/gcc/x86_64-redhat-linux/7/cc1", "-quiet", "ProgsAndScriptsForUnitTests/HelloWorld.c", "-quiet", "-dumpbase", "HelloWorld.c", "-mtune=generic", "-march=x86-64", "-auxbase", "HelloWorld", "-O3", "-o", "/tmp/cceK71h9.s"], 0x2514140 /* 35 vars */ <unfinished ...>
[pid 22033] 19:37:50.334164 <... vfork resumed> ) = 22034 <0.002192>
[pid 22033] 19:37:50.334185 wait4(22034,  <unfinished ...>
[pid 22034] 19:37:50.336857 <... execve resumed> ) = 0 <0.002784>
[pid 22034] 19:37:50.415238 exit_group(0) = ?
19:37:50.420925 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 22034 <0.086697>
19:37:50.420957 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=22034, si_uid=1001, si_status=0, si_utime=2, si_stime=1} ---
19:37:50.421368 vfork( <unfinished ...>
[pid 22035] 19:37:50.421446 execve("/u01/app/oracle/product/11.2.0/xe/bin/as", ["as", "--64", "-o", "/tmp/ccFp4gIJ.o", "/tmp/cceK71h9.s"], 0x2514140 /* 35 vars */) = -1 ENOENT (No such file or directory) <0.000016>
[pid 22035] 19:37:50.421509 execve("/usr/local/bin/as", ["as", "--64", "-o", "/tmp/ccFp4gIJ.o", "/tmp/cceK71h9.s"], 0x2514140 /* 35 vars */) = -1 ENOENT (No such file or directory) <0.000009>
[pid 22035] 19:37:50.421554 execve("/usr/bin/as", ["as", "--64", "-o", "/tmp/ccFp4gIJ.o", "/tmp/cceK71h9.s"], 0x2514140 /* 35 vars */ <unfinished ...>
[pid 22033] 19:37:50.421664 <... vfork resumed> ) = 22035 <0.000284>
[pid 22033] 19:37:50.421679 wait4(22035,  <unfinished ...>
[pid 22035] 19:37:50.421772 <... execve resumed> ) = 0 <0.000186>
[pid 22035] 19:37:50.443500 exit_group(0) = ?
19:37:50.444220 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 22035 <0.022534>
19:37:50.444258 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=22035, si_uid=1001, si_status=0, si_utime=0, si_stime=0} ---
19:37:50.445324 vfork( <unfinished ...>
[pid 22036] 19:37:50.445387 execve("/usr/libexec/gcc/x86_64-redhat-linux/7/collect2", ["/usr/libexec/gcc/x86_64-redhat-linux/7/collect2", "-plugin", "/usr/libexec/gcc/x86_64-redhat-linux/7/liblto_plugin.so", "-plugin-opt=/usr/libexec/gcc/x86_64-redhat-linux/7/lto-wrapper", "-plugin-opt=-fresolution=/tmp/cczFnlck.res", "-plugin-opt=-pass-through=-lgcc", "-plugin-opt=-pass-through=-lgcc_s", "-plugin-opt=-pass-through=-lc", "-plugin-opt=-pass-through=-lgcc", "-plugin-opt=-pass-through=-lgcc_s", "--build-id", "--no-add-needed", "--eh-frame-hdr", "--hash-style=gnu", "-m", "elf_x86_64", "-dynamic-linker", "/lib64/ld-linux-x86-64.so.2", "/usr/lib/gcc/x86_64-redhat-linux/7/../../../../lib64/crt1.o", "/usr/lib/gcc/x86_64-redhat-linux/7/../../../../lib64/crti.o", "/usr/lib/gcc/x86_64-redhat-linux/7/crtbegin.o", "-L/usr/lib/gcc/x86_64-redhat-linux/7", "-L/usr/lib/gcc/x86_64-redhat-linux/7/../../../../lib64", "-L/lib/../lib64", "-L/usr/lib/../lib64", "-L/usr/lib/gcc/x86_64-redhat-linux/7/../../..", "/tmp/ccFp4gIJ.o", "-lgcc", "--as-needed", "-lgcc_s", "--no-as-needed", "-lc", "-lgcc", "--as-needed", "-lgcc_s", "--no-as-needed", "/usr/lib/gcc/x86_64-redhat-linux/7/crtend.o", "/usr/lib/gcc/x86_64-redhat-linux/7/../../../../lib64/crtn.o"], 0x2513ac0 /* 37 vars */ <unfinished ...>
[pid 22033] 19:37:50.445549 <... vfork resumed> ) = 22036 <0.000211>
[pid 22033] 19:37:50.445565 wait4(22036,  <unfinished ...>
[pid 22036] 19:37:50.445654 <... execve resumed> ) = 0 <0.000191>
[pid 22036] 19:37:50.451652 vfork( <unfinished ...>
[pid 22037] 19:37:50.454001 execve("/usr/bin/ld", ["/usr/bin/ld", "-plugin", "/usr/libexec/gcc/x86_64-redhat-linux/7/liblto_plugin.so", "-plugin-opt=/usr/libexec/gcc/x86_64-redhat-linux/7/lto-wrapper", "-plugin-opt=-fresolution=/tmp/cczFnlck.res", "-plugin-opt=-pass-through=-lgcc", "-plugin-opt=-pass-through=-lgcc_s", "-plugin-opt=-pass-through=-lc", "-plugin-opt=-pass-through=-lgcc", "-plugin-opt=-pass-through=-lgcc_s", "--build-id", "--no-add-needed", "--eh-frame-hdr", "--hash-style=gnu", "-m", "elf_x86_64", "-dynamic-linker", "/lib64/ld-linux-x86-64.so.2", "/usr/lib/gcc/x86_64-redhat-linux/7/../../../../lib64/crt1.o", "/usr/lib/gcc/x86_64-redhat-linux/7/../../../../lib64/crti.o", "/usr/lib/gcc/x86_64-redhat-linux/7/crtbegin.o", "-L/usr/lib/gcc/x86_64-redhat-linux/7", "-L/usr/lib/gcc/x86_64-redhat-linux/7/../../../../lib64", "-L/lib/../lib64", "-L/usr/lib/../lib64", "-L/usr/lib/gcc/x86_64-redhat-linux/7/../../..", "/tmp/ccFp4gIJ.o", "-lgcc", "--as-needed", "-lgcc_s", "--no-as-needed", "-lc", "-lgcc", "--as-needed", "-lgcc_s", "--no-as-needed", "/usr/lib/gcc/x86_64-redhat-linux/7/crtend.o", "/usr/lib/gcc/x86_64-redhat-linux/7/../../../../lib64/crtn.o"], 0x7fff24a533b0 /* 37 vars */ <unfinished ...>
[pid 22036] 19:37:50.454193 <... vfork resumed> ) = 22037 <0.002531>
[pid 22036] 19:37:50.454255 wait4(22037,  <unfinished ...>
[pid 22037] 19:37:50.454345 <... execve resumed> ) = 0 <0.000239>
[pid 22037] 19:37:50.580046 exit_group(0) = ?
[pid 22036] 19:37:50.580616 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 22037 <0.126352>
[pid 22036] 19:37:50.580653 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=22037, si_uid=1001, si_status=0, si_utime=1, si_stime=0} ---
[pid 22036] 19:37:50.582078 exit_group(0) = ?
19:37:50.582232 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 22036 <0.136662>
19:37:50.582254 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=22036, si_uid=1001, si_status=0, si_utime=0, si_stime=0} ---
19:37:50.582490 exit_group(0)           = ?
"""

        tempfil_strace = tempfile.NamedTemporaryFile(mode='w+',delete=False)
        tempfil_strace.write(strace_logfile_content)
        tempfil_strace.close()

        output_summary_file = dockit.test_from_file(
            input_log_file=tempfil_strace.name,
            tracer="strace",
            input_process_id=22029,
            output_files_prefix=None,
            output_format=None,
            verbose=False,
            map_params_summary=dockit.full_map_params_summary,
            summary_format="XML",
            with_warning=False,
            with_dockerfile=False,
            update_server= None,
            aggregator=None)

        sys.stdout.write("\nRebuilding tree\n")
        process_tree = SummaryXMLTest.rebuild_process_tree(output_summary_file)

        print(process_tree)

        # Tests the existence of some processes and their subprocesses.
        process_tree[22033]
        process_tree[22033][22034]
        process_tree[22033][22035]
        process_tree[22033][22036]
        process_tree[22033][22036][22037]

    # This loads a log file generated by ltrace and rebuilds the processes tree.
    def test_summary_XML_ltrace(self):
        # For testing the creation of summary XML file from a ltrace log.
        ltrace_logfile_content = """
[pid 21256] 14:45:29.412869 vfork@SYS(0x463a43, 0, 0, 4 <unfinished ...>
[pid 21257] 14:45:29.414920 execve@SYS("/usr/libexec/gcc/x86_64-redhat-linux/7/cc1", 0x164ffb8, 0x1650140 <no return ...>
[pid 21257] 14:45:29.415223 --- Called exec() ---
[pid 21256] 14:45:29.420448 <... vfork resumed> ) = 0x5309 <0.007575>
[pid 21256] 14:45:29.420514 wait4@SYS(0x5309, 0x1650290, 0, 0 <unfinished ...>
[pid 21257] 14:45:29.672105 exit_group@SYS(0 <no return ...>
[pid 21257] 14:45:29.673172 +++ exited (status 0) +++
[pid 21256] 14:45:29.673366 <... wait4 resumed> ) = 0x5309 <0.252849>
[pid 21256] 14:45:29.673408 --- SIGCHLD (Child exited) ---
[pid 21256] 14:45:29.675913 vfork@SYS(0x463a43, 2, 0, 0x164b350 <unfinished ...>
[pid 21258] 14:45:29.676501 execve@SYS("/u01/app/oracle/product/11.2.0/xe/bin/as", 0x164ffb8, 0x1650140) = -2 <0.000290>
[pid 21258] 14:45:29.677529 execve@SYS("/usr/local/bin/as", 0x164ffb8, 0x1650140) = -2 <0.000103>
[pid 21258] 14:45:29.677941 execve@SYS("/usr/bin/as", 0x164ffb8, 0x1650140 <no return ...>
[pid 21258] 14:45:29.678193 --- Called exec() ---
[pid 21256] 14:45:29.678663 <... vfork resumed> ) = 0x530a <0.002748>
[pid 21256] 14:45:29.678700 wait4@SYS(0x530a, 0x164fa30, 0, 0 <unfinished ...>
[pid 21258] 14:45:29.715636 exit_group@SYS(0 <no return ...>
[pid 21258] 14:45:29.716361 +++ exited (status 0) +++
[pid 21256] 14:45:29.716387 <... wait4 resumed> ) = 0x530a <0.037686>
[pid 21256] 14:45:29.716414 --- SIGCHLD (Child exited) ---
[pid 21256] 14:45:29.728543 vfork@SYS(0x463a43, 0, 0, 0x164fc00 <unfinished ...>
[pid 21259] 14:45:29.733906 execve@SYS("/usr/libexec/gcc/x86_64-redhat-linux/7/collect2", 0x1654988, 0x164fac0 <no return ...>
[pid 21259] 14:45:29.734250 --- Called exec() ---
[pid 21256] 14:45:29.735035 <... vfork resumed> ) = 0x530b <0.006486>
[pid 21256] 14:45:29.735067 wait4@SYS(0x530b, 0x1650250, 0, 0 <unfinished ...>
[pid 21259] 14:45:29.756841 vfork@SYS(0x449d93, 2, 0, 4 <unfinished ...>
[pid 21260] 14:45:29.758993 execve@SYS("/usr/bin/ld", 0xe3ca80, 0x7ffedb332d50 <no return ...>
[pid 21260] 14:45:29.759195 --- Called exec() ---
[pid 21259] 14:45:29.759395 <... vfork resumed> ) = 0x530c <0.002551>
[pid 21259] 14:45:29.759503 wait4@SYS(0x530c, 0xe3d670, 0, 0 <unfinished ...>
[pid 21260] 14:45:29.858749 exit_group@SYS(0 <no return ...>
[pid 21260] 14:45:29.859295 +++ exited (status 0) +++
    [pid 21259] 14:45:29.859311 <... wait4 resumed> ) = 0x530c <0.099809>
[pid 21259] 14:45:29.859329 --- SIGCHLD (Child exited) ---
[pid 21259] 14:45:29.861786 exit_group@SYS(0 <no return ...>
[pid 21259] 14:45:29.862872 +++ exited (status 0) +++
[pid 21256] 14:45:29.862889 <... wait4 resumed> ) = 0x530b <0.127822>
[pid 21256] 14:45:29.862907 --- SIGCHLD (Child exited) ---
[pid 21256] 14:45:29.863331 exit_group@SYS(0 <no return ...>
[pid 21256] 14:45:29.863535 +++ exited (status 0) +++
"""

        tempfil_ltrace = tempfile.NamedTemporaryFile(mode='w+',delete=False)
        tempfil_ltrace.write(ltrace_logfile_content)
        tempfil_ltrace.close()

        output_summary_file = dockit.test_from_file(
            input_log_file=tempfil_ltrace.name,
            tracer="ltrace",
            input_process_id=21256,
            output_files_prefix=None,
            output_format=None,
            verbose=False,
            map_params_summary=dockit.full_map_params_summary,
            summary_format="XML",
            with_warning=False,
            with_dockerfile=False,
            update_server=None,
            aggregator=None)

        sys.stdout.write("\nRebuilding tree\n")
        process_tree = SummaryXMLTest.rebuild_process_tree(output_summary_file)

        print(process_tree)

        # This tests the existence of some processes and their sub-sub-processes.
        process_tree[21256]
        process_tree[21256][21257]
        process_tree[21256][21258]
        process_tree[21256][21259]
        process_tree[21256][21259][21260]


class ReplaySessionsTest(unittest.TestCase):
    """
    Replay sessions of Dockit executions using log and ini files.
    """

    def test_replay_linux_strace_txt(self):
        dockit.test_from_file(
            input_log_file=path_prefix_input_file("sample_shell.strace.log"),
            tracer="strace",
            input_process_id=0,
            output_files_prefix=path_prefix_output_result("sample_shell_strace_tst_txt"),
            output_format="TXT",
            verbose=True,
            map_params_summary=["CIM_Process", "CIM_DataFile.Category=['Others','Shared libraries']"],
            summary_format="TXT",
            with_warning=False,
            with_dockerfile=False,
            update_server=None,
            aggregator="clusterize")

        check_file_content("sample_shell_strace_tst_txt.txt")
        check_file_content("sample_shell_strace_tst_txt.summary.txt")

    def test_replay_linux_strace_csv_docker(self):
        output_basename_prefix = "sample_shell_strace_tst_csv"
        dockit.test_from_file(
            input_log_file=path_prefix_input_file("sample_shell.strace.log"),
            tracer="strace",
            input_process_id=0,
            output_files_prefix=path_prefix_output_result(output_basename_prefix),
            output_format="CSV",
            verbose=True,
            map_params_summary=["CIM_Process", "CIM_DataFile.Category=['Others','Shared libraries']"],
            summary_format="XML",
            with_warning=False,
            with_dockerfile=True,
            update_server=None,
            aggregator="clusterize")

        check_file_content(output_basename_prefix + ".csv")
        check_file_content(output_basename_prefix + ".summary.xml")
        check_file_content(output_basename_prefix + ".docker", "Dockerfile")

    def test_replay_linux_strace_json(self):
        output_basename_prefix = "sample_shell_strace_tst_json"
        dockit.test_from_file(
            input_log_file=path_prefix_input_file("sample_shell.strace.log"),
            tracer="strace",
            input_process_id=0,
            output_files_prefix=path_prefix_output_result(output_basename_prefix),
            output_format="JSON",
            verbose=True,
            map_params_summary=["CIM_Process", "CIM_DataFile.Category=['Others','Shared libraries']"],
            summary_format="TXT",
            with_warning=False,
            with_dockerfile=False,
            update_server=None,
            aggregator="clusterize")

        check_file_content(output_basename_prefix + ".json")
        check_file_content(output_basename_prefix + ".summary.txt")

    def test_replay_linux_ltrace_docker(self):
        output_basename_prefix = "sample_shell_ltrace_tst_docker"
        dockit.test_from_file(
            input_log_file= path_prefix_input_file("sample_shell.ltrace.log"),
            tracer="ltrace",
            input_process_id=0,
            output_files_prefix= path_prefix_output_result(output_basename_prefix),
            output_format="JSON",
            verbose=True,
            map_params_summary=["CIM_Process", "CIM_DataFile.Category=['Others','Shared libraries']"],
            summary_format="TXT",
            with_warning=False,
            with_dockerfile=True,
            update_server=None,
            aggregator="clusterize")

        check_file_content(output_basename_prefix + ".json")
        check_file_content(output_basename_prefix + ".summary.txt")
        check_file_content(output_basename_prefix + ".docker", "Dockerfile")

    # TODO: This replay could theoretically run on Linux,
    # TODO: but win32_defs must be amended so that it can load some parts, on Linux boxes.
    @unittest.skipIf(is_platform_linux, "This is not a Windows machine. Test skipped.")
    def test_replay_win32_dir(self):
        output_basename_prefix = "windows_dir_pydbg_45884"
        dockit.test_from_file(
            input_log_file= path_prefix_input_file("windows_dir.pydbg.45884.log"),
            tracer="pydbg",
            input_process_id=0,
            output_files_prefix= path_prefix_output_result(output_basename_prefix),
            output_format="JSON",
            verbose=True,
            map_params_summary=["CIM_Process", "CIM_DataFile.Category=['Others','Shared libraries']"],
            summary_format="TXT",
            with_warning=False,
            with_dockerfile=True,
            update_server=None,
            aggregator="clusterize")

        check_file_content(output_basename_prefix + ".json")
        check_file_content(output_basename_prefix + ".summary.txt")
        check_file_content(output_basename_prefix + ".docker", "Dockerfile")

    def test_replay_all_trace_files(self):
        """Iterates on all input test files

        After that we can check if the results are as expected.
        The keys are the prefix of the log files and the content is an array of actual files
        whose output must be reproduced.
        """
        ####mapFiles = {}

        # First pass to build a map of files.
        # This takes only the log files at the top level.
        for subdir, dirs, files in os.walk( path_prefix_input_file() ):
            for in_file in files:
                input_log_file = subdir + os.sep + in_file
                output_basename_prefix, fil_ext = os.path.splitext(in_file)

                if fil_ext != ".log":
                    continue

                # The main process pid might be embedded in the log file name,
                # just before the extension. If it cannot be found, it is assumed
                # to be -1.

                tracer = dockit.default_tracer(input_log_file)

                # TODO: This is a hack to avoid replaying Windows sessions on Linux.
                # TODO: This replay could theoretically run on Linux,
                # TODO: but win32_defs must be amended so that it can load some parts, on Linux boxes.
                if tracer == "pydbg" and is_platform_linux:
                    print("DO NOT RUN FOR THE MOMENT:", input_log_file)
                    continue

                for output_format in ["JSON"]:
                    # In tests, the summary output format is always XML.
                    dockit.test_from_file(
                        input_log_file=input_log_file,
                        tracer=tracer,
                        input_process_id=-1,
                        output_files_prefix=path_prefix_output_result(output_basename_prefix),
                        output_format=output_format,
                        verbose=False,
                        map_params_summary=dockit.full_map_params_summary,
                        summary_format="TXT",
                        with_warning=False,
                        with_dockerfile=True,
                        update_server=None,
                        aggregator="clusterize")

            # Files .ini are not created for replay sessions.
            check_file_missing(output_basename_prefix + ".ini")

            # Files .log are not created because --duplicate option is not set.
            check_file_missing(output_basename_prefix + ".log")

            check_file_content(output_basename_prefix + ".summary.txt")


class RunningLinuxProcessesTest(unittest.TestCase):
    """
    Test the execution of the Dockit script from real processes.
    """

    # @unittest.skipIf(not is_platform_linux or is_travis_machine(), "This is not a Linux machine. Test skipped.")
    @unittest.skipIf(is_platform_windows, "This is not a Linux machine. Test skipped.")
    def test_strace_ls(self):
        sub_proc = subprocess.Popen(['bash', '-c', 'sleep 5;ls /tmp'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        INFO("Started process is:%d", sub_proc.pid)

        time.sleep(2.0)

        # Avoids exception: "UnsupportedOperation: redirected stdin is pseudofile, has no fileno()"
        output_basename_prefix = "result_ls_strace"
        sys.stdin = open(os.devnull)
        dockit.test_from_file(
            input_log_file= None,
            tracer="strace",
            input_process_id=sub_proc.pid,
            output_files_prefix=path_prefix_output_result(output_basename_prefix),
            output_format="TXT",
            verbose=True,
            map_params_summary=["CIM_Process", "CIM_DataFile.Category=['Others','Shared libraries']"],
            summary_format="TXT",
            with_warning=False,
            with_dockerfile=False,
            update_server=None,
            aggregator="clusterize")

        sub_proc.communicate()
        self.assertTrue(sub_proc.returncode == 0)

        check_file_content(output_basename_prefix + ".txt")
        check_file_content(output_basename_prefix + ".summary.txt")


class StoreToRDFTest(unittest.TestCase):
    """
    Send events to an RDF file.
    """

    def test_create_RDF_file(self):
        output_basename_prefix = "sample_shell_ltrace_tst_create_RDF"
        dockit.test_from_file(
            input_log_file=path_prefix_input_file("sample_shell.ltrace.log"),
            tracer="ltrace",
            input_process_id=0,
            output_files_prefix=path_prefix_output_result(output_basename_prefix),
            output_format="JSON",
            verbose=True,
            map_params_summary=["CIM_Process", "CIM_DataFile.Category=['Others','Shared libraries']"],
            summary_format="TXT",
            with_warning=False,
            with_dockerfile=False,
            update_server= path_prefix_output_result("sample_shell_ltrace_tst_create_RDF.rdf"),
            aggregator="clusterize")

        check_file_content(output_basename_prefix + ".json")
        check_file_content(output_basename_prefix + ".summary.txt")
        check_file_content(output_basename_prefix + ".rdf")


class EventsServerTest(unittest.TestCase):
    """
    This tests the ability to parse a strace log and tranform it into events in Survol,
    with a Survol agents receiving the events from an url.
    """

    def setUp(self):
        # If the Survol agent does not exist, this script starts a local one.
        self.RemoteEventsTestAgent = start_cgiserver(RemoteEventsTestAgent, RemoteEventsTestPort)

    def tearDown(self):
        stop_cgiserver(self.RemoteEventsTestAgent)

    def _check_read_triples(self, num_loops, expected_types_list):
        # Now read the events.
        url_events = RemoteEventsTestAgent + "/survol/sources_types/event_get_all.py?mode=rdf"

        actual_types_dict = collections.defaultdict(lambda: 0)

        while(num_loops > 0):
            events_response = portable_urlopen(url_events, timeout=20)
            events_content = events_response.read()  # Py3:bytes, Py2:str
            split_content = events_content.split(b"\n")
            events_content_trunc = b"".join(split_content)

            events_graph = rdflib.Graph()
            result = events_graph.parse(data=events_content_trunc, format="application/rdf+xml")
            print("len results=", len(events_graph))
            for event_subject, event_predicate, event_object in events_graph:
                # Given the input filename, this expects some specific data.
                if event_predicate == rdflib.namespace.RDF.type:
                    # 'http://www.primhillcomputers.com/survol#CIM_Process'
                    header, hash_char, class_name = str(event_object).rpartition("#")

                    # Some URLs are not objects.
                    # http://www.w3.org/1999/02/22-rdf-syntax-ns#Property
                    if class_name not in ['Class', 'Property']:
                        actual_types_dict[class_name] += 1

            print("num_loops=", num_loops,"types_dict=", actual_types_dict)
            if expected_types_list == actual_types_dict:
                break
            time.sleep(2.0)
            num_loops -= 1

        print("expected_types_list=", expected_types_list)
        print("actual_types_dict=", actual_types_dict)
        self.assertTrue(expected_types_list == actual_types_dict)

    def test_file_events_ps_ef(self):
        output_basename_prefix = "dockit_events_ps_ef.strace"
        dockit.test_from_file(
            input_log_file= path_prefix_input_file("dockit_ps_ef.strace.log"),
            tracer="strace",
            input_process_id=0,
            output_files_prefix= path_prefix_output_result(output_basename_prefix),
            output_format="JSON",
            verbose=False,
            map_params_summary=["CIM_Process", "CIM_DataFile.Category=['Others','Shared libraries']"],
            summary_format="TXT",
            with_warning=False,
            with_dockerfile=False,
            update_server=RemoteEventsTestAgent + "/survol/event_put.py",
            aggregator="clusterize")

        check_file_content(output_basename_prefix + ".json")
        check_file_content(output_basename_prefix + ".summary.txt")

        expected_types_list = {
            'CIM_Process': 1,
            'CIM_NetworkAdapter': 1,
            'CIM_DataFile': 292,
            'CIM_ComputerSystem': 1
        }

        # Now read and test the events.
        self._check_read_triples(5, expected_types_list)

    # FIXME: Broken on local machine with Windows, Python 3, if the server is automatically started.
    # FIXME: Sometimes, it stops reading only 23360 bytes ....
    # FIXME: It cannot be a sizing problem because it sometimes work.
    # FIXME: When it works, it reads everything in one go.
    @unittest.skipIf(is_platform_windows and is_py3 and not is_travis_machine(), "BROKEN WITH PY3 AND WINDOWS AND LOCAL. WHY ??")
    def test_file_events_shell(self):
        output_basename_prefix = "dockit_events_sample_shell.ltrace"
        dockit.test_from_file(
            input_log_file= path_prefix_input_file("dockit_sample_shell.ltrace.log"),
            tracer="ltrace",
            input_process_id=0,
            output_files_prefix= path_prefix_output_result(output_basename_prefix),
            output_format="JSON",
            verbose=False,
            map_params_summary=["CIM_Process", "CIM_DataFile.Category=['Others','Shared libraries']"],
            summary_format="TXT",
            with_warning=False,
            with_dockerfile=False,
            update_server=RemoteEventsTestAgent + "/survol/event_put.py",
            aggregator="clusterize")

        check_file_content(output_basename_prefix + ".json")
        check_file_content(output_basename_prefix + ".summary.txt")

        expected_types_list = {
            'CIM_Process': 5,
            'CIM_NetworkAdapter': 1,
            'CIM_DataFile': 1066,
            'CIM_ComputerSystem': 1
        }

        # Now read and test the events.
        self._check_read_triples(5, expected_types_list)

    @unittest.skipIf(is_platform_windows and is_py3 and not is_travis_machine(), "BROKEN WITH PY3 AND WINDOWS AND LOCAL. WHY ??")
    def test_file_events_proftpd(self):
        output_basename_prefix = "dockit_events_proftpd.strace.26299"
        dockit.test_from_file(
            input_log_file= path_prefix_input_file("dockit_proftpd.strace.26299.log"),
            tracer="strace",
            input_process_id=0,
            output_files_prefix= path_prefix_output_result(output_basename_prefix),
            output_format="JSON",
            verbose=False,
            map_params_summary=["CIM_Process", "CIM_DataFile.Category=['Others','Shared libraries']"],
            summary_format="TXT",
            with_warning=False,
            with_dockerfile=False,
            update_server=RemoteEventsTestAgent + "/survol/event_put.py",
            aggregator="clusterize")

        check_file_content(output_basename_prefix + ".json")
        check_file_content(output_basename_prefix + ".summary.txt")

        expected_types_list = {
            'CIM_Process': 6,
            'CIM_NetworkAdapter': 1,
            'CIM_DataFile': 4229,
            'CIM_ComputerSystem': 1
        }

        # Now read and test the events.
        self._check_read_triples(5, expected_types_list)

    @unittest.skipIf(is_platform_windows and is_py3 and not is_travis_machine(), "BROKEN WITH PY3 AND WINDOWS AND LOCAL. WHY ??")
    def test_file_events_firefox(self):
        output_basename_prefix = "firefox_events_google.strace.22501"
        dockit.test_from_file(
            input_log_file= path_prefix_input_file("firefox_google.strace.22501.log"),
            tracer="strace",
            input_process_id=0,
            output_files_prefix= path_prefix_output_result(output_basename_prefix),
            output_format="JSON",
            verbose=False,
            map_params_summary=["CIM_Process", "CIM_DataFile.Category=['Others','Shared libraries']"],
            summary_format="TXT",
            with_warning=False,
            with_dockerfile=False,
            update_server=RemoteEventsTestAgent + "/survol/event_put.py",
            aggregator="clusterize")

        check_file_content(output_basename_prefix + ".json")
        check_file_content(output_basename_prefix + ".summary.txt")

        expected_types_list = {
            'CIM_Process': 174,
            'CIM_NetworkAdapter': 1,
            'CIM_DataFile': 1678,
            'CIM_ComputerSystem': 1
        }

        # Now read and test the events.
        self._check_read_triples(5, expected_types_list)


if __name__ == '__main__':
    unittest.main()

