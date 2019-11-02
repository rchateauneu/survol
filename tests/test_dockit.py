#!/usr/bin/env python

from __future__ import print_function

import cgitb
import cgi
import os
import re
import sys
from xml.dom import minidom
import json
import tempfile
import unittest
import shutil
import rdflib

# This loads the module from the source, so no need to install it, and no need of virtualenv.
# This is needed when running from PyCharm.
sys.path.insert(0,"../survol/scripts")


# On Travis, getcwd= /home/travis/build/rchateauneu/survol
# path= ['../survol/scripts', '/home/travis/build/rchateauneu/survol',
# '../survol', '/home/travis/build/rchateauneu/survol', '/home/travis/virtualenv/python2.7.15/bin',
# '/home/travis/virtualenv/python2.7.15/lib/python27.zip', '/home/travis/virtualenv/python2.7.15/lib/python2.7',
# '/home/travis/virtualenv/python2.7.15/lib/python2.7/plat-linux2',
# '/home/travis/virtualenv/python2.7.15/lib/python2.7/lib-tk',
# '/home/travis/virtualenv/python2.7.15/lib/python2.7/lib-old', '/home/travis/virtualenv/python2.7.15/lib/python2.7/lib-dynload',
# '/opt/python/2.7.15/lib/python2.7', '/opt/python/2.7.15/lib/python2.7/plat-linux2',
# '/opt/python/2.7.15/lib/python2.7/lib-tk', '/home/travis/virtualenv/python2.7.15/lib/python2.7/site-packages',
# 'survol', '/home/travis/build/rchateauneu/survol/survol']
sys.path.insert(0,"survol/scripts")

dockit_output_files_path = os.path.join( os.path.dirname(__file__), "dockit_output_files" )

# Creates the destination file for result if not there, otherwise cleanup.
# This is needed otherwise pytest would run the Python files in this dir.
if os.path.exists(dockit_output_files_path):
    shutil.rmtree(dockit_output_files_path)
os.makedirs(dockit_output_files_path)

def path_prefix_output_result(*file_path):
    return os.path.join( dockit_output_files_path, *file_path )

dock_input_files_path = os.path.join( os.path.dirname(__file__), "dockit_input_test_trace_files" )

def path_prefix_input_file(*file_path):
    # Travis and PyCharm do not start this unit tests script from the same directory.
    # The test files are alongside the script.
    # input_test_files_dir = os.path.dirname(__file__)

    return os.path.join( dock_input_files_path, *file_path )

print("path=",sys.path)
print("getcwd=",os.getcwd())

import dockit

from init import *


class DockitParserTest(unittest.TestCase):
    """
    Test parsing of strace output.
    """

    # This is a set of arguments of system function calls as displayed by strace or ltrace.
    # This checks if they are correctly parsed.
    def test_trace_line_parse(self):
        dataTst = [
            ( 'xyz',
              ["xyz"],3 ),
            ( '"Abcd"',
              ["Abcd"],6 ),
            ( '"Ab","cd"',
              ["Ab","cd"],9 ),
            ( 'Ab,"cd"',
              ["Ab","cd"],7 ),
            ( '"Ab","cd","ef"',
              ["Ab","cd","ef"],14 ),
            ( '"Ab","cd","ef",gh',
              ["Ab","cd","ef","gh"],17 ),
            ( '"/usr/bin/grep", ["grep", "toto"]',
              ["/usr/bin/grep", ["grep", "toto"] ],33 ),
            ( '"/usr/bin/grep", ["grep", "toto", "tutu"]',
              ["/usr/bin/grep", ["grep", "toto", "tutu"] ],41 ),
            ( '"/usr/bin/grep", ["grep", "toto", "tutu"], "tata"',
              ["/usr/bin/grep", ["grep", "toto", "tutu"], "tata" ],49 ),
            ( '"","cd"',
              ["","cd"],7 ),
            ( '3 <unfinished ...>',
              ["3"],2 ),
            ( '<... close resumed>',
              ['<... close resumed>'],19 ),
            ( '"12345",""',
              ["12345",""],10 ),
            ( '8, "/\nbid_convert_data.o/\nbid128_noncomp.o/\nbid128_compare.o/\nbid32_to_bid64.o/\nbid32_to_bid128.o/\nbid64_to_bid128.o/\nbid64_to_int32.o/\nbid64_to_int64.o/\nbid64_to_uint32.o/\nbid64_to_uint64.o/\nbid128_to_in"..., 4096',
              ['8', '/\nbid_convert_data.o/\nbid128_noncomp.o/\nbid128_compare.o/\nbid32_to_bid64.o/\nbid32_to_bid128.o/\nbid64_to_bid128.o/\nbid64_to_int32.o/\nbid64_to_int64.o/\nbid64_to_uint32.o/\nbid64_to_uint64.o/\nbid128_to_in...', '4096'],214 ),
            ( '3</usr/lib64/libpcre.so.1.2.8>',
              ['3</usr/lib64/libpcre.so.1.2.8>'], 30),
            ( 'NULL, 4000096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3</usr/lib64/libc-2.25.so>, 0',
              ['NULL', '4000096', 'PROT_READ|PROT_EXEC', 'MAP_PRIVATE|MAP_DENYWRITE', '3</usr/lib64/libc-2.25.so>', '0'], 92),
            ( '"/usr/bin/grep", ["grep", "Hello", "../Divers/com_type_l"...], 0x7ffd8a76efa8 /* 17 vars */',
              ['/usr/bin/grep', ['grep', 'Hello', '../Divers/com_type_l...'], '0x7ffd8a76efa8 /* 17 vars */'], 91),
            ( '3</usr/lib64/libpthread-2.21.so>, "xyz", 832',
              ['3</usr/lib64/libpthread-2.21.so>', 'xyz', '832'],44),
            ( '1<pipe:[7124131]>, TCGETS, 0x7ffe58d35d60',
              ['1<pipe:[7124131]>', 'TCGETS', '0x7ffe58d35d60'],41 ),
            ( '3<TCP:[127.0.0.1:59100->127.0.0.1:3306]>, SOL_IP, IP_TOS, [8], 4',
              ['3<TCP:[127.0.0.1:59100->127.0.0.1:3306]>', 'SOL_IP', 'IP_TOS', ['8'], '4'],64 ),
            ( '"/usr/bin/python", ["python", "TestProgs/big_mysql_"...], [/* 37 vars */]',
              ['/usr/bin/python', ['python', 'TestProgs/big_mysql_...'], ['/* 37 vars */']],73 ),

            ( '3</usr/lib64/libc-2.21.so>, "\x7fELF\x02\x01\x01\x03\\>\x00"..., 832',
                ['3</usr/lib64/libc-2.21.so>', '\x7fELF\x02\x01\x01\x03\\>\x00...', '832'],49 ),

            ( '29</home/rchateau/.mozilla/firefox/72h59sxe.default/cookies.sqlite>, "SQLite format 3\0\200\0\2\2\0@  \0\0\0\4\0\0\0\4\0\0\0\0\0\0\0\0\0\0\0\2\0\0\0\4\0\0\0\0\0\0\0\0\0\0\0\1\0\0\0\t\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\4\0.\30\310", 100',
              ['29</home/rchateau/.mozilla/firefox/72h59sxe.default/cookies.sqlite>', 'SQLite format 3\x00\x80\x00\x02\x02\x00@  \x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\t\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00.\x18\xc8', '100'], 176),

            ( '5</etc/pki/nssdb/key4.db>, "\r\0\0\0\1\0G\0\0G\3\313\0\0\0\0\0\0\2076\1\7\27!!\1\2167tablenssPrivatenssPrivate\2CREATE TABLE nssP\2076\1\7\27!!\1\2167tablenssPrivatenssPrivate\2CREATE TABLE nssPrivate (id PRIMARY KEY UNIQUE ON CONFLICT ABORT, a0, a1, a2, a3, a10, a11, a"..., 1024, 3072',
              ['5</etc/pki/nssdb/key4.db>', '\r\x00\x00\x00\x01\x00G\x00\x00G\x03\xcb\x00\x00\x00\x00\x00\x00\x876\x01\x07\x17!!\x01\x8e7tablenssPrivatenssPrivate\x02CREATE TABLE nssP\x876\x01\x07\x17!!\x01\x8e7tablenssPrivatenssPrivate\x02CREATE TABLE nssPrivate (id PRIMARY KEY UNIQUE ON CONFLICT ABORT, a0, a1, a2, a3, a10, a11, a...', '1024', '3072'], 244),

            ( '4</etc/pki/nssdb/cert9.db>, F_SETLK, {l_type=F_RDLCK, l_whence=SEEK_SET, l_start=1073741824, l_len=1}',
                ['4</etc/pki/nssdb/cert9.db>', 'F_SETLK', ['l_type=F_RDLCK', 'l_whence=SEEK_SET', 'l_start=1073741824', 'l_len=1']], 101),

            ( '4</etc/pki/nssdb/cert9.db>, "\0\0\0\2\0\0\0\t\0\0\0\0\0\0\0\0", 16, 24',
              ['4</etc/pki/nssdb/cert9.db>', '\x00\x00\x00\x02\x00\x00\x00\t\x00\x00\x00\x00\x00\x00\x00\x00', '16', '24'], 54),

            ( '0</dev/pts/2>, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 2)}',
              ['0</dev/pts/2>', ['st_mode=S_IFCHR|0620', 'st_rdev=makedev(136, 2)']],62 ),

            ( '6, [4<UNIX:[3646855,"/run/proftpd/proftpd.sock"]>], NULL, NULL, {tv_sec=0, tv_usec=500}',
              ['6', ['4<UNIX:[3646855,"/run/proftpd/proftpd.sock"]>'], 'NULL', 'NULL', ['tv_sec=0', 'tv_usec=500']], 87),

            ( '13<UNIX:[10579575->10579582]>, SOL_SOCKET, SO_PEERSEC, "system_u:system_r:system_dbusd_t:s0-s0:c0.c1023\0", [64->48]',
              ['13<UNIX:[10579575->10579582]>', 'SOL_SOCKET', 'SO_PEERSEC', 'system_u:system_r:system_dbusd_t:s0-s0:c0.c1023\x00', ['64->48']], 115),

            ( '17<TCP:[54.36.162.150:32855]>, {sa_family=AF_INET, sin_port=htons(63705), sin_addr=inet_addr("82.45.12.63")}, [16]',
              ['17<TCP:[54.36.162.150:32855]>', ['sa_family=AF_INET', 'sin_port=htons(63705)', 'sin_addr=inet_addr("82.45.12.63")'], ['16']], 114),

            ( '"/usr/bin/gcc", ["gcc", "-O3", "ProgsAndScriptsForUnitTests/HelloWorld.c"], 0x7ffd8b44aab8 /* 30 vars */) = 0 <0.000270>',
              ['/usr/bin/gcc', ['gcc', '-O3', 'ProgsAndScriptsForUnitTests/HelloWorld.c'], '0x7ffd8b44aab8 /* 30 vars */'],106 ),

            # TODO: ltrace does not escape double-quotes:
            #  "\001$\001$\001\026\001"\0015\001\n\001\r\001\r\001\f\001(\020",
            # "read@SYS(3, "" + str(row) + "\\n")\n\n", 4096)"
            # This string is broken due to the repeated double-quote.
            # ( '4, "\001\024\001$\001$\001\026\001"\0015\001\n\001\r\001\004\002\r\001\f\001(\020", 4096) = 282 <0.000051>',
            #   ['4', '\x01\x14\x01$\x01$\x01\x16\x01"\x015\x01\n\x01\r\x01\x04\x02\r\x01\x0c\x01(\x10', '4096'], 987979 ),

        ]

        for tupl in dataTst:
            # The input string theoretically starts and ends with parenthesis,
            # but the closing one might not be there.
            # Therefore it should be tested with and without the closing parenthesis.
            resu,idx = dockit.ParseCallArguments(tupl[0])
            if resu != tupl[1]:
                raise Exception("\n     Fail:%s\nSHOULD BE:%s" % ( str(resu),str(tupl[1])  ) )

            # This must be the position of the end of the arguments.
            if idx != tupl[2]:
                raise Exception("Fail idx: %d SHOULD BE:%d" % ( idx, tupl[2] ) )

            if idx != len(tupl[0]):
                if not tupl[0][idx:].startswith("<unfinished ...>"):
                    if tupl[0][idx-2] != ')':
                        raise Exception("Fail idx2: len=%d %d SHOULD BE:%d; S=%s / '%s'" % ( len(tupl[0]), idx, tupl[2], tupl[0], tupl[0][idx-2:] ) )



class DockitSummaryXMLTest(unittest.TestCase):
    @staticmethod
    def RebuildProcessTreeAux(currNode,margin=""):
        def PrintOneNode(currNode,margin):
            try:
                procId = currNode.attributes['Handle'].value
            except KeyError:
                procId = 123456789

            execNam = "???"
            for subNod in currNode.childNodes:
                if subNod.nodeType == subNod.TEXT_NODE:
                    continue

                if subNod.localName == 'Executable':
                    try:
                        strXml = subNod.toxml()
                        execNam = re.sub("<.*?>", "", strXml)
                    except AttributeError:
                        pass
                    break

            #sys.stdout.write("%s   %s %s\n"%(margin,procId,execNam))

        procTree = {}

        submargin = margin + "   "
        for subNod in currNode.childNodes:
            if subNod.localName == 'CIM_Process':
                subObj = DockitSummaryXMLTest.RebuildProcessTreeAux(subNod,submargin)
                procId = int(subNod.attributes['Handle'].value)
                PrintOneNode(subNod,submargin)
                procTree[procId] = subObj

        return procTree

    @staticmethod
    def RebuildProcessTree(outputSummaryFile):
        mydoc = minidom.parse(outputSummaryFile)
        currNode = mydoc.getElementsByTagName('Dockit')

        return DockitSummaryXMLTest.RebuildProcessTreeAux(currNode[0])


    # This loads a log file generated by strace and rebuilds the processes tree.
    def test_summary_XML_strace1(self):
        # For testing the creation of summary XML file from a strace log.
        tstLogFileSTrace = """
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

        tmpFilSTrace = tempfile.NamedTemporaryFile(mode='w+',delete=False)
        tmpFilSTrace.write(tstLogFileSTrace)
        tmpFilSTrace.close()

        outputSummaryFile = dockit.UnitTest(tmpFilSTrace.name,"strace",19351,None,None,False,dockit.fullMapParamsSummary,"XML",False,False,None)

        procTree = DockitSummaryXMLTest.RebuildProcessTree(outputSummaryFile)

        print(procTree)

        procTree[19351]
        procTree[19351][19353]
        procTree[19351][19354]
        procTree[19351][19355]
        procTree[19351][19355][19356]



    # This loads a log file generated by strace and rebuilds the processes tree.
    def test_summary_XML_strace2(self):
        # For testing the creation of summary XML file from a strace log.
        tstLogFileSTrace = """
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

        tmpFilSTrace = tempfile.NamedTemporaryFile(mode='w+',delete=False)
        tmpFilSTrace.write(tstLogFileSTrace)
        tmpFilSTrace.close()

        outputSummaryFile = dockit.UnitTest(
            tmpFilSTrace.name,
            "strace",
            22029,
            None,
            None,
            False,
            dockit.fullMapParamsSummary,
            "XML",
            False,
            False,
            None)

        sys.stdout.write("\nRebuilding tree\n")
        procTree = DockitSummaryXMLTest.RebuildProcessTree(outputSummaryFile)

        print(procTree)

        # Tests the existence of some processes and their subprocesses.
        procTree[22033]
        procTree[22033][22034]
        procTree[22033][22035]
        procTree[22033][22036]
        procTree[22033][22036][22037]

    # This loads a log file generated by ltrace and rebuilds the processes tree.
    def test_summary_XML_ltrace(self):
        # For testing the creation of summary XML file from a ltrace log.
        tstLogFileLTrace = """
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

        tmpFilSTrace = tempfile.NamedTemporaryFile(mode='w+',delete=False)
        tmpFilSTrace.write(tstLogFileLTrace)
        tmpFilSTrace.close()

        outputSummaryFile = dockit.UnitTest(
            inputLogFile = tmpFilSTrace.name,
            tracer = "ltrace",
            topPid = 21256,
            baseOutName = None,
            outputFormat = None,
            verbose = False,
            mapParamsSummary = dockit.fullMapParamsSummary,
            summaryFormat = "XML",
            withWarning = False,
            withDockerfile = False,
            updateServer = None)

        sys.stdout.write("\nRebuilding tree\n")
        procTree = DockitSummaryXMLTest.RebuildProcessTree(outputSummaryFile)

        print(procTree)

        # This tests the existence of some processes.
        procTree[21256]
        procTree[21256][21257]
        procTree[21256][21258]
        procTree[21256][21259]
        procTree[21256][21259][21260]

class DockitTraceFilesTest(unittest.TestCase):
    """
    Test the execution of the Dockit script of trace files.
    """

    def test_file_strace_txt(self):
        dockit.UnitTest(
            inputLogFile = path_prefix_input_file( "sample_shell.strace.log"),
            tracer = "strace",
            topPid = 0,
            baseOutName = path_prefix_output_result( "result_strace"),
            outputFormat = "TXT",
            verbose = True,
            mapParamsSummary = ["CIM_Process","CIM_DataFile.Category=['Others','Shared libraries']"],
            summaryFormat = "TXT",
            withWarning = False,
            withDockerfile = False,
            updateServer = None)

        fil_txt = open( path_prefix_output_result( "result_strace.txt") )
        fil_txt.close()

        fil_summary = open( path_prefix_output_result( "result_strace.summary.txt") )
        fil_summary.close()

    def test_file_strace_csv_docker(self):
        dockit.UnitTest(
            inputLogFile = path_prefix_input_file( "sample_shell.strace.log"),
            tracer = "strace",
            topPid = 0,
            baseOutName = path_prefix_output_result( "result_strace" ),
            outputFormat = "CSV",
            verbose = True,
            mapParamsSummary = ["CIM_Process","CIM_DataFile.Category=['Others','Shared libraries']"],
            summaryFormat = "XML",
            withWarning = False,
            withDockerfile = True,
            updateServer = None)

        fil_csv = open( path_prefix_output_result( "result_strace.csv") )
        fil_csv.close()

        fil_summary = open( path_prefix_output_result( "result_strace.summary.xml") )
        fil_summary.close()

        fil_docker = open( path_prefix_output_result( "result_strace.docker", "Dockerfile") )
        fil_docker.close()

    def test_file_strace_json(self):

        dockit.UnitTest(
            inputLogFile = path_prefix_input_file( "sample_shell.strace.log"),
            tracer = "strace",
            topPid = 0,
            baseOutName = path_prefix_output_result( "result_strace" ),
            outputFormat = "JSON",
            verbose = True,
            mapParamsSummary = ["CIM_Process","CIM_DataFile.Category=['Others','Shared libraries']"],
            summaryFormat = "TXT",
            withWarning = False,
            withDockerfile = False,
            updateServer = None)

        fil_json = open( path_prefix_output_result( "result_strace.json") )
        data = json.load(fil_json)
        fil_json.close()

        fil_summary = open( path_prefix_output_result( "result_strace.summary.txt") )
        fil_summary.close()


    def test_file_ltrace_docker(self):
        dockit.UnitTest(
            inputLogFile = path_prefix_input_file( "sample_shell.ltrace.log"),
            tracer="ltrace",
            topPid=0,
            baseOutName= path_prefix_output_result( "result_ltrace" ),
            outputFormat="JSON",
            verbose=True,
            mapParamsSummary=["CIM_Process", "CIM_DataFile.Category=['Others','Shared libraries']"],
            summaryFormat="TXT",
            withWarning=False,
            withDockerfile=True,
            updateServer=None)

        fil_json = open( path_prefix_output_result( "result_ltrace.json") )
        data = json.load(fil_json)
        fil_json.close()

        fil_summary = open( path_prefix_output_result( "result_ltrace.summary.txt") )
        fil_summary.close()

        fil_docker = open( path_prefix_output_result( "result_ltrace.docker", "Dockerfile") )
        fil_docker.close()


    def test_all_trace_files(self):
        # This iterates on the input test files and generates the "compressed" output.as
        # After that we can check if the results are as expected.

        # The keys are the prefix of the log files
        # and the content is an array of actual files
        # whose output must be reproduced.
        mapFiles = {}

        # First pass to build a map of files.
        # This takes only the log files at the top level.
        for subdir, dirs, files in os.walk( path_prefix_input_file() ):
            for inFile in files:
                inputLogFile = subdir + os.sep + inFile
                baseName, filExt = os.path.splitext(inFile)

                if filExt != ".log":
                    continue

                # The main process pid might be embedded in the log file name,
                # just before the extension. If it cannot be found, it is assumed
                # to be -1..
                # mtchLog = re.match(".*\.([0-9]*)$", baseName)
                # if mtchLog:
                #    aPid = int( mtchLog.group(1) )
                # else:
                #    aPid = -1

                tracer = dockit.DefaultTracer(inputLogFile)

                for outputFormat in ["JSON"]:
                    # In tests, the summary output format is always XML.
                    dockit.UnitTest(
                        inputLogFile = inputLogFile,
                        tracer = tracer,
                        topPid = -1,
                        baseOutName = path_prefix_output_result( baseName ),
                        outputFormat = outputFormat,
                        verbose = False,
                        mapParamsSummary = dockit.fullMapParamsSummary,
                        summaryFormat = "TXT",
                        withWarning = False,
                        withDockerfile = True,
                        updateServer = None)


class DockitProcessesTest(unittest.TestCase):
    """
    Test the execution of the Dockit script from real processes.
    """

    @unittest.skipIf(not is_platform_linux or is_travis_machine(), "This is not a Linux machine. Test skipped.")
    def test_strace_ls(self):
        import subprocess
        # stdout=FNULL, stderr=subprocess.STDOUT, subprocess.PIPE
        FNULL = open(os.devnull, 'r')
        sub_proc = subprocess.Popen(['bash', '-c', 'sleep 5;ls /tmp'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        INFO("Started process is:%d", sub_proc.pid)

        time.sleep(2.0)

        # Avoids exception: "UnsupportedOperation: redirected stdin is pseudofile, has no fileno()"
        sys.stdin = open(os.devnull)
        dockit.UnitTest(
            inputLogFile = None,
            tracer="strace",
            topPid=str(sub_proc.pid),
            baseOutName=path_prefix_output_result("result_ls_strace"),
            outputFormat="TXT",
            verbose=True,
            mapParamsSummary=["CIM_Process", "CIM_DataFile.Category=['Others','Shared libraries']"],
            summaryFormat="TXT",
            withWarning=False,
            withDockerfile=False,
            updateServer=None)

        sub_proc.communicate()
        self.assertTrue(sub_proc.returncode == 0)

        fil_txt = open(path_prefix_output_result("result_ls_strace.txt"))
        # Check content
        fil_txt.close()

        fil_summary = open(path_prefix_output_result("result_ls_strace.summary.txt"))
        fil_summary.close()

class DockitEventsTest(unittest.TestCase):
    """
    Send events.
    """

    def setUp(self):
        pass
        # If the Survol agent does not exist, this script starts a local one.
        self.RemoteEventsTestAgent = CgiAgentStart(RemoteEventsTestAgent, RemoteEventsTestPort)

    def tearDown(self):
        CgiAgentStop(self.RemoteEventsTestAgent)

    def test_file_events(self):
        dockit.UnitTest(
            inputLogFile = path_prefix_input_file("mineit_ps_ef.strace.log"),
            tracer="strace",
            topPid=0,
            baseOutName= path_prefix_output_result("mineit_ps_ef.strace"),
            outputFormat="JSON",
            verbose=False,
            mapParamsSummary=["CIM_Process", "CIM_DataFile.Category=['Others','Shared libraries']"],
            summaryFormat="TXT",
            withWarning=False,
            withDockerfile=False,
            updateServer=RemoteEventsTestAgent + "/survol/event_put.py")

        fil_json = open( path_prefix_output_result( "mineit_ps_ef.strace.json") )
        data = json.load(fil_json)
        fil_json.close()

        fil_summary = open( path_prefix_output_result( "mineit_ps_ef.strace.summary.txt") )
        fil_summary.close()

        time.sleep(5.0)

        # Now read the events.
        # This is for a specific entity.
        # RemoteTestAgent + "/survol/event_get.py"
        url_events = RemoteEventsTestAgent + "/survol/sources_types/event_get_all.py?mode=rdf"
        events_response = portable_urlopen(url_events, timeout=180)
        events_content = events_response.read() # Py3:bytes, Py2:str

        events_graph = rdflib.Graph()
        split_content = events_content.split(b"\n")
        events_content_trunc = b"".join(split_content)


        result = events_graph.parse(data=events_content_trunc, format="application/rdf+xml")
        print("len results=", len(events_graph))
        types_dict = dict()
        for event_subject, event_predicate, event_object in events_graph:
            # Given the input filename, this expects some specific data.
            if event_predicate == rdflib.namespace.RDF.type:
                # 'http://www.primhillcomputers.com/survol#CIM_Process'
                header, hash_char, class_name = str(event_object).rpartition("#")
                try:
                    types_dict[class_name] += 1
                except KeyError:
                    types_dict[class_name] = 1

        print(types_dict)
        expected_types_list = {
            'CIM_Process': 1,
            'CIM_NetworkAdapter': 1,
            'CIM_DataFile': 292,
            'CIM_ComputerSystem': 1,
            'Property': 14,
            'Class': 4 }
        self.assertTrue(expected_types_list == types_dict)


if __name__ == '__main__':
    unittest.main()



