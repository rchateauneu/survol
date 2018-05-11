#!/usr/bin/python

"""Unit test framework for dockit"""

__author__      = "Remi Chateauneu"
__copyright__   = "Primhill Computers, 2018"
__credits__ = ["","",""]
__license__ = "GPL"
__version__ = "0.0.1"
__maintainer__ = "Remi Chateauneu"
__email__ = "contact@primhillcomputers.com"
__status__ = "Development"


import re
import os
import sys
import getopt
import difflib

import dockit

def InternalUnitTests_ParseSTraceObject():
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
          # ["3 <unfinished ...>"],18 ),
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

        ( '3</usr/lib64/libc-2.21.so>, "\177ELF\2\1\1\3\>\0"..., 832',
          ['3</usr/lib64/libc-2.21.so>', '\x7fELF\x02\x01\x01\x03\\>\x00...', '832'],49 ),

        ( '29</home/rchateau/.mozilla/firefox/72h59sxe.default/cookies.sqlite>, "SQLite format 3\0\200\0\2\2\0@  \0\0\0\4\0\0\0\4\0\0\0\0\0\0\0\0\0\0\0\2\0\0\0\4\0\0\0\0\0\0\0\0\0\0\0\1\0\0\0\t\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\4\0.\30\310", 100',
          ['29</home/rchateau/.mozilla/firefox/72h59sxe.default/cookies.sqlite>', 'SQLite format 3\x00\x80\x00\x02\x02\x00@  \x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\t\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00.\x18\xc8', '100'], 176),

        ( '5</etc/pki/nssdb/key4.db>, "\r\0\0\0\1\0G\0\0G\3\313\0\0\0\0\0\0\2076\1\7\27!!\1\2167tablenssPrivatenssPrivate\2CREATE TABLE nssP\2076\1\7\27!!\1\2167tablenssPrivatenssPrivate\2CREATE TABLE nssPrivate (id PRIMARY KEY UNIQUE ON CONFLICT ABORT, a0, a1, a2, a3, a10, a11, a"..., 1024, 3072',
          ['5</etc/pki/nssdb/key4.db>', '\r\x00\x00\x00\x01\x00G\x00\x00G\x03\xcb\x00\x00\x00\x00\x00\x00\x876\x01\x07\x17!!\x01\x8e7tablenssPrivatenssPrivate\x02CREATE TABLE nssP\x876\x01\x07\x17!!\x01\x8e7tablenssPrivatenssPrivate\x02CREATE TABLE nssPrivate (id PRIMARY KEY UNIQUE ON CONFLICT ABORT, a0, a1, a2, a3, a10, a11, a...', '1024', '3072'], 244),

        ( '4</etc/pki/nssdb/cert9.db>, F_SETLK, {l_type=F_RDLCK, l_whence=SEEK_SET, l_start=1073741824, l_len=1}',
            ['4</etc/pki/nssdb/cert9.db>', 'F_SETLK', {'l_len': '1', 'l_type': 'F_RDLCK', 'l_start': '1073741824', 'l_whence': 'SEEK_SET'}], 101),

        ( '4</etc/pki/nssdb/cert9.db>, "\0\0\0\2\0\0\0\t\0\0\0\0\0\0\0\0", 16, 24',
          ['4</etc/pki/nssdb/cert9.db>', '\x00\x00\x00\x02\x00\x00\x00\t\x00\x00\x00\x00\x00\x00\x00\x00', '16', '24'], 54),

        ( '0</dev/pts/2>, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 2)}',
          ['0</dev/pts/2>', {'st_rdev': 'makedev(136, 2)', 'st_mode': 'S_IFCHR|0620'}],62 ),
          # ['0</dev/pts/2>', [('st_mode', 'S_IFCHR|0620'), ('st_rdev', 'makedev(136, 2)')]],62 ),

        ( '6, [4<UNIX:[3646855,"/run/proftpd/proftpd.sock"]>], NULL, NULL, {tv_sec=0, tv_usec=500}',
          ['6', ['4<UNIX:[3646855,"/run/proftpd/proftpd.sock"]>'], 'NULL', 'NULL', {'tv_sec': '0', 'tv_usec': '500'}], 87),

        ( '13<UNIX:[10579575->10579582]>, SOL_SOCKET, SO_PEERSEC, "system_u:system_r:system_dbusd_t:s0-s0:c0.c1023\0", [64->48]',
          ['13<UNIX:[10579575->10579582]>', 'SOL_SOCKET', 'SO_PEERSEC', 'system_u:system_r:system_dbusd_t:s0-s0:c0.c1023\x00', ['64->48']], 115),

        ( '17<TCP:[54.36.162.150:32855]>, {sa_family=AF_INET, sin_port=htons(63705), sin_addr=inet_addr("82.45.12.63")}, [16]',
          ['17<TCP:[54.36.162.150:32855]>', {'sin_port': 'htons(63705)', 'sin_addr': 'inet_addr("82.45.12.63")', 'sa_family': 'AF_INET'}, ['16']], 114),

        #( '1, [0</dev/pts/2>], [], [0</dev/pts/2>], {tv_sec=0, tv_usec=0}',
        #  ['1', ['0</dev/pts/2>'], [], ['0</dev/pts/2>'], {'tv_sec': '0', 'tv_usec': '0'}],9999 ),
     #   ( '1, [0</dev/pts/2>], [], [0</dev/pts/2>], {tv_sec=0, tv_usec=0}',
     #     ['1', ['0</dev/pts/2>'], [], ['0</dev/pts/2>'], [('tv_sec', '0'), ('tv_usec', '0')]],62 ),

        #( '48<UNIX:[15589121->15589122]>, {msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base="\10\0\0\0\371\224\206r\237,\216\27\0", iov_len=40}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, MSG_DONTWAIT <unfinished ...>',
        #  ['48<UNIX:[15589121->15589122]>', {'msg_iov': [{'': '\x8e\x17\x00', 'iov_len': '40', 'iov_base': '\x08\x00\x00\x00\xf9\x94\x86r\x9f'}], 'msg_iovlen': '1', 'msg_namelen': '0', 'msg_controllen': '0', 'msg_name': 'NULL', 'msg_flags': '0'}, 'MSG_DONTWAIT <unfinished ...>'],1 ),
        #( '4<TCPv6:[::1:59094->::1:6015]>, [{iov_base="(\4\4\0\20\0", iov_len=16}, {iov_base=NULL, iov_len=0}, {iov_base="", iov_len=0}], 3 <unfinished ...>',
        #  ['4<TCPv6:[::1:59094->::1:6015]>', [], '3 <unfinished ...>'],1 ),

        #( '6</usr/lib64/python2.7/posixpath.pyc>, {st_mode=S_IFREG|0644, st_size=11420, ...}',
        #  ['6</usr/lib64/python2.7/posixpath.pyc>', None],1 ),
        #( '3</usr/lib/locale/locale-archive>, {st_mode=S_IFREG|0644, st_size=2291760, ...}',
        #  ['3</usr/lib/locale/locale-archive>', None], 999),


# theCall=<... pipe resumed> [17<pipe:[15590080]>, 18<pipe:[15590080]>]) = 0 <0.000030>
# m_parsedArgs=[['17<pipe:[15590080]>', '18<pipe:[15590080]>'], '']


    ]

    for tupl in dataTst:
        # The input string theoretically starts and ends with parenthesis,
        # but the closing one might not be there.
        # Therefore it should be tested with and without the closing parenthesis.
        resu,idx = dockit.ParseCallArguments(tupl[0])
        if resu != tupl[1]:
            raise Exception("\n     Fail:%s\nSHOULD BE:%s" % ( str(resu),str(tupl[1])  ) )

        if idx != tupl[2]:
            raise Exception("Fail idx: %d SHOULD BE:%d" % ( idx, tupl[2] ) )
        sys.stdout.write("------%s\n"%str(resu))
        sys.stdout.write("\n")

def DoTheTests(verbose,mapParamsSummary,withWarning,withDockerfile):

    # This iterates on the input test files and generates the "compressed" output.as
    #  After that we can check if the results are as expected.
    
    # The keys are the prefix of the log files
    # and the content is an array of actual files
    # whose output must be reproduced.
    mapFiles = {}
    
    # First pass to build a map of files.
    # This takes only the log files at the top level.
    for subdir, dirs, files in os.walk("UnitTests"):
        for inFile in files:
            inPath = subdir + os.sep + inFile
            baseName, filExt = os.path.splitext(inFile)
    
            keyName = subdir + os.sep + baseName

            if not os.path.exists(keyName + ".log"):
                continue
    
            # The key does not need the extension so it does not matter
            # if this lists the output files before the log input,
            # because the key has to be the same.
            # ".ini" files are context parameters for the test only.
            # ".xml" files are used to store the execution summary.
            if filExt not in [".log",".ini",".xml",".docker"]:
                try:
                    mapFiles[keyName].append( inPath )
                except KeyError:
                    mapFiles[keyName] = [ inPath ]
        # Top-level only.
        break

    for baseName in mapFiles:
        print("")
        inputLogFile = baseName + ".log"

        # The main process pid might be embedded in the log file name,
        # just before the extension. If it cannot be foujnd, it is assumed
        # to be -1..
        mtchLog = re.match(".*\.([0-9]*)$", baseName)
        if mtchLog:
            aPid = int( mtchLog.group(1) )
        else:
            aPid = -1

        print("Input=%s"%inputLogFile)
    
        tracer = dockit.DefaultTracer(inputLogFile)
    
        for outFilNam in mapFiles[baseName]:
            print("Destination=%s"%outFilNam)
    
            baseOutName, filOutExt = os.path.splitext(outFilNam)

            # "txt", "json" etc...
            outputFormat = filOutExt[1:].upper()

            # In tests, the summary output format is always XML.
            dockit.UnitTest(inputLogFile,tracer,aPid,outFilNam,outputFormat,verbose,mapParamsSummary,"XML",withWarning,withDockerfile)
            # print("          ",inPath,tracer,outFilNam,outputFormat)


def Usage(exitCode = 1, errMsg = None):
    if errMsg:
        print(errMsg)

    progNam = sys.argv[0]
    print("Unit tests: %s <executable>"%progNam)
    print("Monitors and factorizes systems calls.")
    print("  -h,--help                     This message.")
    print("  -v,--verbose                  Verbose mode (Cumulative).")
    print("  -w,--warning                  Display warnings (Cumulative).")
    print("  -s,--summary <CIM class>      With summary.")
    print("  -D,--dockerfile               Generates a dockerfile for each sample.")
    print("")

    sys.exit(exitCode)


if __name__ == '__main__':
    try:
        optsCmd, argsCmd = getopt.getopt(sys.argv[1:],
                "hvws:Dd",
                ["help","verbose","warning","summary","docker","differences"])
    except getopt.GetoptError as err:
        # print help information and exit:
        Usage(2,err) # will print something like "option -a not recognized"

    verbose = 0
    withWarning = 0
    # By default, generate all summaries.
    mapParamsSummary = dockit.fullMapParamsSummary

    withDockerfile = None
    diffFiles = False

    for anOpt, aVal in optsCmd:
        if anOpt in ("-v", "--verbose"):
            verbose += 1
        elif anOpt in ("-w", "--warning"):
            withWarning += 1
        elif anOpt in ("-s", "--summary"):
            mapParamsSummary = mapParamsSummary + [ aVal ] if aVal else []
        elif anOpt in ("-D", "--dockerfile"):
            withDockerfile = True
        elif anOpt in ("-h", "--help"):
            Usage(0)
        else:
            assert False, "Unhandled option"

    # First, some internal tests of parsing functions..
    InternalUnitTests_ParseSTraceObject()
    print("Internal tests OK.")

    DoTheTests(verbose,mapParamsSummary,withWarning,withDockerfile)
    print("Tests done")



