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
        ( '"Abcd"',
          ["Abcd"] ),
        ( '"Ab","cd"',
          ["Ab","cd"] ),
        ( '"/usr/bin/grep", ["grep", "toto"]',
          ["/usr/bin/grep", ["grep", "toto"] ] ),
        ( '"","cd"',
          ["","cd"] ),
        ( '"12345",""',
          ["12345",""] ),
    ]

    for tupl in dataTst:
        resu = dockit.ParseSTraceObject(tupl[0],True)
        if resu != tupl[1]:
            raise Exception("Fail:%s != %s" % ( str(tupl[1]), resu ) )

def DoTheTests(verbose,diffFiles,mapParamsSummary,withWarning,withDockerfile):

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

            # It should be the same whatever the output format is.
            # outputSummaryFile = baseName + ".xml"

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
    print("  -d,--diff                     Differences.")
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
    mapParamsSummary = []
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
        elif anOpt in ("-d", "--diff"):
            diffFiles = aVal
        elif anOpt in ("-h", "--help"):
            Usage(0)
        else:
            assert False, "Unhandled option"

    # First, some internal tests of parsing functions..
    InternalUnitTests_ParseSTraceObject()
    print("Internal tests OK.")

    DoTheTests(verbose,diffFiles,mapParamsSummary,withWarning,withDockerfile)
    print("Tests done")



