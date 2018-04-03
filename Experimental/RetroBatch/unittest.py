#!/usr/bin/python

import re
import os
import sys
import getopt
import difflib

import retrobatch

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
        resu = retrobatch.ParseSTraceObject(tupl[0],True)
        if resu != tupl[1]:
            raise Exception("Fail:%s != %s" % ( str(tupl[1]), resu ) )

def DoTheTests(verbose,diffFiles,withSummary,withWarning):

    # This iterates on the input test files and generates the "compressed" output.as
    #  After that we can check if the results are as expected.
    
    # The keys are the prefix of the log files
    # and the content is an array of actual files
    # whose output must be reproduced.
    mapFiles = {}
    
    # First pass to build a map of files.
    for subdir, dirs, files in os.walk("UnitTests"):
        for inFile in files:
            #print os.path.join(subdir, file)
    
            if inFile.startswith("mineit_"):
                inPath = subdir + os.sep + inFile
                baseName, filExt = os.path.splitext(inFile)
    
                keyName = subdir + os.sep + baseName
    
                # The key does not need the extension so it does not matter
                # of this lists the output files before the log input,
                # because the key has to be the same.
                if filExt != ".log":
                    try:
                        mapFiles[keyName].append( inPath )
                    except KeyError:
                        mapFiles[keyName] = [ inPath ]

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
    
        tracer = retrobatch.DefaultTracer(inputLogFile)
    
        for outFilNam in mapFiles[baseName]:
            print("Destination=%s"%outFilNam)
    
            baseOutName, filOutExt = os.path.splitext(outFilNam)

            # "txt", "json" etc...
            outputFormat = filOutExt[1:].upper()

            # In tests, the summary output format is always XML.
            retrobatch.UnitTest(inputLogFile,tracer,aPid,outFilNam,outputFormat,verbose,withSummary,"XML",withWarning)
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
    print("  -d,--diff                     Differences.")
    print("")

    sys.exit(exitCode)


if __name__ == '__main__':
    try:
        optsCmd, argsCmd = getopt.getopt(sys.argv[1:],
                "hvws:d",
                ["help","verbose","warning","summary","differences"])
    except getopt.GetoptError as err:
        # print help information and exit:
        Usage(2,err) # will print something like "option -a not recognized"

    verbose = 0
    withWarning = 0
    withSummary = []
    diffFiles = False

    for anOpt, aVal in optsCmd:
        if anOpt in ("-v", "--verbose"):
            verbose += 1
        elif anOpt in ("-w", "--warning"):
            withWarning += 1
        elif anOpt in ("-s", "--summary"):
            withSummary = withSummary + [ aVal ] if aVal else []
        elif anOpt in ("-d", "--diff"):
            diffFiles = aVal
        elif anOpt in ("-h", "--help"):
            Usage(0)
        else:
            assert False, "Unhandled option"

    # First, some internal tests of parsing functions..
    InternalUnitTests_ParseSTraceObject()
    print("Internal tests OK.")

    DoTheTests(verbose,diffFiles,withSummary,withWarning)
    print("Tests done")



