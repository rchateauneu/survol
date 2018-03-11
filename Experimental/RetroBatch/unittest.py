import re
import os
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

# First, some internal tests of parsing functions..
InternalUnitTests_ParseSTraceObject()

print("Internal tests OK.")


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
    print(baseName)
    inputLogFile = baseName + ".log"

    tracer = retrobatch.DefaultTracer(inputLogFile)

    for outFilNam in mapFiles[baseName]:
        print("    "+outFilNam)

        baseOutName, filOutExt = os.path.splitext(outFilNam)

        outputFormat = filOutExt[1:].upper()
        retrobatch.UnitTest(inputLogFile,tracer,outFilNam,outputFormat)
        # print("          ",inPath,tracer,outFilNam,outputFormat)

