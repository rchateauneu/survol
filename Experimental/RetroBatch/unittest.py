import re
import os
import retrobatch

# This iterates on the inut test files andgenerate the "compressed" output.as
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

    # The file format might be "xyzxyz.strace.log", "abcabc.ltrace.log", "123123.cdb.log"
    # depending on the tool which generated the log.
    matchTrace = re.match(".*\.([^\.]*)\.log", inputLogFile )
    if not matchTrace:
        raise Exception("Cannot read tracer from log file name:%s"%inputLogFile)
    tracer = matchTrace.group(1)

    for outFilNam in mapFiles[baseName]:
        print("    "+outFilNam)

        baseOutName, filOutExt = os.path.splitext(outFilNam)

        outputFormat = filOutExt[1:].upper()
        retrobatch.UnitTest(inputLogFile,tracer,outFilNam,outputFormat)
        # print("          ",inPath,tracer,outFilNam,outputFormat)

