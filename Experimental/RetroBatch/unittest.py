import os
import retrobatch

# This iterates on the inut test files andgenerate the "compressed" output.as
#  After that we can check if the results are as expected.
for subdir, dirs, files in os.walk("UnitTests"):
    for inFile in files:
        #print os.path.join(subdir, file)

        if inFile.endswith("log") and inFile.startswith("mineit_"):
            inPath = subdir + os.sep + inFile
            print (inPath)

            pre, ext = os.path.splitext(inFile)
            outFile = pre + ".out"
            outPath = subdir + os.sep + outFile

            retrobatch.UnitTest(inPath,outPath)
