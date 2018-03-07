import os
import retrobatch

for subdir, dirs, files in os.walk("."):
    for inFile in files:
        #print os.path.join(subdir, file)

        if inFile.endswith("log") and inFile.startswith("mineit_"):
            inPath = subdir + os.sep + inFile
            print (inPath)

            pre, ext = os.path.splitext(inFile)
            outFile = pre + ".out"
            outPath = subdir + os.sep + outFile

            retrobatch.UnitTest(inPath,outPath)
