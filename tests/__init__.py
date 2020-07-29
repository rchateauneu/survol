# This is executed by Travis-CI

import sys
import os

# This is for the test program pytest which is started from the root directory.
sys.path.append("survol")
sys.path.append("tests")

sys.stdout.write("%s Current dir=%s\n" % (__file__, os.getcwd()))

$ pytest --version