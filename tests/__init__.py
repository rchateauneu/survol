# This is executed by Travis-CI

import sys
import os

# This is for the test program pytest which is started from the root directory.
sys.path.append("survol")
sys.path.append("tests")

print("__init__.py Current dir=",os.getcwd())
print("__init__.py Tests path=",sys.path)
