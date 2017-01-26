"""
AC2 classes
"""

import os

def ConfigFileNameClean(configFilename):
	onlyFile = os.path.basename(configFilename)

	filNoExt = os.path.splitext(onlyFile)[0]
	return filNoExt
